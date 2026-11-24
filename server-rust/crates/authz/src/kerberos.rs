//! Native Kerberos/SPNEGO verification via `libgssapi` (MIT krb5 FFI, #355b).
//!
//! Owner decision (2026-11-14): validate `Authorization: Negotiate <base64>`
//! tokens with MIT krb5 `libgssapi` FFI against the configured HTTP service
//! keytab, without build-time `libkrb5-dev` linkage or `KRB5_KTNAME` mutation.
//!
//! Linux loads `libgssapi_krb5.so.2` once into a process-global `OnceLock`
//! (never `dlclose`d) and passes `"FILE:<keytab>"` through
//! `gss_acquire_cred_from` with `desired_mechs = {SPNEGO, KRB5}`. macOS falls
//! back to serialized `gsskrb5_register_acceptor_identity` + `gss_acquire_cred`
//! against `GSS.framework` for local developer verification.
use crate::basic::Verified;
use base64::{engine::general_purpose::STANDARD, Engine};
use setjoin_pg::{ScopedExecutor, Type};
use std::{
    ffi::{c_char, c_void, CString},
    future::Future,
    path::{Path, PathBuf},
    pin::Pin,
    ptr,
    sync::OnceLock,
    time::Duration,
};

/// Upper bound on the raw base64 payload after `"Negotiate "` (~48 KiB decoded).
pub const MAX_NEGOTIATE_B64_LEN: usize = 65_536;

/// Per-verification FFI bound so a stalled keytab/filesystem read never wedges a worker.
pub const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

const GSS_S_COMPLETE: u32 = 0;
const GSS_C_ACCEPT: u32 = 2;
const GSS_C_INDEFINITE: u32 = 0xffff_ffff;

/// SPNEGO mechanism OID: `1.3.6.1.5.5.2`.
const SPNEGO_OID_BYTES: [u8; 6] = [0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos V5 mechanism OID: `1.2.840.113554.1.2.2`.
const KRB5_OID_BYTES: [u8; 9] = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02];
/// `GSS_KRB5_NT_PRINCIPAL_NAME`: `1.2.840.113554.1.2.2.1`.
const KRB5_NT_PRINCIPAL_OID_BYTES: [u8; 10] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02, 0x01];
/// `GSS_C_NT_USER_NAME`: `1.2.840.113554.1.2.1.1`.
const GSS_C_NT_USER_NAME_OID_BYTES: [u8; 10] =
    [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x01, 0x01];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KerberosConfig {
    pub keytab: PathBuf,
    pub realm: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KerberosError {
    LibraryUnavailable(&'static str),
    InvalidConfig(&'static str),
    MalformedToken(&'static str),
    ValidationFailed(&'static str),
    RealmMismatch,
    TimedOut,
}

impl std::fmt::Display for KerberosError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::LibraryUnavailable(msg) => write!(f, "libgssapi unavailable: {msg}"),
            Self::InvalidConfig(msg) => write!(f, "invalid kerberos config: {msg}"),
            Self::MalformedToken(msg) => write!(f, "malformed negotiate token: {msg}"),
            Self::ValidationFailed(msg) => write!(f, "SPNEGO validation failed: {msg}"),
            Self::RealmMismatch => write!(f, "SPNEGO realm mismatch"),
            Self::TimedOut => write!(f, "SPNEGO verification timed out"),
        }
    }
}

impl std::error::Error for KerberosError {}

pub type ValidateFuture<'a> =
    Pin<Box<dyn Future<Output = Result<String, KerberosError>> + Send + 'a>>;

/// Abstraction over SPNEGO token validation so production uses real `libgssapi`
/// (`GssapiVerifier`) and gateway tests can exercise both real GSSAPI and fault hooks.
pub trait KerberosValidator: Send + Sync {
    fn validate_spnego<'a>(&'a self, token: &'a [u8]) -> ValidateFuture<'a>;
}

/// Strictly decode the base64 payload of the first `Authorization: Negotiate <b64>` header.
/// Enforces case-sensitive `"Negotiate "`, bounded length, strict standard base64 with
/// padding (matching Go `base64.StdEncoding.DecodeString`), non-empty bytes, and rejects
/// raw `NTLMSSP\0` tokens before FFI.
pub fn parse_negotiate_token(headers: &hyper::HeaderMap) -> Result<Vec<u8>, KerberosError> {
    let raw = headers
        .get(hyper::header::AUTHORIZATION)
        .ok_or(KerberosError::MalformedToken(
            "missing authorization header",
        ))?
        .as_bytes()
        .strip_prefix(b"Negotiate ")
        .ok_or(KerberosError::MalformedToken("missing Negotiate prefix"))?;
    if raw.is_empty() {
        return Err(KerberosError::MalformedToken("empty token"));
    }
    if raw.len() > MAX_NEGOTIATE_B64_LEN {
        return Err(KerberosError::MalformedToken("token exceeds size bound"));
    }
    let decoded = STANDARD
        .decode(raw)
        .map_err(|_| KerberosError::MalformedToken("invalid base64"))?;
    if decoded.is_empty() {
        return Err(KerberosError::MalformedToken("empty decoded token"));
    }
    if decoded.starts_with(b"NTLMSSP\0") {
        return Err(KerberosError::ValidationFailed("raw NTLMSSP rejected"));
    }
    Ok(decoded)
}

/// Validate a displayed Kerberos principal (`user@REALM`) and optional realm pin.
/// Rejects NUL/control characters, backslash escapes (`\@`, `\/`, `\\`), and multiple `@`.
pub fn validate_principal(raw: &str, expected_realm: &str) -> Result<String, KerberosError> {
    if raw.is_empty() || raw.contains('\\') || raw.chars().any(|c| c.is_control()) {
        return Err(KerberosError::ValidationFailed("invalid principal syntax"));
    }
    let mut parts = raw.split('@');
    let (Some(client), Some(realm), None) = (parts.next(), parts.next(), parts.next()) else {
        return Err(KerberosError::ValidationFailed(
            "principal must have exactly one @",
        ));
    };
    if client.is_empty() || realm.is_empty() {
        return Err(KerberosError::ValidationFailed(
            "empty principal client or realm",
        ));
    }
    if !expected_realm.is_empty() && realm != expected_realm {
        return Err(KerberosError::RealmMismatch);
    }
    Ok(raw.to_owned())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalLookup {
    Found(Verified),
    TotpRequired(Verified),
    Guest(Verified),
    NotFound,
    Unavailable,
}

/// Resolve a validated Kerberos principal to an enabled non-guest user, enforcing
/// fail-closed guest containment (`guest_account_status($1)`) and TOTP check.
pub async fn lookup_principal(exec: &ScopedExecutor, principal: &str) -> PrincipalLookup {
    let rows = match exec
        .read(
            "SELECT u.id, u.email, u.totp_enabled FROM users u \
             WHERE u.krb5_principal = $1 AND u.enabled = TRUE",
            &[(&principal, Type::TEXT)],
        )
        .await
    {
        Ok(rows) => rows,
        Err(_) => return PrincipalLookup::Unavailable,
    };
    let Some(row) = rows.first() else {
        return PrincipalLookup::NotFound;
    };
    let (Ok(user_id), Ok(email), Ok(totp_enabled)) = (
        row.try_get::<_, i64>(0),
        row.try_get::<_, String>(1),
        row.try_get::<_, bool>(2),
    ) else {
        return PrincipalLookup::Unavailable;
    };
    // Fail-closed guest satellite check BEFORE logging `event='login'` or RuntimeGate.
    match exec
        .read(
            "SELECT status FROM guest_account_status($1)",
            &[(&user_id, Type::INT8)],
        )
        .await
    {
        Ok(guest_rows) if !guest_rows.is_empty() => {
            return PrincipalLookup::Guest(Verified { user_id, email });
        }
        Ok(_) => {}
        Err(_) => return PrincipalLookup::Unavailable,
    }
    let user = Verified { user_id, email };
    if totp_enabled {
        PrincipalLookup::TotpRequired(user)
    } else {
        PrincipalLookup::Found(user)
    }
}

/// Write a `kerberos` row to `auth_event_log` (`pwhash.LogAuthEvent` parity).
pub async fn record_kerberos_event(
    exec: &ScopedExecutor,
    user: Option<i64>,
    event: &str,
    email: Option<&str>,
    ip: Option<&str>,
    details: Option<&str>,
) {
    let _ = exec
        .record_protocol_auth_event_with_details(
            user,
            event,
            "kerberos",
            email.filter(|s| !s.is_empty()),
            ip.filter(|s| !s.is_empty()),
            details.filter(|s| !s.is_empty()),
        )
        .await;
}

// ---------------------------------------------------------------------------
// Dynamic MIT krb5 libgssapi FFI (RFC 2744 + cred-store extension)
// ---------------------------------------------------------------------------

#[repr(C)]
struct GssBufferDesc {
    length: usize,
    value: *mut c_void,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct GssOidDesc {
    length: u32,
    elements: *mut c_void,
}

#[repr(C)]
struct GssOidSetDesc {
    count: usize,
    elements: *mut GssOidDesc,
}

#[repr(C)]
struct GssKeyValueElementDesc {
    key: *const c_char,
    value: *const c_char,
}

#[repr(C)]
struct GssKeyValueSetDesc {
    count: u32,
    elements: *const GssKeyValueElementDesc,
}

type GssCredId = *mut c_void;
type GssCtxId = *mut c_void;
type GssName = *mut c_void;

type FnAcquireCredFrom = unsafe extern "C" fn(
    minor_status: *mut u32,
    desired_name: GssName,
    time_req: u32,
    desired_mechs: *const GssOidSetDesc,
    cred_usage: u32,
    cred_store: *const GssKeyValueSetDesc,
    output_cred_handle: *mut GssCredId,
    actual_mechs: *mut *mut GssOidSetDesc,
    time_rec: *mut u32,
) -> u32;

#[cfg(target_os = "macos")]
type FnAcquireCred = unsafe extern "C" fn(
    minor_status: *mut u32,
    desired_name: GssName,
    time_req: u32,
    desired_mechs: *const GssOidSetDesc,
    cred_usage: u32,
    output_cred_handle: *mut GssCredId,
    actual_mechs: *mut *mut GssOidSetDesc,
    time_rec: *mut u32,
) -> u32;

#[cfg(target_os = "macos")]
type FnRegisterAcceptorIdentity = unsafe extern "C" fn(identity: *const c_char) -> u32;

type FnAcceptSecContext = unsafe extern "C" fn(
    minor_status: *mut u32,
    context_handle: *mut GssCtxId,
    acceptor_cred_handle: GssCredId,
    input_token_buffer: *const GssBufferDesc,
    input_chan_bindings: *const c_void,
    src_name: *mut GssName,
    mech_type: *mut *mut GssOidDesc,
    output_token: *mut GssBufferDesc,
    ret_flags: *mut u32,
    time_rec: *mut u32,
    delegated_cred_handle: *mut GssCredId,
) -> u32;

type FnDisplayName = unsafe extern "C" fn(
    minor_status: *mut u32,
    input_name: GssName,
    output_name_buffer: *mut GssBufferDesc,
    output_name_type: *mut *mut GssOidDesc,
) -> u32;

type FnReleaseCred =
    unsafe extern "C" fn(minor_status: *mut u32, cred_handle: *mut GssCredId) -> u32;
type FnReleaseName = unsafe extern "C" fn(minor_status: *mut u32, input_name: *mut GssName) -> u32;
type FnReleaseBuffer =
    unsafe extern "C" fn(minor_status: *mut u32, buffer: *mut GssBufferDesc) -> u32;
type FnDeleteSecContext = unsafe extern "C" fn(
    minor_status: *mut u32,
    context_handle: *mut GssCtxId,
    output_token: *mut GssBufferDesc,
) -> u32;

struct GssApi {
    // Process-lifetime handle: intentionally never `dlclose`d (MIT krb5 plugin state).
    _handle: usize,
    acquire_cred_from: Option<FnAcquireCredFrom>,
    #[cfg(target_os = "macos")]
    acquire_cred: Option<FnAcquireCred>,
    #[cfg(target_os = "macos")]
    register_acceptor_identity: Option<FnRegisterAcceptorIdentity>,
    accept_sec_context: FnAcceptSecContext,
    display_name: FnDisplayName,
    release_cred: FnReleaseCred,
    release_name: FnReleaseName,
    release_buffer: FnReleaseBuffer,
    delete_sec_context: FnDeleteSecContext,
}

// Safety: Function pointers loaded from a never-unloaded shared library are thread-safe to share.
unsafe impl Send for GssApi {}
unsafe impl Sync for GssApi {}

impl std::fmt::Debug for GssApi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GssApi")
            .field("has_acquire_cred_from", &self.acquire_cred_from.is_some())
            .finish()
    }
}

static GSSAPI: OnceLock<Result<GssApi, &'static str>> = OnceLock::new();

#[cfg(target_os = "macos")]
static MACOS_KEYTAB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

unsafe fn load_sym<T>(handle: *mut c_void, name: &[u8]) -> Option<T> {
    let ptr = libc::dlsym(handle, name.as_ptr().cast::<c_char>());
    if ptr.is_null() {
        None
    } else {
        Some(std::mem::transmute_copy::<*mut c_void, T>(&ptr))
    }
}

fn load_gssapi() -> Result<&'static GssApi, KerberosError> {
    let loaded = GSSAPI.get_or_init(|| {
        #[cfg(target_os = "macos")]
        let candidates: &[&[u8]] = &[
            b"/System/Library/Frameworks/GSS.framework/GSS\0",
            b"libgssapi_krb5.dylib\0",
        ];
        #[cfg(not(target_os = "macos"))]
        let candidates: &[&[u8]] = &[b"libgssapi_krb5.so.2\0"];

        let mut handle = ptr::null_mut();
        for name in candidates {
            // Safety: NUL-terminated static C string, RTLD_LAZY | RTLD_LOCAL, never closed.
            let h = unsafe {
                libc::dlopen(
                    name.as_ptr().cast::<c_char>(),
                    libc::RTLD_LAZY | libc::RTLD_LOCAL,
                )
            };
            if !h.is_null() {
                handle = h;
                break;
            }
        }
        if handle.is_null() {
            return Err("could not dlopen libgssapi");
        }
        // Safety: handle is valid and stays loaded for process lifetime.
        unsafe {
            let acquire_cred_from =
                load_sym::<FnAcquireCredFrom>(handle, b"gss_acquire_cred_from\0");
            #[cfg(target_os = "macos")]
            let acquire_cred = load_sym::<FnAcquireCred>(handle, b"gss_acquire_cred\0");
            #[cfg(target_os = "macos")]
            let register_acceptor_identity = load_sym::<FnRegisterAcceptorIdentity>(
                handle,
                b"gsskrb5_register_acceptor_identity\0",
            );

            #[cfg(not(target_os = "macos"))]
            if acquire_cred_from.is_none() {
                return Err("missing gss_acquire_cred_from");
            }
            #[cfg(target_os = "macos")]
            if acquire_cred_from.is_none()
                && (acquire_cred.is_none() || register_acceptor_identity.is_none())
            {
                return Err("missing gss_acquire_cred_from and macOS fallback symbols");
            }

            let Some(accept_sec_context) =
                load_sym::<FnAcceptSecContext>(handle, b"gss_accept_sec_context\0")
            else {
                return Err("missing gss_accept_sec_context");
            };
            let Some(display_name) = load_sym::<FnDisplayName>(handle, b"gss_display_name\0")
            else {
                return Err("missing gss_display_name");
            };
            let Some(release_cred) = load_sym::<FnReleaseCred>(handle, b"gss_release_cred\0")
            else {
                return Err("missing gss_release_cred");
            };
            let Some(release_name) = load_sym::<FnReleaseName>(handle, b"gss_release_name\0")
            else {
                return Err("missing gss_release_name");
            };
            let Some(release_buffer) = load_sym::<FnReleaseBuffer>(handle, b"gss_release_buffer\0")
            else {
                return Err("missing gss_release_buffer");
            };
            let Some(delete_sec_context) =
                load_sym::<FnDeleteSecContext>(handle, b"gss_delete_sec_context\0")
            else {
                return Err("missing gss_delete_sec_context");
            };

            Ok(GssApi {
                _handle: handle as usize,
                acquire_cred_from,
                #[cfg(target_os = "macos")]
                acquire_cred,
                #[cfg(target_os = "macos")]
                register_acceptor_identity,
                accept_sec_context,
                display_name,
                release_cred,
                release_name,
                release_buffer,
                delete_sec_context,
            })
        }
    });
    match loaded {
        Ok(api) => Ok(api),
        Err(msg) => Err(KerberosError::LibraryUnavailable(msg)),
    }
}

struct CredGuard<'a> {
    api: &'a GssApi,
    handle: GssCredId,
}
impl Drop for CredGuard<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let mut minor = 0u32;
            unsafe {
                (self.api.release_cred)(&mut minor, &mut self.handle);
            }
        }
    }
}

struct CtxGuard<'a> {
    api: &'a GssApi,
    handle: GssCtxId,
}
impl Drop for CtxGuard<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let mut minor = 0u32;
            unsafe {
                (self.api.delete_sec_context)(&mut minor, &mut self.handle, ptr::null_mut());
            }
        }
    }
}

struct NameGuard<'a> {
    api: &'a GssApi,
    handle: GssName,
}
impl Drop for NameGuard<'_> {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            let mut minor = 0u32;
            unsafe {
                (self.api.release_name)(&mut minor, &mut self.handle);
            }
        }
    }
}

struct BufferGuard<'a> {
    api: &'a GssApi,
    buf: GssBufferDesc,
}
impl<'a> BufferGuard<'a> {
    fn empty(api: &'a GssApi) -> Self {
        Self {
            api,
            buf: GssBufferDesc {
                length: 0,
                value: ptr::null_mut(),
            },
        }
    }
}
impl Drop for BufferGuard<'_> {
    fn drop(&mut self) {
        if !self.buf.value.is_null() || self.buf.length != 0 {
            let mut minor = 0u32;
            unsafe {
                (self.api.release_buffer)(&mut minor, &mut self.buf);
            }
        }
    }
}

unsafe fn oid_bytes<'a>(oid: *const GssOidDesc) -> Option<&'a [u8]> {
    if oid.is_null() {
        return None;
    }
    let desc = &*oid;
    if desc.elements.is_null() || desc.length == 0 {
        return None;
    }
    Some(std::slice::from_raw_parts(
        desc.elements.cast::<u8>(),
        desc.length as usize,
    ))
}

fn keytab_file_cstring(path: &Path) -> Result<CString, KerberosError> {
    #[cfg(unix)]
    let raw_bytes = {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes()
    };
    #[cfg(not(unix))]
    let raw_bytes = path
        .to_str()
        .ok_or(KerberosError::InvalidConfig("non-UTF-8 keytab path"))?
        .as_bytes();

    if raw_bytes.is_empty() || raw_bytes.contains(&0) {
        return Err(KerberosError::InvalidConfig("empty or NUL keytab path"));
    }
    // Prefix with `FILE:` so paths containing `:` cannot select non-file keytab types
    // (`MEMORY:`, `KCM:`, etc.) in `krb5_kt_resolve`.
    let mut prefixed = Vec::with_capacity(5 + raw_bytes.len());
    prefixed.extend_from_slice(b"FILE:");
    prefixed.extend_from_slice(raw_bytes);
    CString::new(prefixed).map_err(|_| KerberosError::InvalidConfig("NUL byte in keytab path"))
}

/// Real MIT krb5 `libgssapi` SPNEGO/Kerberos verifier.
#[derive(Clone, Debug)]
pub struct GssapiVerifier {
    keytab: PathBuf,
    keytab_spec: CString,
    realm: String,
}

impl GssapiVerifier {
    /// Validate configuration, check keytab readability (matching Go `keytab.Load`),
    /// and verify `libgssapi` symbols are loadable. Fails closed on any error.
    pub fn new(config: KerberosConfig) -> Result<Self, KerberosError> {
        let keytab_spec = keytab_file_cstring(&config.keytab)?;
        let meta = std::fs::metadata(&config.keytab)
            .map_err(|_| KerberosError::InvalidConfig("keytab not readable"))?;
        if !meta.is_file() {
            return Err(KerberosError::InvalidConfig("keytab is not a regular file"));
        }
        std::fs::File::open(&config.keytab)
            .map_err(|_| KerberosError::InvalidConfig("cannot open keytab"))?;
        let _ = load_gssapi()?;
        Ok(Self {
            keytab: config.keytab,
            keytab_spec,
            realm: config.realm,
        })
    }

    /// Synchronous FFI verification against the configured keytab file.
    pub fn validate_sync(&self, token: &[u8]) -> Result<String, KerberosError> {
        if token.is_empty() {
            return Err(KerberosError::MalformedToken("empty token"));
        }
        if token.starts_with(b"NTLMSSP\0") {
            return Err(KerberosError::ValidationFailed("raw NTLMSSP rejected"));
        }
        // Fail closed immediately if the keytab was removed or made unreadable mid-run.
        std::fs::File::open(&self.keytab)
            .map_err(|_| KerberosError::ValidationFailed("keytab unreadable"))?;

        let api = load_gssapi()?;
        let mut spnego_oid_buf = SPNEGO_OID_BYTES;
        let mut krb5_oid_buf = KRB5_OID_BYTES;
        let mut mechs = [
            GssOidDesc {
                length: spnego_oid_buf.len() as u32,
                elements: spnego_oid_buf.as_mut_ptr().cast::<c_void>(),
            },
            GssOidDesc {
                length: krb5_oid_buf.len() as u32,
                elements: krb5_oid_buf.as_mut_ptr().cast::<c_void>(),
            },
        ];
        let desired_mechs = GssOidSetDesc {
            count: mechs.len(),
            elements: mechs.as_mut_ptr(),
        };

        let cred = self.acquire_acceptor_cred(api, &desired_mechs)?;

        let mut ctx = CtxGuard {
            api,
            handle: ptr::null_mut(),
        };
        let mut src_name = NameGuard {
            api,
            handle: ptr::null_mut(),
        };
        let mut out_token = BufferGuard::empty(api);
        let mut actual_mech: *mut GssOidDesc = ptr::null_mut();
        let mut ret_flags = 0u32;
        let mut time_rec = 0u32;
        let mut minor = 0u32;

        let input = GssBufferDesc {
            length: token.len(),
            value: token.as_ptr() as *mut c_void,
        };

        // Safety: all pointers are valid for the call; `output_token` is unconditionally
        // released by `BufferGuard`; `delegated_cred_handle` is NULL so client TGTs cannot leak.
        let maj = unsafe {
            (api.accept_sec_context)(
                &mut minor,
                &mut ctx.handle,
                cred.handle,
                &input,
                ptr::null(),
                &mut src_name.handle,
                &mut actual_mech,
                &mut out_token.buf,
                &mut ret_flags,
                &mut time_rec,
                ptr::null_mut(),
            )
        };

        if maj != GSS_S_COMPLETE {
            return Err(KerberosError::ValidationFailed(
                "gss_accept_sec_context did not complete",
            ));
        }

        // Defense-in-depth: accept ONLY Kerberos V5 mechanism (never NTLM or other mechs).
        let mech_bytes = unsafe { oid_bytes(actual_mech) };
        if mech_bytes != Some(&KRB5_OID_BYTES[..]) {
            return Err(KerberosError::ValidationFailed(
                "non-Kerberos mechanism rejected",
            ));
        }

        if src_name.handle.is_null() {
            return Err(KerberosError::ValidationFailed("missing source principal"));
        }

        let mut name_buf = BufferGuard::empty(api);
        let mut name_type: *mut GssOidDesc = ptr::null_mut();
        let mut disp_minor = 0u32;
        let disp_maj = unsafe {
            (api.display_name)(
                &mut disp_minor,
                src_name.handle,
                &mut name_buf.buf,
                &mut name_type,
            )
        };
        if disp_maj != GSS_S_COMPLETE || name_buf.buf.value.is_null() || name_buf.buf.length == 0 {
            return Err(KerberosError::ValidationFailed("gss_display_name failed"));
        }

        let nt_bytes = unsafe { oid_bytes(name_type) };
        if nt_bytes != Some(&KRB5_NT_PRINCIPAL_OID_BYTES[..])
            && nt_bytes != Some(&GSS_C_NT_USER_NAME_OID_BYTES[..])
        {
            return Err(KerberosError::ValidationFailed(
                "unexpected GSS name type rejected",
            ));
        }

        let raw_bytes = unsafe {
            std::slice::from_raw_parts(name_buf.buf.value.cast::<u8>(), name_buf.buf.length)
        };
        let raw_str = std::str::from_utf8(raw_bytes)
            .map_err(|_| KerberosError::ValidationFailed("non-UTF-8 principal"))?;
        validate_principal(raw_str, &self.realm)
    }

    fn acquire_acceptor_cred<'a>(
        &self,
        api: &'a GssApi,
        desired_mechs: &GssOidSetDesc,
    ) -> Result<CredGuard<'a>, KerberosError> {
        if let Some(acquire_from) = api.acquire_cred_from {
            let key_cstr = CString::new("keytab").expect("static key");
            let elem = GssKeyValueElementDesc {
                key: key_cstr.as_ptr(),
                value: self.keytab_spec.as_ptr(),
            };
            let store = GssKeyValueSetDesc {
                count: 1,
                elements: &elem,
            };
            let mut cred = CredGuard {
                api,
                handle: ptr::null_mut(),
            };
            let mut minor = 0u32;
            let maj = unsafe {
                acquire_from(
                    &mut minor,
                    ptr::null_mut(),
                    GSS_C_INDEFINITE,
                    desired_mechs,
                    GSS_C_ACCEPT,
                    &store,
                    &mut cred.handle,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if maj != GSS_S_COMPLETE || cred.handle.is_null() {
                return Err(KerberosError::ValidationFailed(
                    "gss_acquire_cred_from failed",
                ));
            }
            return Ok(cred);
        }

        #[cfg(target_os = "macos")]
        {
            let _guard = MACOS_KEYTAB_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let register =
                api.register_acceptor_identity
                    .ok_or(KerberosError::LibraryUnavailable(
                        "missing gsskrb5_register_acceptor_identity",
                    ))?;
            let acquire = api.acquire_cred.ok_or(KerberosError::LibraryUnavailable(
                "missing gss_acquire_cred",
            ))?;
            let reg_maj = unsafe { register(self.keytab_spec.as_ptr()) };
            if reg_maj != GSS_S_COMPLETE {
                return Err(KerberosError::ValidationFailed(
                    "gsskrb5_register_acceptor_identity failed",
                ));
            }
            let mut cred = CredGuard {
                api,
                handle: ptr::null_mut(),
            };
            let mut minor = 0u32;
            let maj = unsafe {
                acquire(
                    &mut minor,
                    ptr::null_mut(),
                    GSS_C_INDEFINITE,
                    desired_mechs,
                    GSS_C_ACCEPT,
                    &mut cred.handle,
                    ptr::null_mut(),
                    ptr::null_mut(),
                )
            };
            if maj != GSS_S_COMPLETE || cred.handle.is_null() {
                return Err(KerberosError::ValidationFailed("gss_acquire_cred failed"));
            }
            Ok(cred)
        }

        #[cfg(not(target_os = "macos"))]
        Err(KerberosError::LibraryUnavailable(
            "missing gss_acquire_cred_from",
        ))
    }
}

impl KerberosValidator for GssapiVerifier {
    fn validate_spnego<'a>(&'a self, token: &'a [u8]) -> ValidateFuture<'a> {
        let verifier = self.clone();
        let owned = token.to_vec();
        Box::pin(async move {
            match tokio::time::timeout(
                VERIFY_TIMEOUT,
                tokio::task::spawn_blocking(move || verifier.validate_sync(&owned)),
            )
            .await
            {
                Ok(Ok(res)) => res,
                Ok(Err(_)) => Err(KerberosError::ValidationFailed("worker join error")),
                Err(_) => Err(KerberosError::TimedOut),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::{
        cipher::{BlockEncrypt, KeyInit},
        Aes128,
    };
    use chrono::{DateTime, Utc};
    use hmac::{Hmac, Mac};
    use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION};
    use sha1::Sha1;

    // -----------------------------------------------------------------------
    // Pure-Rust RFC 3962 (AES-128-CTS-HMAC-SHA1-96) + RFC 4120 AP-REQ +
    // RFC 4178 SPNEGO NegTokenInit + MIT v0x0502 keytab test minter.
    // Exercises REAL libgssapi (`libgssapi_krb5.so.2` / macOS GSS.framework).
    // -----------------------------------------------------------------------

    fn gcd(mut a: usize, mut b: usize) -> usize {
        while b != 0 {
            let t = b;
            b = a % b;
            a = t;
        }
        a
    }

    fn lcm(a: usize, b: usize) -> usize {
        a / gcd(a, b) * b
    }

    fn rot_right_13(input: &[u8], n: usize) -> Vec<u8> {
        let bit_len = input.len() * 8;
        let shift = (13 * n) % bit_len;
        let mut out = vec![0u8; input.len()];
        for bit in 0..bit_len {
            let src_bit = (bit + bit_len - shift) % bit_len;
            let val = (input[src_bit / 8] >> (7 - (src_bit % 8))) & 1;
            out[bit / 8] |= val << (7 - (bit % 8));
        }
        out
    }

    fn ones_complement_add(a: &mut [u8], b: &[u8]) {
        let mut carry = 0u16;
        for i in (0..a.len()).rev() {
            let sum = a[i] as u16 + b[i] as u16 + carry;
            a[i] = (sum & 0xff) as u8;
            carry = sum >> 8;
        }
        while carry != 0 {
            for i in (0..a.len()).rev() {
                let sum = a[i] as u16 + carry;
                a[i] = (sum & 0xff) as u8;
                carry = sum >> 8;
                if carry == 0 {
                    break;
                }
            }
        }
    }

    fn n_fold(input: &[u8], out_bytes: usize) -> Vec<u8> {
        let total = lcm(out_bytes, input.len());
        let copies = total / input.len();
        let mut expanded = Vec::with_capacity(total);
        for i in 0..copies {
            expanded.extend_from_slice(&rot_right_13(input, i));
        }
        let mut acc = vec![0u8; out_bytes];
        for chunk in expanded.chunks_exact(out_bytes) {
            ones_complement_add(&mut acc, chunk);
        }
        acc
    }

    fn dk_aes128(base_key: &[u8; 16], usage: u32, suffix: u8) -> [u8; 16] {
        let mut constant = [0u8; 5];
        constant[..4].copy_from_slice(&usage.to_be_bytes());
        constant[4] = suffix;
        let folded = n_fold(&constant, 16);
        let cipher = Aes128::new_from_slice(base_key).unwrap();
        let mut block = aes::Block::from(<[u8; 16]>::try_from(folded.as_slice()).unwrap());
        cipher.encrypt_block(&mut block);
        let mut out = [0u8; 16];
        out.copy_from_slice(&block);
        out
    }

    fn encrypt_aes128_cts_hmac_sha1_96(
        base_key: &[u8; 16],
        usage: u32,
        confounder: [u8; 16],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let ke = dk_aes128(base_key, usage, 0xaa);
        let ki = dk_aes128(base_key, usage, 0x55);

        let mut plain = Vec::with_capacity(16 + plaintext.len());
        plain.extend_from_slice(&confounder);
        plain.extend_from_slice(plaintext);

        // HMAC-SHA1-96 over confounder || plaintext
        let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(&ki).unwrap();
        mac.update(&plain);
        let hmac_full = mac.finalize().into_bytes();

        let cipher = Aes128::new_from_slice(&ke).unwrap();
        let n = plain.len();
        assert!(n >= 16);

        let mut ct = Vec::with_capacity(n + 12);
        if n == 16 {
            let mut b = aes::Block::from(<[u8; 16]>::try_from(plain.as_slice()).unwrap());
            cipher.encrypt_block(&mut b);
            ct.extend_from_slice(&b);
        } else {
            let rem = n % 16;
            let num_blocks = n.div_ceil(16);
            let mut prev = [0u8; 16];
            let mut blocks: Vec<[u8; 16]> = Vec::with_capacity(num_blocks);
            for i in 0..num_blocks {
                let start = i * 16;
                let end = (start + 16).min(n);
                let mut cur = [0u8; 16];
                cur[..(end - start)].copy_from_slice(&plain[start..end]);
                for j in 0..16 {
                    cur[j] ^= prev[j];
                }
                let mut b = aes::Block::from(cur);
                cipher.encrypt_block(&mut b);
                let mut enc = [0u8; 16];
                enc.copy_from_slice(&b);
                prev = enc;
                blocks.push(enc);
            }
            // RFC 3962 CS3 CTS: emit C_0 .. C_{k-3}, then C_{k-1} (full 16B),
            // then C_{k-2} truncated to `if rem == 0 { 16 } else { rem }` bytes.
            for b in &blocks[..num_blocks - 2] {
                ct.extend_from_slice(b);
            }
            ct.extend_from_slice(&blocks[num_blocks - 1]);
            let tail_len = if rem == 0 { 16 } else { rem };
            ct.extend_from_slice(&blocks[num_blocks - 2][..tail_len]);
        }
        ct.extend_from_slice(&hmac_full[..12]);
        ct
    }

    fn der_len(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len <= 0xff {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xff) as u8]
        }
    }

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(1 + 3 + body.len());
        out.push(tag);
        out.extend_from_slice(&der_len(body.len()));
        out.extend_from_slice(body);
        out
    }

    fn der_ctx(num: u8, inner: &[u8]) -> Vec<u8> {
        der_tlv(0xa0 | num, inner)
    }

    fn der_int(val: i64) -> Vec<u8> {
        assert!(val >= 0);
        let bytes = val.to_be_bytes();
        let mut start = 0;
        while start < 7 && bytes[start] == 0 {
            start += 1;
        }
        let mut body = Vec::new();
        if bytes[start] & 0x80 != 0 {
            body.push(0);
        }
        body.extend_from_slice(&bytes[start..]);
        der_tlv(0x02, &body)
    }

    fn der_general_string(s: &str) -> Vec<u8> {
        der_tlv(0x1b, s.as_bytes())
    }

    fn der_generalized_time(ts: DateTime<Utc>) -> Vec<u8> {
        let s = ts.format("%Y%m%d%H%M%SZ").to_string();
        der_tlv(0x18, s.as_bytes())
    }

    fn der_principal(name_type: i64, components: &[&str]) -> Vec<u8> {
        let mut strs = Vec::new();
        for c in components {
            strs.extend_from_slice(&der_general_string(c));
        }
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_ctx(0, &der_int(name_type)));
        seq.extend_from_slice(&der_ctx(1, &der_tlv(0x30, &strs)));
        der_tlv(0x30, &seq)
    }

    fn der_encryption_key(enctype: i64, key: &[u8]) -> Vec<u8> {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_ctx(0, &der_int(enctype)));
        seq.extend_from_slice(&der_ctx(1, &der_tlv(0x04, key)));
        der_tlv(0x30, &seq)
    }

    fn der_encrypted_data(enctype: i64, kvno: Option<i64>, cipher: &[u8]) -> Vec<u8> {
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_ctx(0, &der_int(enctype)));
        if let Some(v) = kvno {
            seq.extend_from_slice(&der_ctx(1, &der_int(v)));
        }
        seq.extend_from_slice(&der_ctx(2, &der_tlv(0x04, cipher)));
        der_tlv(0x30, &seq)
    }

    fn build_mit_keytab(realm: &str, components: &[&str], kvno: u8, key: &[u8; 16]) -> Vec<u8> {
        let mut entry = Vec::new();
        entry.extend_from_slice(&(components.len() as u16).to_be_bytes());
        entry.extend_from_slice(&(realm.len() as u16).to_be_bytes());
        entry.extend_from_slice(realm.as_bytes());
        for c in components {
            entry.extend_from_slice(&(c.len() as u16).to_be_bytes());
            entry.extend_from_slice(c.as_bytes());
        }
        entry.extend_from_slice(&1u32.to_be_bytes()); // KRB5_NT_PRINCIPAL
        entry.extend_from_slice(&0u32.to_be_bytes()); // timestamp
        entry.push(kvno);
        entry.extend_from_slice(&17u16.to_be_bytes()); // aes128-cts-hmac-sha1-96
        entry.extend_from_slice(&(key.len() as u16).to_be_bytes());
        entry.extend_from_slice(key);
        entry.extend_from_slice(&(kvno as u32).to_be_bytes());

        let mut kt = vec![0x05, 0x02];
        kt.extend_from_slice(&(entry.len() as i32).to_be_bytes());
        kt.extend_from_slice(&entry);
        kt
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_spnego_krb5_token(
        client_name: &str,
        client_realm: &str,
        service_components: &[&str],
        service_realm: &str,
        service_key: &[u8; 16],
        kvno: u8,
        session_key: &[u8; 16],
        now: DateTime<Utc>,
        end: DateTime<Utc>,
        cusec: i64,
        confounder_seed: u8,
    ) -> Vec<u8> {
        // EncTicketPart (APPLICATION 3 = 0x63)
        let mut enc_tkt = Vec::new();
        enc_tkt.extend_from_slice(&der_ctx(0, &der_tlv(0x03, &[0x00, 0x00, 0x00, 0x00, 0x00]))); // flags
        enc_tkt.extend_from_slice(&der_ctx(1, &der_encryption_key(17, session_key)));
        enc_tkt.extend_from_slice(&der_ctx(2, &der_general_string(client_realm)));
        enc_tkt.extend_from_slice(&der_ctx(3, &der_principal(1, &[client_name])));
        // transited: { tr-type 1, contents "" }
        let mut transited = Vec::new();
        transited.extend_from_slice(&der_ctx(0, &der_int(1)));
        transited.extend_from_slice(&der_ctx(1, &der_tlv(0x04, &[])));
        enc_tkt.extend_from_slice(&der_ctx(4, &der_tlv(0x30, &transited)));
        enc_tkt.extend_from_slice(&der_ctx(5, &der_generalized_time(now))); // authtime
        enc_tkt.extend_from_slice(&der_ctx(7, &der_generalized_time(end))); // endtime
        let enc_tkt_der = der_tlv(0x63, &der_tlv(0x30, &enc_tkt));

        let tkt_cipher =
            encrypt_aes128_cts_hmac_sha1_96(service_key, 2, [confounder_seed; 16], &enc_tkt_der);

        // Ticket (APPLICATION 1 = 0x61)
        let mut tkt = Vec::new();
        tkt.extend_from_slice(&der_ctx(0, &der_int(5)));
        tkt.extend_from_slice(&der_ctx(1, &der_general_string(service_realm)));
        tkt.extend_from_slice(&der_ctx(2, &der_principal(2, service_components)));
        tkt.extend_from_slice(&der_ctx(
            3,
            &der_encrypted_data(17, Some(kvno as i64), &tkt_cipher),
        ));
        let ticket_der = der_tlv(0x61, &der_tlv(0x30, &tkt));

        // Authenticator (APPLICATION 2 = 0x62)
        // Include 0x8003 GSS checksum (24 bytes: len=16, 16 zero binding bytes, flags=0)
        // which MIT krb5 and Heimdal require in GSS-KRB5 AP-REQ authenticators.
        let mut cksum_body = vec![0u8; 24];
        cksum_body[0..4].copy_from_slice(&16u32.to_le_bytes());
        let mut cksum = Vec::new();
        cksum.extend_from_slice(&der_ctx(0, &der_int(0x8003)));
        cksum.extend_from_slice(&der_ctx(1, &der_tlv(0x04, &cksum_body)));

        let mut auth = Vec::new();
        auth.extend_from_slice(&der_ctx(0, &der_int(5)));
        auth.extend_from_slice(&der_ctx(1, &der_general_string(client_realm)));
        auth.extend_from_slice(&der_ctx(2, &der_principal(1, &[client_name])));
        auth.extend_from_slice(&der_ctx(3, &der_tlv(0x30, &cksum)));
        auth.extend_from_slice(&der_ctx(4, &der_int(cusec)));
        auth.extend_from_slice(&der_ctx(5, &der_generalized_time(now)));
        let auth_der = der_tlv(0x62, &der_tlv(0x30, &auth));

        let auth_cipher = encrypt_aes128_cts_hmac_sha1_96(
            session_key,
            11,
            [confounder_seed.wrapping_add(1); 16],
            &auth_der,
        );

        // AP-REQ (APPLICATION 14 = 0x6e)
        let mut ap_req = Vec::new();
        ap_req.extend_from_slice(&der_ctx(0, &der_int(5)));
        ap_req.extend_from_slice(&der_ctx(1, &der_int(14)));
        ap_req.extend_from_slice(&der_ctx(2, &der_tlv(0x03, &[0x00, 0x00, 0x00, 0x00, 0x00])));
        ap_req.extend_from_slice(&der_ctx(3, &ticket_der));
        ap_req.extend_from_slice(&der_ctx(4, &der_encrypted_data(17, None, &auth_cipher)));
        let ap_req_der = der_tlv(0x6e, &der_tlv(0x30, &ap_req));

        // Inner GSS-KRB5 InitialContextToken (RFC 4121)
        let mut inner_body = Vec::new();
        inner_body.extend_from_slice(&der_tlv(0x06, &KRB5_OID_BYTES));
        inner_body.extend_from_slice(&[0x01, 0x00]); // TOK_ID = AP-REQ
        inner_body.extend_from_slice(&ap_req_der);
        let gss_krb5 = der_tlv(0x60, &inner_body);

        // Outer SPNEGO NegTokenInit (RFC 4178)
        let mech_types = der_tlv(0x30, &der_tlv(0x06, &KRB5_OID_BYTES));
        let mut neg_init_seq = Vec::new();
        neg_init_seq.extend_from_slice(&der_ctx(0, &mech_types));
        neg_init_seq.extend_from_slice(&der_ctx(2, &der_tlv(0x04, &gss_krb5)));
        let neg_init = der_ctx(0, &der_tlv(0x30, &neg_init_seq));

        let mut spnego_body = Vec::new();
        spnego_body.extend_from_slice(&der_tlv(0x06, &SPNEGO_OID_BYTES));
        spnego_body.extend_from_slice(&neg_init);
        der_tlv(0x60, &spnego_body)
    }

    fn spnego_ntlm_token() -> Vec<u8> {
        // NTLMSSP OID: 1.3.6.1.4.1.311.2.2.10
        const NTLM_OID: [u8; 10] = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
        let ntlm_neg = b"NTLMSSP\0\x01\x00\x00\x00\x07\x82\x08\xa2";
        let mech_types = der_tlv(0x30, &der_tlv(0x06, &NTLM_OID));
        let mut seq = Vec::new();
        seq.extend_from_slice(&der_ctx(0, &mech_types));
        seq.extend_from_slice(&der_ctx(2, &der_tlv(0x04, ntlm_neg)));
        let mut body = Vec::new();
        body.extend_from_slice(&der_tlv(0x06, &SPNEGO_OID_BYTES));
        body.extend_from_slice(&der_ctx(0, &der_tlv(0x30, &seq)));
        der_tlv(0x60, &body)
    }

    #[test]
    fn parse_negotiate_header_enforces_case_bounds_base64_and_ntlm_rejection() {
        let mut h = HeaderMap::new();
        h.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Negotiate {}", STANDARD.encode(b"\x60\x01\x00")))
                .unwrap(),
        );
        assert_eq!(parse_negotiate_token(&h).unwrap(), b"\x60\x01\x00");

        // Lowercase scheme rejected
        h.insert(AUTHORIZATION, HeaderValue::from_static("negotiate YQ=="));
        assert!(matches!(
            parse_negotiate_token(&h),
            Err(KerberosError::MalformedToken(_))
        ));

        // Empty / unpadded / invalid base64 rejected
        for bad in ["Negotiate ", "Negotiate !!!", "Negotiate YQ"] {
            h.insert(AUTHORIZATION, HeaderValue::from_static(bad));
            assert!(
                parse_negotiate_token(&h).is_err(),
                "expected error for {bad:?}"
            );
        }

        // Oversized token rejected before decode
        let huge = format!("Negotiate {}", "A".repeat(MAX_NEGOTIATE_B64_LEN + 4));
        h.insert(AUTHORIZATION, HeaderValue::from_str(&huge).unwrap());
        assert!(matches!(
            parse_negotiate_token(&h),
            Err(KerberosError::MalformedToken(_))
        ));

        // Raw NTLMSSP rejected
        let ntlm = format!(
            "Negotiate {}",
            STANDARD.encode(b"NTLMSSP\0\x01\x00\x00\x00")
        );
        h.insert(AUTHORIZATION, HeaderValue::from_str(&ntlm).unwrap());
        assert!(matches!(
            parse_negotiate_token(&h),
            Err(KerberosError::ValidationFailed(_))
        ));

        // Multiple Authorization headers: only first header inspected (matches Go Header.Get)
        let mut multi = HeaderMap::new();
        multi.append(AUTHORIZATION, HeaderValue::from_static("Bearer abc"));
        multi.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Negotiate {}", STANDARD.encode(b"\x60\x01\x00")))
                .unwrap(),
        );
        assert!(parse_negotiate_token(&multi).is_err());
    }

    #[test]
    fn validate_principal_rejects_escapes_controls_multi_at_and_wrong_realm() {
        assert_eq!(
            validate_principal("alice@CORP.EXAMPLE", "CORP.EXAMPLE").unwrap(),
            "alice@CORP.EXAMPLE"
        );
        assert_eq!(
            validate_principal("alice@CORP.EXAMPLE", "").unwrap(),
            "alice@CORP.EXAMPLE"
        );
        assert_eq!(
            validate_principal("alice@OTHER.EXAMPLE", "CORP.EXAMPLE"),
            Err(KerberosError::RealmMismatch)
        );
        for bad in [
            "",
            "alice",
            "@CORP.EXAMPLE",
            "alice@",
            "alice@a@CORP.EXAMPLE",
            r"alice\@corp@CORP.EXAMPLE",
            r"alice@CORP\@EVIL",
            "alice\0@CORP.EXAMPLE",
            "alice\n@CORP.EXAMPLE",
        ] {
            assert!(
                validate_principal(bad, "CORP.EXAMPLE").is_err(),
                "expected rejection for {bad:?}"
            );
        }
    }

    #[test]
    fn real_gssapi_verifies_spnego_and_rejects_bad_tokens_replay_ntlm_and_rotation() {
        // On Linux (CI / production), libgssapi_krb5.so.2 MUST load — never silently skip.
        let api_check = load_gssapi();
        #[cfg(target_os = "linux")]
        assert!(
            api_check.is_ok(),
            "libgssapi_krb5.so.2 must be loadable on Linux: {api_check:?}"
        );
        if api_check.is_err() {
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        // Colon in filename proves FILE: prefix prevents krb5_kt_resolve scheme hijacking.
        let kt_path = dir.path().join("svc:mail.keytab");
        let service_key_v1 = [0x11u8; 16];
        let service_key_v2 = [0x22u8; 16];
        let wrong_key = [0x99u8; 16];
        let session_key = [0x33u8; 16];

        std::fs::write(
            &kt_path,
            build_mit_keytab(
                "EXAMPLE.TEST",
                &["HTTP", "mail.example.test"],
                1,
                &service_key_v1,
            ),
        )
        .unwrap();

        let verifier = GssapiVerifier::new(KerberosConfig {
            keytab: kt_path.clone(),
            realm: "EXAMPLE.TEST".into(),
        })
        .expect("load verifier with valid keytab");

        let now = Utc::now();
        let end = now + chrono::Duration::hours(1);

        // 1. Valid SPNEGO AP-REQ -> extracts exact principal
        let valid_token = mint_spnego_krb5_token(
            "alice",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v1,
            1,
            &session_key,
            now,
            end,
            1001,
            0x41,
        );
        assert_eq!(
            verifier.validate_sync(&valid_token).unwrap(),
            "alice@EXAMPLE.TEST"
        );

        // 2. Replay of identical AP-REQ must be rejected by MIT krb5 rcache on Linux
        #[cfg(target_os = "linux")]
        assert!(
            verifier.validate_sync(&valid_token).is_err(),
            "MIT krb5 rcache must reject replayed AP-REQ"
        );

        // 3. Realm mismatch rejected (ticket signed for our keytab, client from other realm)
        let wrong_realm_tok = mint_spnego_krb5_token(
            "alice",
            "OTHER.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v1,
            1,
            &session_key,
            now,
            end,
            1002,
            0x42,
        );
        assert_eq!(
            verifier.validate_sync(&wrong_realm_tok),
            Err(KerberosError::RealmMismatch)
        );

        // 4. Wrong service key rejected
        let wrong_key_tok = mint_spnego_krb5_token(
            "alice",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &wrong_key,
            1,
            &session_key,
            now,
            end,
            1003,
            0x43,
        );
        assert!(verifier.validate_sync(&wrong_key_tok).is_err());

        // 5. Expired ticket rejected
        let expired_tok = mint_spnego_krb5_token(
            "alice",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v1,
            1,
            &session_key,
            now - chrono::Duration::hours(2),
            now - chrono::Duration::hours(1),
            1004,
            0x44,
        );
        assert!(verifier.validate_sync(&expired_tok).is_err());

        // 6. Future clock-skewed authenticator rejected (>5m)
        let future_tok = mint_spnego_krb5_token(
            "alice",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v1,
            1,
            &session_key,
            now + chrono::Duration::minutes(15),
            now + chrono::Duration::hours(2),
            1005,
            0x45,
        );
        assert!(verifier.validate_sync(&future_tok).is_err());

        // 7. Tampered token rejected
        let mut tampered = valid_token.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert!(verifier.validate_sync(&tampered).is_err());

        // 8. SPNEGO-wrapped NTLM rejected (must never succeed or accept continue-needed)
        assert!(verifier.validate_sync(&spnego_ntlm_token()).is_err());

        // 9. Garbage / truncated DER rejected
        assert!(verifier.validate_sync(b"\x60\x05\x06\x01\x00").is_err());

        // 10. Keytab hot-rotation to kvno 2 succeeds without restarting verifier
        std::fs::write(
            &kt_path,
            build_mit_keytab(
                "EXAMPLE.TEST",
                &["HTTP", "mail.example.test"],
                2,
                &service_key_v2,
            ),
        )
        .unwrap();
        let rotated_tok = mint_spnego_krb5_token(
            "bob",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v2,
            2,
            &session_key,
            now,
            end,
            1006,
            0x46,
        );
        assert_eq!(
            verifier.validate_sync(&rotated_tok).unwrap(),
            "bob@EXAMPLE.TEST"
        );

        // 11. Deleting keytab fails closed
        std::fs::remove_file(&kt_path).unwrap();
        let after_delete_tok = mint_spnego_krb5_token(
            "bob",
            "EXAMPLE.TEST",
            &["HTTP", "mail.example.test"],
            "EXAMPLE.TEST",
            &service_key_v2,
            2,
            &session_key,
            now,
            end,
            1007,
            0x47,
        );
        assert!(verifier.validate_sync(&after_delete_tok).is_err());
    }
}
