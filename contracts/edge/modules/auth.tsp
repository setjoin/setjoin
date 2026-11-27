import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Auth;

// ── Shared Auth/Identity Models ──────────────────────────────────────────

enum AuthAccountType {
  member: "member",
  guest: "guest",
}

model AuthDelegate {
  id: int64;
  email: string;
  permission: string;
}

model AuthAlias {
  email: string;
  name?: string;
}

model AuthMeResponse {
  user_id: int64;
  email: string;
  display_name: string;
  is_admin: boolean;
  has_mailbox: boolean;
  totp_enabled: boolean;
  totp_enabled_at: string | null;
  delegates: AuthDelegate[];
  aliases: AuthAlias[];
  account_type: AuthAccountType;
  impersonating?: boolean;
  actor_id?: int64;
}

model AuthTokenResponse {
  access_token: string;
  refresh_token: string;
  expires_in: int64;
}

model AuthRefreshRequest {
  refresh_token?: string;
}

@error
model AuthRefreshUnavailableProblem {
  @statusCode statusCode: 503;
  @header("content-type") contentType: "application/problem+json";
  @header("Retry-After") retryAfter?: string;
  @body body: ProblemDetails;
}

model AuthMfaChallengeResponse {
  status?: string;
  mfa_required?: boolean;
  mfa_method?: string;
  mfa_token: string;
  nonce?: string;
  ttl_seconds?: int64;
  fallback?: string[];
  step_up_reason?: string;
  step_up_methods?: string[];
  correlation_id?: string;
}

model AuthLoginRequest {
  email: string;
  password: string;
  stay_signed_in?: boolean;
  remember_device?: boolean;
  dpop_jwk?: Record<unknown>;
}

model AuthLoginForbiddenBody {
  status?: string;
  message?: string;
  mfa_required?: boolean;
  mfa_token?: string;
  force_password_change?: boolean;
  force_token?: string;
  reason?: string;
  error?: string;
  captcha_prompt?: string;
  captcha_token?: string;
  retry_after?: int64;
  type?: string;
  title?: string;
  detail?: string;
  code?: string;
}

@error
model AuthLoginForbiddenJson {
  @statusCode statusCode: 403;
  @header("content-type") contentType: "application/json";
  @body body: AuthLoginForbiddenBody;
}

model AuthRateLimitBody {
  error?: string;
  captcha_prompt?: string;
  captcha_token?: string;
  retry_after?: int64;
  detail?: string;
}

@error
model AuthRateLimitJson {
  @statusCode statusCode: 429;
  @header("content-type") contentType: "application/json";
  @body body: AuthRateLimitBody;
}

model PasswordPolicyResponse {
  minLength: int32;
  maxBytes: int32;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireDigit: boolean;
  requireSpecial: boolean;
}

model ChangePasswordRequest {
  oldPassword: string;
  newPassword: string;
}

// ── Guest Invite Acceptance ──────────────────────────────────────────────

model GuestInviteDisclosureResponse {
  channels: string[];
  disclosure_text: string;
  disclosure_version: string;
  expires_at: string;
  invited_email: string;
  org_name: string;
}

model GuestInviteAcceptRequest {
  token: string;
  disclosure_accepted: boolean;
  new_password: string;
}

model GuestInviteAcceptResponse {
  invited_email: string;
  message: string;
}

model AuthSimpleErrorBody {
  error: string;
}

@error
model AuthBadRequestJson {
  @statusCode statusCode: 400;
  @header("content-type") contentType: "application/json";
  @body body: AuthSimpleErrorBody;
}

@error
model AuthUnauthorizedJson {
  @statusCode statusCode: 401;
  @header("content-type") contentType: "application/json";
  @body body: AuthSimpleErrorBody;
}

@error
model AuthNotFoundJson {
  @statusCode statusCode: 404;
  @header("content-type") contentType: "application/json";
  @body body: AuthSimpleErrorBody;
}

@error
model AuthConflictJson {
  @statusCode statusCode: 409;
  @header("content-type") contentType: "application/json";
  @body body: AuthSimpleErrorBody;
}

// ── MFA Reauth & Possession Proofs ───────────────────────────────────────

enum MfaReauthOperation {
  totpEnroll: "totp.enroll",
  totpReplace: "totp.replace",
  webauthnRegister: "webauthn.register",
  webauthnRevoke: "webauthn.revoke",
  recoveryRegenerate: "recovery.regenerate",
  deviceRegisterNative: "device.register.native",
  bootstrapTotpEnroll: "bootstrap.totp.enroll",
}

model MfaReauthRequest {
  password?: string;
  operation?: MfaReauthOperation;
  target_ref?: string;
}

model MfaReauthResponse {
  reauth_token: string;
  expires_in: int64;
}

model PossessionTotpRequest {
  operation: MfaReauthOperation;
  code: string;
  target_ref?: string;
}

model PossessionWebAuthnBeginRequest {
  operation: MfaReauthOperation;
  mfa_token?: string;
  target_ref?: string;
}

model WebAuthnAssertionPayload {
  authenticatorData: string;
  clientDataJSON: string;
  signature: string;
  userHandle?: string | null;
}

model PossessionWebAuthnFinishRequest {
  id: string;
  rawId: string;
  type: string;
  response: WebAuthnAssertionPayload;
  operation: MfaReauthOperation;
  mfa_token?: string;
  target_ref?: string;
}

model PossessionWebAuthnFinishResponse {
  reauth_token?: string;
  expires_in?: int64;
  granted?: boolean;
}

// ── WebAuthn / Passkeys ──────────────────────────────────────────────────

model PasskeyCredential {
  id: string;
  device_name: string;
  created_at: string;
  uv_capable?: boolean;
}

model PasskeyCredentialsListResponse {
  credentials: PasskeyCredential[];
}

model WebAuthnBeginOptionsResponse {
  publicKey?: Record<unknown>;
  status?: string;
}

model WebAuthnLoginFinishRequest {
  id: string;
  rawId: string;
  type: string;
  response: WebAuthnAssertionPayload;
  dpop_jwk?: Record<unknown>;
}

model WebAuthnLoginFinishResponse {
  access_token?: string;
  refresh_token?: string;
  expires_in?: int64;
  status?: string;
  mfa_required?: boolean;
  mfa_method?: string;
  mfa_token?: string;
  nonce?: string;
  ttl_seconds?: int64;
  fallback?: string[];
}

model WebAuthnAttestationPayload {
  attestationObject: string;
  clientDataJSON: string;
}

model WebAuthnRegisterFinishRequest {
  id: string;
  rawId: string;
  type: string;
  response: WebAuthnAttestationPayload;
  reauth_token?: string;
}

// ── Backup Codes, TOTP, Push, Impersonation ──────────────────────────────

model BackupCodesGenerateRequest {
  reauth_token?: string;
}

model BackupCodesGenerateResponse {
  backup_codes: string[];
}

model TotpSetupResponse {
  provisioning_uri: string;
  enrollment_id?: string;
}

model TotpConfirmRequest {
  code: string;
  reauth_token?: string;
  enrollment_id?: string;
}

model TotpVerifyRequest {
  code: string;
  mfa_token: string;
  dpop_jwk?: Record<unknown>;
}

model TotpEnrollSetupRequest {
  mfa_token: string;
}

model TotpEnrollConfirmRequest {
  code: string;
  mfa_token: string;
  dpop_jwk?: Record<unknown>;
  enrollment_id?: string;
}

model TotpRemoveBeginRequest {
  password: string;
  code: string;
}

model TotpRemoveBeginResponse {
  step_up_token: string;
  expires_in: int64;
}

model TotpRemoveRequest {
  step_up_token: string;
  confirm: string;
}

model PushStatusRequest {
  nonce: string;
  mfa_token: string;
  dpop_jwk?: Record<unknown>;
}

model PushStatusResponse {
  approved?: boolean;
  access_token?: string;
  refresh_token?: string;
  expires_in?: int64;
}

model ImpersonateUserResponse {
  expires_in: int64;
  impersonating: boolean;
  target_email: string;
}

// ── Interface ────────────────────────────────────────────────────────────

@tag("Auth")
@route("/auth")
interface AuthApi {
  @doc("Return the currently authenticated user profile and session metadata.")
  @get
  @route("/me")
  getMe():
    | AuthMeResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Authenticate with email and password, returning session tokens or an MFA challenge.")
  @post
  @route("/login")
  login(
    @header("X-Captcha-Token") captchaToken?: string,
    @header("X-Captcha-Answer") captchaAnswer?: string,
    @body body: AuthLoginRequest,
  ):
    | AuthTokenResponse
    | {
        @statusCode statusCode: 202;
        @body body: AuthMfaChallengeResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | AuthLoginForbiddenJson
    | ForbiddenProblem
    | ConflictProblem
    | AuthRateLimitJson
    | TooManyRequestsProblem
    | ServiceUnavailableProblem
    | InternalServerProblem;

  @doc("Sign out the current session and revoke refresh cookies.")
  @post
  @route("/logout")
  logout():
    | NoContentResponse
    | UnauthorizedProblem
    | InternalServerProblem;

  @doc("Rotate the access and refresh token pair from a JSON refresh_token request body (400 on missing/invalid JSON, 401 on invalid/revoked token, 503 with Retry-After on retryable risk-read outage). Body stays optional strictly for compatibility with webmail's legacy best-effort refreshSession() probe.")
  @post
  @route("/refresh")
  refresh(@body body?: AuthRefreshRequest):
    | AuthTokenResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | AuthRefreshUnavailableProblem
    | InternalServerProblem;

  @doc("Return the organization password complexity policy.")
  @get
  @route("/password-policy")
  getPasswordPolicy():
    | PasswordPolicyResponse
    | InternalServerProblem;

  @doc("Legacy password change endpoint.")
  @post
  @route("/change-password")
  changePassword(@body body: ChangePasswordRequest):
    | Record<unknown>
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundTextResponse
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Fetch guest invitation disclosure metadata for an invite token.")
  @get
  @route("/guest-invite/accept")
  getGuestInviteDisclosure(@query token: string):
    | GuestInviteDisclosureResponse
    | AuthBadRequestJson
    | AuthUnauthorizedJson
    | AuthNotFoundJson
    | AuthConflictJson
    | BadRequestProblem
    | UnauthorizedProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("Accept a guest invitation and set the guest account password.")
  @post
  @route("/guest-invite/accept")
  acceptGuestInvite(@body body: GuestInviteAcceptRequest):
    | GuestInviteAcceptResponse
    | AuthBadRequestJson
    | AuthUnauthorizedJson
    | AuthNotFoundJson
    | AuthConflictJson
    | BadRequestProblem
    | UnauthorizedProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("Verify account password and target operation (`application/json`) to mint a single-use MFA re-authentication token.")
  @post
  @route("/mfa/reauth")
  mfaReauth(@body body?: MfaReauthRequest):
    | MfaReauthResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | UnsupportedMediaTypeProblem
    | LockedProblem
    | TooManyRequestsProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Prove possession of an enrolled TOTP authenticator to mint a re-auth grant.")
  @post
  @route("/mfa/possession/totp")
  mfaPossessionTotp(@body body: PossessionTotpRequest):
    | MfaReauthResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem;

  @doc("Begin a user-verified WebAuthn possession assertion ceremony.")
  @post
  @route("/mfa/possession/webauthn/begin")
  mfaPossessionWebAuthnBegin(@body body: PossessionWebAuthnBeginRequest):
    | WebAuthnBeginOptionsResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Finish a user-verified WebAuthn possession assertion ceremony.")
  @post
  @route("/mfa/possession/webauthn/finish")
  mfaPossessionWebAuthnFinish(@body body: PossessionWebAuthnFinishRequest):
    | PossessionWebAuthnFinishResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("List WebAuthn passkeys registered for the authenticated user.")
  @get
  @route("/webauthn/credentials")
  listWebAuthnCredentials():
    | PasskeyCredentialsListResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Begin a passwordless WebAuthn passkey login ceremony.")
  @get
  @route("/webauthn/login/begin")
  webAuthnLoginBegin(@query email: string):
    | WebAuthnBeginOptionsResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Complete a WebAuthn passkey login ceremony.")
  @post
  @route("/webauthn/login/finish")
  webAuthnLoginFinish(@body body: WebAuthnLoginFinishRequest):
    | WebAuthnLoginFinishResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Begin WebAuthn passkey registration (or resume a bound ceremony).")
  @get
  @route("/webauthn/register/begin")
  webAuthnRegisterBegin(@header("X-MFA-Reauth") mfaReauth?: string):
    | WebAuthnBeginOptionsResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Complete WebAuthn passkey registration.")
  @post
  @route("/webauthn/register/finish")
  webAuthnRegisterFinish(@body body: WebAuthnRegisterFinishRequest):
    | EmptyCreatedResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Regenerate recovery backup codes (requires fresh re-authentication).")
  @post
  @route("/backup-codes/generate")
  generateBackupCodes(@body body: BackupCodesGenerateRequest):
    | BackupCodesGenerateResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Begin TOTP authenticator setup for the authenticated session.")
  @get
  @route("/totp/setup")
  setupTotp(@header("X-MFA-Reauth") mfaReauth?: string):
    | TotpSetupResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Confirm TOTP authenticator enrollment with a current verification code.")
  @post
  @route("/totp/confirm")
  confirmTotp(@body body: TotpConfirmRequest):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Verify a TOTP code to complete an MFA-gated login.")
  @post
  @route("/totp/verify")
  verifyTotp(@body body: TotpVerifyRequest):
    | AuthTokenResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem;

  @doc("Begin mandatory TOTP enrollment during MFA-pending bootstrap login.")
  @post
  @route("/totp/enroll/setup")
  setupTotpEnrollment(@body body: TotpEnrollSetupRequest):
    | TotpSetupResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Confirm mandatory TOTP enrollment during MFA-pending bootstrap login.")
  @post
  @route("/totp/enroll/confirm")
  confirmTotpEnrollment(@body body: TotpEnrollConfirmRequest):
    | AuthTokenResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Begin TOTP de-enrollment step-up verification.")
  @post
  @route("/totp/remove/begin")
  beginTotpRemoval(@body body: TotpRemoveBeginRequest):
    | TotpRemoveBeginResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Complete TOTP de-enrollment and clear recovery codes.")
  @post
  @route("/totp/remove")
  removeTotp(@body body: TotpRemoveRequest):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Poll out-of-band push MFA approval status.")
  @post
  @route("/push/status")
  pollPushStatus(@body body: PushStatusRequest):
    | PushStatusResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Start an admin impersonation session targeting another user.")
  @post
  @route("/admin/users/{id}/impersonate")
  impersonateUser(@path id: int64):
    | ImpersonateUserResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;
}
