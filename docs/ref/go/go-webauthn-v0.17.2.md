package webauthn // import "github.com/go-webauthn/webauthn/webauthn"

Package webauthn contains the API functionality of the library. After creating
and configuring a webauthn object, users can call the object to create and
validate web authentication credentials.

This documentation section highlights key functions within the library which are
recommended and often have examples attached. Functions which are discouraged
due to their lack of functionality are expressly not documented here,
and you're on your own with these functions. Generally speaking, if the function
is not documented here, it is either used by another function documented here,
and it hides one of the arguments or return values, or it is lower level logic
only intended for advanced use cases.

The New function is a key function in creating a new instance of a WebAuthn
Relying Party which is required to perform most actions.

To start the credential creation ceremony, the
WebAuthn.BeginMediatedRegistration or WebAuthn.BeginRegistration functions
are used which returns *SessionData and a *protocol.CredentialCreation struct
which can be easily serialized as JSON for the frontend library/logic.
The *SessionData must be saved in a way which allows the implementer to restore
it later. This *SessionData should be safely anchored to a user agent without
allowing the user agent to modify the contents (i.e. opaque session cookie).

To finish the credential creation ceremony, the WebAuthn.FinishRegistration
function can be used. This function requires a *http.Request and
performs all the necessary and requested validations. If you have other
requirements, you can use protocol.ParseCredentialCreationResponseBody or
protocol.ParseCredentialCreationResponseBytes which require an io.Reader or byte
array respectively, then use WebAuthn.CreateCredential to perform validations
against the *protocol.ParsedCredentialCreationData and saved *SessionData
and finalize the process. For complete customizability, just produce the
*protocol.ParsedCredentialCreationData with a custom parser and provide it to
WebAuthn.CreateCredential.

To start a Passkey login ceremony, the WebAuthn.BeginDiscoverableMediatedLogin
or WebAuthn.BeginDiscoverableLogin functions are used which returns *SessionData
and a *protocol.CredentialAssertion struct which can easily be serialized as
JSON for the frontend library/logic. The *SessionData should be safely handled
as previously described.

To finish a Passkey login ceremony, the WebAuthn.FinishPasskeyLogin
function can be used. This function requires a *http.Request and
performs all the necessary validations. If you have other requirements,
you can use the protocol.ParseCredentialRequestResponseBody or
protocol.ParseCredentialRequestResponseBytes which require an io.Reader or
byte array respectively, then use WebAuthn.ValidatePasskeyLogin to perform
validations against the *protocol.ParsedCredentialAssertionData and saved
*SessionData and finalize the process. For complete customizabilty, just produce
the protocol.ParsedCredentialAssertionData with a custom parser and provide it
to WebAuthn.ValidatePasskeyLogin.

To start a Multi-Factor login ceremony, the WebAuthn.BeginMediatedLogin
or WebAuthn.BeginLogin functions are used which returns SessionData and a
*protocol.CredentialAssertion struct which can easily be serialized as JSON
for the frontend library/logic. The *SessionData should be safely handled as
previously described.

To finish a Multi-Factor login ceremony, the WebAuthn.FinishLogin
function can be used. This function requires a *http.Request and
performs all the necessary validations. If you have other requirements,
you can use the protocol.ParseCredentialRequestResponseBody or
protocol.ParseCredentialRequestResponseBytes which require an io.Reader or byte
array respectively, then use WebAuthn.ValidateLogin to perform validations
against the *protocol.ParsedCredentialAssertionData and saved *SessionData
and finalize the process. For complete customizabilty, just produce the
protocol.ParsedCredentialAssertionData with a custom parser and provide it to
WebAuthn.ValidateLogin.

# Relying Party Usage

This library hadnles the relying party server-side concerns. The browser or
other user agent is responsible for handling the JSON responses from this
library and translating them for the WebAUthn API appropriately. There are two
primary ways to handle this other than doing so manually:

 1. Using a client side library like @simplewebauthn/browser.
 2. Some browsers support the parseCreationOptionsFromJSON static method on the
    WebAuthn object.

# Storage

This section describes how a Relying Party should persist the state produced
by the library: the Credential records returned from registration (which
must survive for the lifetime of the credential) and the SessionData records
exchanged between the Begin and Finish/Validate calls of each ceremony (which
need only live long enough to span the ceremony).

Guidance here assumes PostgreSQL as the backing store; the same shape translates
to other SQL engines but the column types given below are written against
PostgreSQL.

Two persistence shapes are supported for the Credential struct and the first is
strongly recommended:

 1. Explicit fields (recommended). Map each field of the struct (and for
    Credential the nested Authenticator and CredentialAttestation fields) to its
    own column, using native types (BYTEA for raw bytes, BOOLEAN for each flag,
    TIMESTAMPTZ for time values, etc.). This gives the database a typed,
    queryable view of each record, allows per-field constraints and indexes,
    and lets an operator audit or migrate individual values without having to
    decode an opaque blob.

 2. Opaque serialized value. Serialize the whole struct into a single BYTEA
    (or JSONB) column. Both encoding/json and MessagePack are supported via the
    struct tags on every field (the `msg:` tags drive the msgp-generated code
    in *_gen.go, and the `json:` tags drive encoding/json); either encoding will
    round-trip a Credential. Prefer this only when the explicit-field approach
    genuinely does not fit; you lose the ability to query, index, or update
    individual fields in the database.

One persistence shape is supported for the SessionData struct which is to store
it as bytes via encoding/json or using MessagePack as bytes in whatever storage
system you're using for user sessions. This data MUST be definitively anchored
to a user's active session, and it must be restored between the ceremony steps.

Regardless of which shape is chosen, the following values MUST be persisted
as their own columns so records can be located and scoped correctly without
first decoding attestation or key material. The User Handle in particular is
per-user state (one value shared by every credential that user owns) and MUST
NOT be stored on the credential row; store it once per user on a separate table
(`webauthn_users` in the example below) and link credentials to that row via the
application user identifier.

On each Credential row:

  - Credential ID; Credential.ID, the identifier returned by the authenticator
    and echoed in every assertion. This is the primary lookup key at login.
  - Relying Party ID; the RP ID the credential was registered against.
    Credentials must be partitioned by RP ID and the stored value must match the
    RP ID in effect at authentication time.
  - Application user identifier; your application's own unique user id
    (the primary key used elsewhere in your schema to reference the user).
    This is what ties a credential back to the user record and, transitively via
    `webauthn_users`, to the User Handle.

On a separate per-user row (`webauthn_users` or equivalent), keyed uniquely by
(RP ID, application user id) and also uniquely by (RP ID, User Handle):

  - Relying Party ID; same scoping rules as above; a user may have distinct User
    Handles under different RP IDs, so the RP ID must be part of both unique
    keys on this table.
  - Application user identifier; the same value stored on each of that user's
    credential rows; this is the join column between `webauthn_users` and
    `webauthn_credentials`.
  - User Handle; the opaque per-user byte sequence returned by User.WebAuthnID,
    equivalently SessionData.UserID. This is the value exchanged with the
    authenticator and is what discoverable-credential flows return at login.
    It MUST be stable for the lifetime of the account and MUST be the same
    across every credential that user owns; storing it once, per user, is what
    enforces that. It is NOT the same as the application user identifier: the
    User Handle is an opaque WebAuthn value emitted to authenticators, whereas
    the application user identifier is your schema's primary key for the user.
    Keeping the two as separate columns lets you resolve from either direction.

A minimal PostgreSQL schema covering the above plus the remaining Credential,
Authenticator, and CredentialAttestation fields is shown below.

Example users table:

    CREATE TABLE webauthn_users (
        id          UUID         PRIMARY KEY DEFAULT uuidv7(),
        created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
        rpid        VARCHAR(512) NOT NULL, -- Relying Party ID
        user_id     UUID         NOT NULL, -- Application-side unique user id (FK to your users table)
        handle      BYTEA        NOT NULL  -- User.WebAuthnID (WebAuthn User Handle); stable per (rpid, user_id)
    );

    CREATE UNIQUE INDEX webauthn_users_user_id_key ON webauthn_users (rpid, user_id);
    CREATE UNIQUE INDEX webauthn_users_handle_key  ON webauthn_users (rpid, handle);

Example credentials table:

    CREATE TABLE webauthn_credentials (
        id                       UUID         PRIMARY KEY DEFAULT uuidv7(),
        created_at               TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_used_at             TIMESTAMPTZ  NULL,
        rpid                     VARCHAR(512) NOT NULL, -- Relying Party ID
        user_id                  UUID         NOT NULL, -- Application-side unique user id
        kid                      BYTEA        NOT NULL, -- Credential.ID
        aaguid                   BYTEA        NULL, -- Authenticator.AAGUID
        public_key               BYTEA        NOT NULL, -- Credential.PublicKey (encrypt at rest)
        attestation_type         VARCHAR(32)  NOT NULL, -- CredentialAttestation.AttestationType
        attestation_format       VARCHAR(32)  NOT NULL, -- CredentialAttestation.AttestationFormat
        attestation              BYTEA        NULL DEFAULT NULL, -- CredentialAttestation serialized as Message Pack or JSON (encrypt at rest)
        transport                VARCHAR(64)  NOT NULL DEFAULT '', -- Credential.Transport serialized as a comma-separated value
        sign_count               BIGINT       NOT NULL DEFAULT 0, -- Authenticator.SignCount
        clone_warning            BOOLEAN      NOT NULL DEFAULT FALSE, -- Authenticator.CloneWarning
        attachment               VARCHAR(64)  NOT NULL DEFAULT '', -- Authenticator.Attachment
        flags                    BYTEA        NOT NULL, -- Value of Flags.ProtocolValue (a single octet), restored with NewCredentialFlags, could also be SMALLINT
        present                  BOOLEAN      NOT NULL DEFAULT FALSE, -- Flags.UserPresent, optionally stored so you can either display it to the user or for filtering credentials
        verified                 BOOLEAN      NOT NULL DEFAULT FALSE, -- Flags.UserVerified, optionally stored so you can either display it to the user or for filtering credentials
        backup_eligible          BOOLEAN      NOT NULL DEFAULT FALSE, -- Flags.BackupEligible, optionally stored so you can either display it to the user or for filtering credentials
        backup_state             BOOLEAN      NOT NULL DEFAULT FALSE -- Flags.BackupState, optionally stored so you can either display it to the user or for filtering credentials
    );

    CREATE UNIQUE INDEX webauthn_credentials_kid_key ON webauthn_credentials (rpid, kid);
    CREATE        INDEX webauthn_credentials_user_id ON webauthn_credentials (rpid, user_id);

With that shape, the two login lookup paths resolve as:

  - Credential-ID-first (allowCredentials flows): match
    `webauthn_credentials.kid` to the credential ID returned by the
    authenticator, then optionally join `webauthn_users` on (rpid, user_id) to
    compare the authenticator-supplied User Handle against the stored one.
  - User-Handle-first (discoverable / passkey flows): match
    `webauthn_users.handle` under the current RP ID to resolve the application
    user id, then load that user's credentials from `webauthn_credentials`.

Fields that change across assertions; Authenticator.SignCount,
Authenticator.CloneWarning, and CredentialFlags.BackupState when
CredentialFlags.BackupEligible is true MUST be written back to storage on every
successful FinishLogin / ValidateLogin so the next ceremony observes the current
values.

For SessionData stored in a database (rather than a server-side session store),
use the same persistence shapes described above. The User Handle on a
SessionData row is per-session ceremony state rather than per-user state, so it
is fine to keep SessionData.UserID on the session row itself; the per-user-table
rule applies to Credential storage, not to SessionData. Additionally index the
challenge (unique) and the expiry timestamp so sessions can be looked up by
challenge at Finish time and expired rows reaped cheaply. Stored sessions must
only be consumed by a Finish call operating under the same RP ID.

[parseCreationOptionsFromJSON]: https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/parseCreationOptionsFromJSON_static
[@simplewebauthn/browser]: https://simplewebauthn.dev/docs/packages/browser

FUNCTIONS

func CredentialParametersDefault() []protocol.CredentialParameter
    CredentialParametersDefault returns the default list of acceptable
    credential algorithms. This includes ES256, ES384, ES512, RS256, RS384,
    RS512, PS256, PS384, PS512, and EdDSA. The order indicates preference.

func CredentialParametersExtendedL3() []protocol.CredentialParameter
    CredentialParametersExtendedL3 returns the WebAuthn Level 3 recommended
    credential algorithm list (EdDSA, ES256, RS256) extended with all other
    algorithms supported by this library (ES384, ES512, RS384, RS512, PS256,
    PS384, PS512). The Level 3 recommended algorithms appear first to indicate
    preference.

func CredentialParametersRecommendedL3() []protocol.CredentialParameter
    CredentialParametersRecommendedL3 returns the WebAuthn Level 3 recommended
    credential algorithm list: EdDSA, ES256, and RS256 (in that order). This is
    the minimal set recommended by the specification for broad authenticator
    compatibility.

func SelectAuthenticator(att string, rrk *bool, uv string) protocol.AuthenticatorSelection
    SelectAuthenticator is a convenience function that constructs
    a protocol.AuthenticatorSelection from individual string
    and boolean parameters. Use protocol.ResidentKeyRequired or
    protocol.ResidentKeyNotRequired for the rrk parameter.

func ValidateFilteredCredential(credential *Credential, filtering *FilteringConfig) (err error)
    ValidateFilteredCredential applies the supplied FilteringConfig to a
    freshly-created Credential and returns a non-nil error when the credential
    violates any configured filtering rule (backup-eligibility prohibition,
    permitted-AAGUID allow-list, prohibited-AAGUID deny-list). A nil filtering
    argument is treated as "no filtering" and the function returns nil.

    The zero AAGUID (uuid.Nil) is never excluded by the permitted list,
    preserving the documented FilteringConfig contract for authenticators that
    report no AAGUID.

    This function is invoked automatically by WebAuthn.CreateCredential using
    the Config.Filtering value; relying parties may also call it directly (e.g.
    to pre-validate a credential before persistence) with any FilteringConfig
    value of their choosing.

    The credential argument must be non-nil.


TYPES

type Authenticator struct {
	// The AAGUID of the authenticator. An AAGUID is defined as an array containing the globally unique
	// identifier of the authenticator model being sought.
	AAGUID []byte `json:"AAGUID,omitempty" msg:"aaguid,omitempty"`

	// SignCount is a representation of the number of times the Authenticator or Credential have been used to login.
	// Upon a new login operation, the Relying Party compares the stored signature counter value with the new SignCount
	// value returned in the assertion’s authenticator data. If this new SignCount value is less than or equal to the
	// stored value, a cloned authenticator may exist, or the authenticator may be malfunctioning.
	SignCount uint32 `json:"signCount,omitempty" msg:"sc,omitempty"`

	// CloneWarning is a signal that the authenticator may be cloned, i.e. at least two copies of the
	// credential private key may exist and are being used in parallel. Relying Parties should incorporate
	// this information into their risk scoring. Whether the Relying Party updates the stored signature
	// counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.
	CloneWarning bool `json:"cloneWarning,omitempty" msg:"cw,omitempty"`

	// Attachment is the authenticatorAttachment value returned by the request.
	Attachment protocol.AuthenticatorAttachment `json:"attachment,omitempty" msg:"aa,omitempty"`
}
    Authenticator represents a specific authenticator in the context of a
    Credential.

func (z *Authenticator) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (z *Authenticator) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z *Authenticator) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (z *Authenticator) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (z *Authenticator) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

func (a *Authenticator) UpdateCounter(authDataCount uint32)
    UpdateCounter updates the authenticator and either sets the clone warning
    value or the sign count.

    Step 17 of §7.2. about verifying attestation. If the signature counter
    value authData.signCount is nonzero or the value stored in conjunction with
    credential’s id attribute is nonzero, then run the following sub-step:

        If the signature counter value authData.signCount is

        → Greater than the signature counter value stored in conjunction with credential’s id attribute.
        Update the stored signature counter value, associated with credential’s id attribute, to be the value of
        authData.signCount.

        → Less than or equal to the signature counter value stored in conjunction with credential’s id attribute.
        This is a signal that the authenticator may be cloned, see CloneWarning above for more information.

type Config struct {
	// RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
	RPID string

	// RPDisplayName configures the display name for the Relying Party Server. This can be any string.
	RPDisplayName string

	// RPOrigins configures the list of Relying Party Server Origins that are permitted. The provided origins can either
	// be fully qualified origins or strings for simple string comparison. The strings are matched using canonical
	// origin matching semantics specifically if they start with 'http://' or 'https://' if the provided origin has a
	// case-insensitive equal scheme and host component they are equal, otherwise simple string comparison is utilized
	// to determine equality.
	RPOrigins []string

	// RPTopOrigins configures the list of Relying Party Server Top Origins that are permitted. The provided origins can
	// either be fully qualified origins or strings for simple string comparison. The strings are matched using
	// canonical origin matching semantics specifically if they start with 'http://' or 'https://' if the provided
	// origin has a case-insensitive equal scheme and host component they are equal, otherwise simple string comparison
	// is utilized to determine equality.
	RPTopOrigins []string

	// RPTopOriginVerificationMode determines the verification mode for the Top Origin value used in cross-origin
	// ceremonies. When the zero value ([protocol.TopOriginDefaultVerificationMode]) is provided, the config
	// validator coerces this field to [protocol.TopOriginExplicitVerificationMode]; i.e. any Top Origin supplied
	// by the client must appear in [Config.RPTopOrigins]. Set this field explicitly to
	// [protocol.TopOriginAutoVerificationMode] or [protocol.TopOriginImplicitVerificationMode] if you need
	// different matching semantics; there is no longer a mode that disables verification entirely.
	RPTopOriginVerificationMode protocol.TopOriginVerificationMode

	// RPAllowCrossOrigin determines whether the RP is allowed to be used in cross-origin contexts. This is disabled
	// by default.
	RPAllowCrossOrigin bool

	// AttestationPreference sets the default attestation conveyance preferences.
	AttestationPreference protocol.ConveyancePreference

	// AuthenticatorSelection sets the default authenticator selection options.
	AuthenticatorSelection protocol.AuthenticatorSelection

	// Debug enables various debug options.
	Debug bool

	// EncodeUserIDAsString ensures the user.id value during registrations is encoded as a raw UTF8 string. This is
	// useful when you only use printable ASCII characters for the random user.id but the browser library does not
	// decode the URL Safe Base64 data.
	EncodeUserIDAsString bool

	// Timeouts configures various timeouts.
	Timeouts TimeoutsConfig

	// MDS configures a FIDO Metadata Service provider for authenticator trust validation. When set, the library
	// validates attestation statements against known authenticator metadata including trust anchors, attestation
	// types, and authenticator status. Use the providers in [github.com/go-webauthn/webauthn/metadata/providers/memory]
	// or [github.com/go-webauthn/webauthn/metadata/providers/cached] to create a provider instance.
	MDS metadata.Provider

	// Filtering configures the filtering of authenticators based on their AAGUIDs. This is useful for enforcing
	// policy on the authenticators that are available to be registered with the Relying Party.
	Filtering *FilteringConfig

	// Has unexported fields.
}
    Config represents the Relying Party configuration for WebAuthn operations.
    At minimum, RPID and RPOrigins must be configured. The RPID should be the
    effective domain of the Relying Party (i.e. "example.com") and RPOrigins
    should contain the fully qualified origins that are permitted (i.e.
    "https://example.com").

func (c *Config) GetMetaDataProvider() metadata.Provider
    GetMetaDataProvider returns the configured FIDO Metadata Service provider.

func (c *Config) GetOrigins() []string
    GetOrigins returns the configured Relying Party Origins.

func (c *Config) GetRPID() string
    GetRPID returns the configured Relying Party ID.

func (c *Config) GetTopOriginVerificationMode() protocol.TopOriginVerificationMode
    GetTopOriginVerificationMode returns the configured Top Origin verification
    mode.

func (c *Config) GetTopOrigins() []string
    GetTopOrigins returns the configured Relying Party Top Origins.

type ConfigProvider interface {
	GetRPID() string
	GetOrigins() []string
	GetTopOrigins() []string
	GetTopOriginVerificationMode() protocol.TopOriginVerificationMode
	GetMetaDataProvider() metadata.Provider
}
    ConfigProvider is an interface that provides access to the WebAuthn
    Config values. This is useful for implementations that wish to provide
    configuration from alternative sources.

type Credential struct {
	// The ID is the ID of the public key credential source. Described by the Credential Record 'id' field.
	ID []byte `json:"id" msg:"id"`

	// The credential public key of the public key credential source. Described by the Credential Record 'publicKey'
	// field.
	PublicKey []byte `json:"publicKey" msg:"pk"`

	// AttestationType is the attestation type as conveyed by the authenticator during the registration ceremonyl
	// one of the values defined by [metadata.AuthenticatorAttestationType] ("basic_full", "basic_surrogate",
	// "attca", "anonca", "ecdaa", "none"). Prior releases incorrectly stored the attestation FORMAT here; see the
	// custom [Credential.UnmarshalJSON] for the backward-compatibility migration applied when decoding such
	// records.
	AttestationType string `json:"attestationType,omitempty" msg:"atttype,omitempty"`

	// AttestationFormat is the attestation statement format identifier ("packed", "tpm", "android-key",
	// "android-safetynet", "fido-u2f", "apple", "compound", "none"); see §8 of the WebAuthn specification and
	// the AttestationFormat constants in the protocol package.
	AttestationFormat string `json:"attestationFormat,omitempty" msg:"attfmt,omitempty"`

	// Transport types the authenticator supports. Described by the Credential Record 'transports' field.
	Transport []protocol.AuthenticatorTransport `json:"transport,omitempty" msg:"t,omitempty"`

	// Flags represent the commonly stored flags.
	Flags CredentialFlags `json:"flags" msg:"flg"`

	// The Authenticator information for a given Credential.
	Authenticator Authenticator `json:"authenticator" msg:"a"`

	// The attestation values that can be used to validate this Credential via the MDS3 at a later date.
	Attestation CredentialAttestation `json:"attestation" msg:"att"`
}
    Credential contains all needed information about a WebAuthn credential for
    storage. This struct is effectively the Credential Record as described in
    the specification.

    Provided this data structure is preserved properly, a Credential can
    be verified against the FIDO Metadata Service at a later date using the
    Credential.Verify method with a metadata.Provider.

    It is strongly recommended for the best security that a Credential is
    encrypted at rest with the exception of the ID and the value you use to
    lookup the user. This prevents a person with access to the database being
    able to compromise privacy by being able to view this data, as well as
    prevents them being able to compromise security by adding or modifying a
    Credential without them also having access to the encryption key.

    For consolidated persistence guidance; recommended schema shape,
    required lookup columns, and which fields must be written back on every
    successful FinishLogin / ValidateLogin; see the Storage section of the
    github.com/go-webauthn/webauthn/webauthn package documentation.

    See: §4. Terminology: Credential Record
    (https://www.w3.org/TR/webauthn-3/#credential-record)

[Storage]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage

func NewCredential(clientDataHash []byte, c *protocol.ParsedCredentialCreationData) (credential *Credential, err error)
    NewCredential returns a *Credential from a successfully validated
    registration response. The returned Credential includes a populated
    CredentialAttestation containing the raw attestation data needed for future
    verification; see the CredentialAttestation documentation for why these
    values must be persisted.

func (z *Credential) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (c *Credential) Descriptor() (descriptor protocol.CredentialDescriptor)
    Descriptor converts a Credential into a protocol.CredentialDescriptor.

func (z *Credential) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z *Credential) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (z *Credential) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (c *Credential) SignalUnknownCredential(rpid string) *protocol.SignalUnknownCredential
    SignalUnknownCredential creates a struct that can easily be marshaled to
    JSON which indicates this is an unknown Credential.

func (c *Credential) UnmarshalJSON(data []byte) error
    UnmarshalJSON decodes a Credential from JSON, applying a
    backward-compatibility migration for records produced by earlier versions
    of this library: if the decoded record has no AttestationFormat and the
    AttestationType value is a recognised attestation FORMAT identifier (i.e.
    "packed", "tpm", "none"), the value is moved to AttestationFormat and
    AttestationType is cleared so callers can re-derive the true attestation
    type by calling Credential.Verify. Records that already carry an
    AttestationFormat are untouched.

func (z *Credential) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

func (c *Credential) Verify(mds metadata.Provider) (err error)
    Verify re-runs the full attestation verification for this credential against
    the given metadata.Provider. The stored raw attestation bytes are re-parsed,
    the attestation signature is re-verified, and the authenticator is validated
    against the MDS via protocol.AttestationObject.VerifyAttestation (which
    internally dispatches protocol.ValidateMetadata). This is the canonical
    audit path and is at least as strong as the original registration-time
    verification; call it on a schedule (i.e. on login or periodically) to
    catch MDS status changes such as a newly-revoked authenticator model or a
    compromise advisory published after registration.

    Requirements:

      - The mds argument must be a non-nil metadata.Provider; a nil provider
        returns an error.

      - CredentialAttestation.ClientDataJSON must be preserved byte-for-byte;
        it is re-parsed for its collected client data fields and re-hashed when
        CredentialAttestation.ClientDataHash is absent.

      - CredentialAttestation.Object must be preserved byte-for-byte; it is the
        raw CBOR attestation object and is decoded to recover the authenticator
        data, statement format, and statement for full re-verification.

      - Credential.PublicKey must be populated with the CBOR-encoded COSE key
        as emitted by the authenticator at registration. As an integrity check,
        Verify compares this value byte-for-byte against the credential public
        key carried inside the attestation object and returns an error on
        mismatch.

      - CredentialAttestation.ClientDataHash is optional; if empty it is
        recomputed as the SHA-256 of ClientDataJSON.

      - Credential.Transport, CredentialAttestation.AuthenticatorData,
        and CredentialAttestation.PublicKeyAlgorithm are not read by the
        current Verify implementation (the authenticator data is re-derived
        from the attestation object, and the top-level AuthenticatorData /
        PublicKeyAlgorithm convenience fields are informational). They are still
        stored so future versions of this library, or alternative verification
        paths, can consume them; see CredentialAttestation for why every field
        should be persisted.

    As a side-effect, a successful Verify call will populate
    Credential.AttestationType from the re-derived value when the field
    is empty (i.e. on a record migrated from a pre-split JSON layout by
    Credential.UnmarshalJSON); the next marshal of the Credential will then
    carry the correct attestation type. For this reason Verify uses a pointer
    receiver.

    See CredentialAttestation for guidance on persisting these raw values
    securely.

func (c *Credential) VerifyAttestationType() (err error)
    VerifyAttestationType is a cutdown version of Verify which only does the
    minimal verification to update the AttestationType if it's unset. For full
    verification use Verify.

type CredentialAttestation struct {
	// ClientDataJSON is the raw JSON-encoded client data from the registration response. This is the verbatim value
	// provided by the client and is used to recompute the client data hash during later verification.
	ClientDataJSON []byte `json:"clientDataJSON,omitempty" msg:"cdj,omitempty"`

	// ClientDataHash is the SHA-256 hash of ClientDataJSON computed during registration verification. If empty,
	// [Credential.Verify] will recompute it from ClientDataJSON.
	ClientDataHash []byte `json:"clientDataHash,omitempty" msg:"cdh,omitempty"`

	// AuthenticatorData is the raw authenticator data from the registration response as provided in the
	// RegistrationResponseJSON. This is the unparsed byte representation that can be re-parsed for future validation.
	AuthenticatorData []byte `json:"authenticatorData,omitempty" msg:"data,omitempty"`

	// PublicKeyAlgorithm is the COSE algorithm identifier for the credential's public key.
	PublicKeyAlgorithm int64 `json:"publicKeyAlgorithm,omitempty" msg:"alg,omitempty"`

	// Object is the raw CBOR-encoded attestation object from the registration response. This contains the attestation
	// statement, format, and authenticator data needed by [Credential.Verify] to re-perform attestation verification.
	Object []byte `json:"object,omitempty" msg:"obj,omitempty"`
}
    CredentialAttestation holds the raw attestation data from a registration
    ceremony. These values are intentionally stored in their original unparsed
    form rather than as parsed structures. This is critical because:

      - It enables the Credential to be verified against the FIDO Metadata
        Service at a later date using Credential.Verify, even long after the
        registration ceremony has completed.
      - The WebAuthn specification evolves over time, introducing new validation
        procedures. Preserving the raw data ensures that credentials created
        today can be re-validated against future rules without requiring
        re-registration.
      - Raw data serves as an auditable record of exactly what the authenticator
        and client provided during registration, independent of how the library
        parsed it at that point in time.

    Implementers MUST persist all fields of this struct.

func (z *CredentialAttestation) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (z *CredentialAttestation) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z *CredentialAttestation) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (z *CredentialAttestation) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (z *CredentialAttestation) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

type CredentialFlags struct {
	// Flag UP indicates the users presence.
	UserPresent bool `json:"userPresent"`

	// Flag UV indicates the user performed verification.
	UserVerified bool `json:"userVerified"`

	// Flag BE indicates the credential is able to be backed up and/or sync'd between devices. This should NEVER change.
	BackupEligible bool `json:"backupEligible"`

	// Flag BS indicates the credential has been backed up and/or sync'd. This value can change but it's recommended
	// that RP's keep track of this value.
	BackupState bool `json:"backupState"`

	// Has unexported fields.
}
    CredentialFlags contains the boolean flags derived from the authenticator
    data during registration or login. These flags indicate the state of user
    presence, user verification, and backup eligibility/state at the time the
    credential was used.

func CredentialFlagsFromMsgpByte(b byte) CredentialFlags
    CredentialFlagsFromMsgpByte reconstructs a CredentialFlags from the
    single-byte representation produced by CredentialFlags.MsgpByte. It is
    intended for use by the msgp-generated serialization layer; normal callers
    should prefer NewCredentialFlags.

func NewCredentialFlags(flags protocol.AuthenticatorFlags) CredentialFlags
    NewCredentialFlags is a utility function that is used to derive the
    Credential's Flags field given a protocol.AuthenticatorFlags. This allows
    implementers to solely save the Raw field of the CredentialFlags to restore
    them appropriately for appropriate processing without concern that changes
    forced upon implementers by the W3C will introduce breaking changes.

func (z *CredentialFlags) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (z CredentialFlags) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z CredentialFlags) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (f CredentialFlags) MsgpByte() byte
    MsgpByte returns the CredentialFlags encoded as a single byte, equivalent
    to the raw protocol.AuthenticatorFlags value. It is intended for use by the
    msgp-generated serialization layer (see the //msgp:shim directive in this
    file); normal callers should prefer CredentialFlags.ProtocolValue.

func (z CredentialFlags) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (f CredentialFlags) ProtocolValue() protocol.AuthenticatorFlags
    ProtocolValue returns the underlying protocol.AuthenticatorFlags provided
    this CredentialFlags was created using NewCredentialFlags.

func (z *CredentialFlags) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

type Credentials []Credential
    Credentials is a decorator type which allows easily converting a
    Credential slice into a protocol.CredentialDescriptor slice by utilizing
    the Credentials.CredentialDescriptors method. This will be the type used
    globally for the library in a future release.

func (c Credentials) CredentialDescriptors() (descriptors []protocol.CredentialDescriptor)
    CredentialDescriptors returns the protocol.CredentialDescriptor slice for
    this Credentials type.

func (z *Credentials) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (z Credentials) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z Credentials) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (z Credentials) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (z *Credentials) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

type DiscoverableUserHandler func(rawID, userHandle []byte) (user User, err error)
    DiscoverableUserHandler is a callback function that the Relying
    Party must provide when performing a discoverable (passkey) login.
    It is called with the rawID of the credential and the userHandle from the
    authenticator response, and must return the User who owns the credential.
    This is necessary because in discoverable login flows, the Relying Party
    does not know which user is authenticating until the authenticator response
    is received.

type FilteringConfig struct {
	// ProhibitBackupEligibility if set will prohibit the use of authenticators with the backup eligible flag set.
	ProhibitBackupEligibility bool

	// PermittedAAGUIDs if set is used to filter authenticators by their AAGUID only allowing specific values. This
	// option is mutually exclusive with ProhibitedAAGUIDs and will never exclude a zero AAGUID. To prohibit the use
	// of Zero AAGUIDs, use [Config.MDS] or [FilteringConfig.ProhibitedAAGUIDs].
	PermittedAAGUIDs []uuid.UUID

	// ProhibitedAAGUIDs if set is used to filter authenticators by their AAGUID only prohibiting specific values. This
	// option is mutually exclusive with PermittedAAGUIDs.
	ProhibitedAAGUIDs []uuid.UUID
}
    FilteringConfig configures the filtering of authenticators based on their
    AAGUIDs. This is useful for enforcing policy on the authenticators that are
    available to be registered with the Relying Party.

type LoginOption func(*protocol.PublicKeyCredentialRequestOptions)
    LoginOption is a functional option that modifies the
    protocol.PublicKeyCredentialRequestOptions sent to the client during
    a login ceremony. Use the With* functions in this package (i.e.
    WithUserVerification, WithAllowedCredentials) to create login options.

func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption
    WithAllowedCredentials adjusts the allowed credentials via a slice
    of protocol.CredentialDescriptor values, discussed in the included
    specification sections with user-supplied values.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-allowcredentials)

    Specification: §5.10.3. Credential Descriptor
    (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)

func WithAppIdExtension(appid string) LoginOption
    WithAppIdExtension automatically includes the specified appid if the
    AllowedCredentials contains a credential with the type `fido-u2f`.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-extensions)

func WithAssertionExtensions(extensions protocol.AuthenticationExtensions) LoginOption
    WithAssertionExtensions adjusts the requested extensions by providing a
    protocol.AuthenticationExtensions.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-extensions)

func WithAssertionPublicKeyCredentialHints(hints []protocol.PublicKeyCredentialHints) LoginOption
    WithAssertionPublicKeyCredentialHints adjusts the non-default hints
    for credential types to select during login by providing a slice of
    protocol.PublicKeyCredentialHints.

    WebAuthn Level 3.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints)

func WithChallenge(challenge []byte) LoginOption
    WithChallenge overrides the random challenge that WebAuthn.BeginLogin would
    otherwise generate for this ceremony. The supplied value is used verbatim.

    The only safe reason to call this is when the relying party needs to record
    the challenge in a server-side store before the ceremony is initiated; for
    example to maintain a set of previously-issued challenges so it can reject a
    replay that reuses one. Generating the challenge inside a separate step lets
    the RP persist it atomically before it is ever handed to the client.

    If you have that need, the supplied challenge MUST be produced by
    protocol.CreateChallenge (32 bytes from crypto/rand). Do not use timestamps,
    counters, UUIDs, hashed user inputs, or any other deterministic
    or partially-predictable source; these defeat the cryptographic
    guarantees the challenge provides and open the ceremony to replay and
    guessing attacks. WebAuthn.BeginLogin enforces a minimum length of
    protocol.MinimumChallengeLength bytes, but that check is a backstop only and
    is not a substitute for using a CSPRNG.

    If you do not have a specific persistence requirement, do not use this
    function; let the library generate the challenge automatically.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-challenge)

    Specification: §13.4.3. Cryptographic Challenges
    (https://www.w3.org/TR/webauthn/#sctn-cryptographic-challenges)

func WithLoginRelyingPartyID(id string) LoginOption
    WithLoginRelyingPartyID sets the Relying Party ID for this particular login.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-rpid)

func WithUserVerification(userVerification protocol.UserVerificationRequirement) LoginOption
    WithUserVerification adjusts the user verification preference by providing a
    protocol.UserVerificationRequirement.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-userverification)

type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)
    RegistrationOption is a functional option that modifies the
    protocol.PublicKeyCredentialCreationOptions sent to the client during
    a registration ceremony. Use the With* functions in this package (i.e.
    WithConveyancePreference, WithExclusions, WithAuthenticatorSelection) to
    create registration options.

func WithAppIdExcludeExtension(appid string) RegistrationOption
    WithAppIdExcludeExtension automatically includes the specified appid if the
    CredentialExcludeList contains a credential with the type `fido-u2f`.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions)

    Specification: §9. Extensions
    (https://www.w3.org/TR/webauthn/#webauthn-extensions)

    Specification: §10.1.2. FIDO AppID Exclusion Extension
    (https://www.w3.org/TR/webauthn/#sctn-appid-exclude-extension)

func WithAttestationFormats(formats []protocol.AttestationFormat) RegistrationOption
    WithAttestationFormats adjusts the non-default formats for credential types
    to select during registration.

    WebAuthn Level 3.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-attestationformats)

func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption
    WithAuthenticatorSelection adjusts the non-default parameters regarding the
    authenticator to select during registration.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection)

    Specification: §5.4.4. Authenticator Selection Criteria
    (https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)

func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption
    WithConveyancePreference adjusts the non-default parameters regarding
    whether the authenticator should attest to the credential.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-attestation)

func WithCredentialParameters(credentialParams []protocol.CredentialParameter) RegistrationOption
    WithCredentialParameters adjusts the credential parameters in the
    registration options.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams)

func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption
    WithExclusions adjusts the non-default parameters regarding credentials to
    exclude from registration.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-excludecredentials)

func WithExtensions(extension protocol.AuthenticationExtensions) RegistrationOption
    WithExtensions adjusts the extension parameter in the registration options.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-extensions)

    Specification: §9. Extensions
    (https://www.w3.org/TR/webauthn/#webauthn-extensions)

func WithPublicKeyCredentialHints(hints []protocol.PublicKeyCredentialHints) RegistrationOption
    WithPublicKeyCredentialHints adjusts the non-default hints for credential
    types to select during registration.

    WebAuthn Level 3.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-hints)

func WithRegistrationRelyingPartyID(id string) RegistrationOption
    WithRegistrationRelyingPartyID sets the relying party id for the
    registration.

func WithRegistrationRelyingPartyName(name string) RegistrationOption
    WithRegistrationRelyingPartyName sets the relying party name for the
    registration.

func WithResidentKeyRequirement(requirement protocol.ResidentKeyRequirement) RegistrationOption
    WithResidentKeyRequirement sets both the resident key and require resident
    key protocol options.

    Specification: §5.4. Parameters for Credential Generation
    (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection)

    Specification: §5.4.4. Authenticator Selection Criteria
    (https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)

type SessionData struct {
	Challenge            string    `json:"challenge" msg:"c"`
	RelyingPartyID       string    `json:"rpId,omitempty" msg:"r,omitempty"`
	UserID               []byte    `json:"user_id,omitempty" msg:"u,omitempty"`
	AllowedCredentialIDs [][]byte  `json:"allowed_credentials,omitempty" msg:"allow,omitempty"`
	Expires              time.Time `json:"expires" msg:"exp"`

	UserVerification protocol.UserVerificationRequirement    `json:"userVerification,omitempty" msg:"uv,omitempty"`
	Extensions       protocol.AuthenticationExtensions       `json:"extensions,omitempty" msg:"exts,omitempty"`
	CredParams       []protocol.CredentialParameter          `json:"credParams,omitempty" msg:"params,omitempty"`
	Mediation        protocol.CredentialMediationRequirement `json:"mediation,omitempty" msg:"cmr,omitempty"`
}
    SessionData is the data that must be stored by the Relying Party between the
    Begin and Finish steps of a WebAuthn ceremony. It contains the challenge and
    other parameters needed to verify the authenticator's response.

    The Relying Party must store this data securely and associate it with the
    user's session. It should not be modifiable by the client (i.e. store it
    server-side or in a signed, opaque cookie). After the ceremony completes,
    the session data should be discarded.

    Every field returned by the Begin* functions must be delivered to the
    matching Finish* / Validate* call with the same values; if anything is
    dropped or reshaped in transit, verification will fail. Treat SessionData as
    an atomic record between those two calls.

    For consolidated persistence guidance; recommended schema shape, required
    lookup columns, and the rules that also apply to Credential records; see
    the Storage section of the github.com/go-webauthn/webauthn/webauthn package
    documentation.

[Storage]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage

func (z *SessionData) DecodeMsg(dc *msgp.Reader) (err error)
    DecodeMsg implements msgp.Decodable

func (z *SessionData) EncodeMsg(en *msgp.Writer) (err error)
    EncodeMsg implements msgp.Encodable

func (z *SessionData) MarshalMsg(b []byte) (o []byte, err error)
    MarshalMsg implements msgp.Marshaler

func (z *SessionData) Msgsize() (s int)
    Msgsize returns an upper bound estimate of the number of bytes occupied by
    the serialized message

func (z *SessionData) UnmarshalMsg(bts []byte) (o []byte, err error)
    UnmarshalMsg implements msgp.Unmarshaler

type TimeoutConfig struct {
	// Enforce the timeouts at the Relying Party / Server. This means if enabled and the user takes too long that even
	// if the browser does not enforce the timeout the Relying Party / Server will.
	Enforce bool

	// Timeout is the timeout for logins/registrations when the UserVerificationRequirement is set to anything other
	// than discouraged.
	Timeout time.Duration

	// TimeoutUVD is the timeout for logins/registrations when the UserVerificationRequirement is set to discouraged.
	TimeoutUVD time.Duration
}
    TimeoutConfig configures timeout behavior for a specific WebAuthn ceremony
    (registration or login).

type TimeoutsConfig struct {
	Login        TimeoutConfig
	Registration TimeoutConfig
}
    TimeoutsConfig configures the timeout durations for both login and
    registration ceremonies. These values are sent to the client as the timeout
    field in the credential request/creation options and optionally enforced
    server-side.

type User interface {
	// WebAuthnID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
	// size of 64 bytes, and is not meant to be displayed to the user.
	//
	// To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
	// member, not the displayName nor name members. See Section 6.1 of [RFC8266].
	//
	// It's recommended this value is completely random and uses the entire 64 bytes.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
	WebAuthnID() []byte

	// WebAuthnName provides the name attribute of the user account during registration and is a human-palatable name
	// for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD
	// let the user choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
	WebAuthnName() string

	// WebAuthnDisplayName provides the name attribute of the user account during registration and is a human-palatable
	// name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
	// SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
	WebAuthnDisplayName() string

	// WebAuthnCredentials provides the slice of [Credential] objects owned by the user. This generally should be all
	// the [Credential] objects owned by the user regardless of which flow is being used.
	WebAuthnCredentials() []Credential
}
    User is an interface with the Relying Party's User entry and provides the
    fields and methods needed for WebAuthn registration operations.

type WebAuthn struct {
	Config *Config
}
    WebAuthn is the primary interface of this package. It provides methods to
    begin and finish both registration and login ceremonies. Create an instance
    using New and then call the appropriate Begin/Finish methods for your use
    case. See the package documentation for detailed ceremony flows.

func New(config *Config) (*WebAuthn, error)
    New creates a new WebAuthn instance from the provided Config. The
    configuration is validated before the instance is returned.

func (webauthn *WebAuthn) BeginDiscoverableLogin(opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
    BeginDiscoverableLogin creates the *protocol.CredentialAssertion
    data payload that should be sent to the user agent for beginning the
    login/assertion process. This function is used to perform a client-side
    discoverable login when the identity of the user is not known such as
    passwordless or usernameless authentication, to specify a conditional
    mediation requirement use WebAuthn.BeginDiscoverableMediatedLogin, to
    perform logins where the identity of the user is known such as multifactor
    authentication see WebAuthn.BeginLogin and WebAuthn.BeginMediatedLogin
    instead. The format of this data can be seen in §5.5 of the WebAuthn
    specification. These default values can be amended by providing additional
    LoginOption parameters. This function also returns SessionData,
    that must be stored by the RP in a secure manner and then provided to the
    WebAuthn.FinishLogin function. This data helps us verify the ownership of
    the credential being retrieved.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)

func (webauthn *WebAuthn) BeginDiscoverableMediatedLogin(mediation protocol.CredentialMediationRequirement, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
    BeginDiscoverableMediatedLogin is similar to WebAuthn.BeginDiscoverableLogin
    however it also allows specifying a credential mediation requirement.

func (webauthn *WebAuthn) BeginLogin(user User, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
    BeginLogin creates the *protocol.CredentialAssertion data payload that
    should be sent to the user agent for beginning the login/assertion
    process. This function is used to perform a login when the identity
    of the user is known such as multifactor authentications, to specify
    a conditional mediation requirement use WebAuthn.BeginMediatedLogin,
    to perform a login when the identity of the user is not known see
    WebAuthn.BeginDiscoverableLogin and WebAuthn.BeginDiscoverableMediatedLogin
    instead. The format of this data can be seen in §5.5 of the WebAuthn
    specification. These default values can be amended by providing additional
    LoginOption parameters. This function also returns SessionData,
    that must be stored by the RP in a secure manner and then provided to the
    WebAuthn.FinishLogin function. This data helps us verify the ownership of
    the credential being retrieved.

    Specification: §5.5. Options for Assertion Generation
    (https://www.w3.org/TR/webauthn/#dictionary-assertion-options)

func (webauthn *WebAuthn) BeginMediatedLogin(user User, mediation protocol.CredentialMediationRequirement, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error)
    BeginMediatedLogin is similar to WebAuthn.BeginLogin however it also allows
    specifying a credential mediation requirement.

func (webauthn *WebAuthn) BeginMediatedRegistration(user User, mediation protocol.CredentialMediationRequirement, opts ...RegistrationOption) (creation *protocol.CredentialCreation, session *SessionData, err error)
    BeginMediatedRegistration is similar to WebAuthn.BeginRegistration however
    it also allows specifying a credential mediation requirement.

func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (creation *protocol.CredentialCreation, session *SessionData, err error)
    BeginRegistration generates a new set of registration data to be sent to the
    client and authenticator. To set a conditional mediation requirement for the
    registration see WebAuthn.BeginMediatedRegistration.

func (webauthn *WebAuthn) CreateCredential(user User, session SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (credential *Credential, err error)
    CreateCredential verifies a parsed response against the user's credentials
    and session data.

    If you wish to skip performing the step required to parse the
    *protocol.ParsedCredentialCreationData and you're using net/http then you
    can use WebAuthn.FinishRegistration instead.

func (webauthn *WebAuthn) FinishDiscoverableLogin(handler DiscoverableUserHandler, session SessionData, response *http.Request) (credential *Credential, err error)
    FinishDiscoverableLogin takes the response from the client and validates it
    against the handler and stored session data. The handler helps to find out
    which user must be used to validate the response. This is a function defined
    in your business code that will retrieve the user from your persistent data.

    As with all Finish functions, this function requires a
    *http.Request but you can perform the same steps with
    the protocol.ParseCredentialRequestResponseBody or
    protocol.ParseCredentialRequestResponseBytes which require an
    io.Reader or byte array respectively, you can also use an arbitrary
    *protocol.ParsedCredentialAssertionData which is returned from all of these
    functions i.e. by implementing a custom parser. The DiscoverableUserHandler,
    *SessionData, and *protocol.ParsedCredentialAssertionData can then be used
    with the WebAuthn.ValidatePasskeyLogin function.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User returned by the handler does not contain a Credential with the
    same ID byte array provided all Credential's in the SessionData exist in the
    User's Credential list.

func (webauthn *WebAuthn) FinishLogin(user User, session SessionData, response *http.Request) (credential *Credential, err error)
    FinishLogin takes the response from the client and validates it against the
    user credentials and stored session data.

    As with all Finish functions, this function requires a
    *http.Request but you can perform the same steps with
    the protocol.ParseCredentialRequestResponseBody or
    protocol.ParseCredentialRequestResponseBytes which require an
    io.Reader or byte array respectively, you can also use an arbitrary
    *protocol.ParsedCredentialAssertionData which is returned from all of
    these functions i.e. by implementing a custom parser. The *SessionData,
    and *protocol.ParsedCredentialAssertionData can then be used with the
    WebAuthn.ValidateLogin function.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User provided does not contain a Credential with the same ID byte
    array provided all Credential's in the SessionData exist in the User's
    Credential list.

func (webauthn *WebAuthn) FinishPasskeyLogin(handler DiscoverableUserHandler, session SessionData, response *http.Request) (user User, credential *Credential, err error)
    FinishPasskeyLogin takes the response from the client and validate it
    against the handler and stored session data. The handler helps to find out
    which user must be used to validate the response. This is a function defined
    in your business code that will retrieve the user from your persistent data.

    As with all Finish functions this function requires a
    *http.Request but you can perform the same steps with
    the protocol.ParseCredentialRequestResponseBody or
    protocol.ParseCredentialRequestResponseBytes which require an
    io.Reader or byte array respectively, you can also use an arbitrary
    *protocol.ParsedCredentialAssertionData which is returned from all of these
    functions i.e. by implementing a custom parser. The DiscoverableUserHandler,
    *SessionData, and *protocol.ParsedCredentialAssertionData can then be used
    with the WebAuthn.ValidatePasskeyLogin function.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User returned by the handler does not contain a Credential with the
    same ID byte array provided all Credential's in the SessionData exist in the
    User's Credential list.

func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, request *http.Request) (credential *Credential, err error)
    FinishRegistration takes the response from the authenticator and client and
    verify the credential against the user's credentials and session data.

    As with all Finish functions this function requires a
    *http.Request but you can perform the same steps with
    the protocol.ParseCredentialCreationResponseBody or
    protocol.ParseCredentialCreationResponseBytes which require an
    io.Reader or byte array respectively, you can also use an arbitrary
    *protocol.ParsedCredentialCreationData which is returned from all of these
    functions i.e. by implementing a custom parser. The User, *SessionData,
    and *protocol.ParsedCredentialCreationData can then be used with the
    WebAuthn.CreateCredential function.

func (webauthn *WebAuthn) ValidateDiscoverableLogin(handler DiscoverableUserHandler, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (credential *Credential, err error)
    ValidateDiscoverableLogin is similar to WebAuthn.ValidateLogin
    that allows for discoverable credentials. It's recommended that
    WebAuthn.ValidatePasskeyLogin is used instead.

    If you wish to skip performing the step required to parse the
    *protocol.ParsedCredentialAssertionData and you're using net/http then you
    can use WebAuthn.FinishDiscoverableLogin instead.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User returned by the handler does not contain a Credential with the
    same ID byte array provided all Credential's in the SessionData exist in the
    User's Credential list.

    Note: this is just a backwards compatibility layer over
    WebAuthn.ValidatePasskeyLogin which returns more information.

func (webauthn *WebAuthn) ValidateLogin(user User, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (credential *Credential, err error)
    ValidateLogin takes a parsed response and validates it against the user
    credentials and session data.

    If you wish to skip performing the step required to parse the
    *protocol.ParsedCredentialAssertionData and you're using net/http then you
    can use WebAuthn.FinishLogin instead.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User provided does not contain a Credential with the same ID byte
    array provided all Credential's in the SessionData exist in the User's
    Credential list.

func (webauthn *WebAuthn) ValidatePasskeyLogin(handler DiscoverableUserHandler, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (user User, credential *Credential, err error)
    ValidatePasskeyLogin is similar to WebAuthn.ValidateLogin that allows for
    discoverable credentials.

    If you wish to skip performing the step required to parse the
    *protocol.ParsedCredentialAssertionData and you're using net/http then you
    can use WebAuthn.FinishPasskeyLogin instead.

    This function will return the protocol.ErrorUnknownCredential error type
    when the User returned by the handler does not contain a Credential with the
    same ID byte array provided all Credential's in the SessionData exist in the
    User's Credential list.

