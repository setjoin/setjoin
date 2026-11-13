package minio // import "github.com/minio/minio-go/v7"


CONSTANTS

const (
	Enabled = "Enabled"
	// Disabled  State = "Disabled" only used by MFA Delete not supported yet.
	Suspended = "Suspended"
)
    Various supported states

const (
	// TierStandard is the standard retrieval tier
	TierStandard = TierType("Standard")
	// TierBulk is the bulk retrieval tier
	TierBulk = TierType("Bulk")
	// TierExpedited is the expedited retrieval tier
	TierExpedited = TierType("Expedited")
)
const (

	// ChecksumSHA256 indicates a SHA256 checksum.
	ChecksumSHA256 ChecksumType = 1 << iota
	// ChecksumSHA1 indicates a SHA-1 checksum.
	ChecksumSHA1
	// ChecksumCRC32 indicates a CRC32 checksum with IEEE table.
	ChecksumCRC32
	// ChecksumCRC32C indicates a CRC32 checksum with Castagnoli table.
	ChecksumCRC32C
	// ChecksumCRC64NVME indicates CRC64 with 0xad93d23594c93659 polynomial.
	ChecksumCRC64NVME
	// ChecksumMD5 indicates an MD5 checksum.
	ChecksumMD5
	// ChecksumSHA512 indicates a SHA-512 checksum.
	ChecksumSHA512
	// ChecksumXXHash64 indicates an XXHash64 checksum.
	ChecksumXXHash64
	// ChecksumXXHash3 indicates an XXH3-64 checksum.
	ChecksumXXHash3
	// ChecksumXXHash128 indicates an XXH3-128 checksum.
	ChecksumXXHash128

	// ChecksumFullObject is a modifier that can be used on CRC32 and CRC32C
	// to indicate full object checksums.
	ChecksumFullObject

	// ChecksumNone indicates no checksum.
	ChecksumNone ChecksumType = 0

	// ChecksumFullObjectCRC32 indicates full object CRC32
	ChecksumFullObjectCRC32 = ChecksumCRC32 | ChecksumFullObject

	// ChecksumFullObjectCRC32C indicates full object CRC32C
	ChecksumFullObjectCRC32C = ChecksumCRC32C | ChecksumFullObject
)
const (
	// GetObjectAttributesTags are tags used to defined
	// return values for the GetObjectAttributes API
	GetObjectAttributesTags = "ETag,Checksum,StorageClass,ObjectSize,ObjectParts"
	// GetObjectAttributesMaxParts defined the default maximum
	// number of parts returned by GetObjectAttributes
	GetObjectAttributesMaxParts = 1000
)
const (

	// ETag is a common response header
	ETag = "ETag"
)
const (
	NoSuchBucket                      = "NoSuchBucket"
	NoSuchKey                         = "NoSuchKey"
	NoSuchUpload                      = "NoSuchUpload"
	AccessDenied                      = "AccessDenied"
	Conflict                          = "Conflict"
	PreconditionFailed                = "PreconditionFailed"
	InvalidArgument                   = "InvalidArgument"
	EntityTooLarge                    = "EntityTooLarge"
	EntityTooSmall                    = "EntityTooSmall"
	UnexpectedEOF                     = "UnexpectedEOF"
	APINotSupported                   = "APINotSupported"
	InvalidRegion                     = "InvalidRegion"
	NoSuchBucketPolicy                = "NoSuchBucketPolicy"
	BadDigest                         = "BadDigest"
	IncompleteBody                    = "IncompleteBody"
	InternalError                     = "InternalError"
	InvalidAccessKeyID                = "InvalidAccessKeyId"
	InvalidBucketName                 = "InvalidBucketName"
	InvalidDigest                     = "InvalidDigest"
	InvalidRange                      = "InvalidRange"
	MalformedXML                      = "MalformedXML"
	MissingContentLength              = "MissingContentLength"
	MissingContentMD5                 = "MissingContentMD5"
	MissingRequestBodyError           = "MissingRequestBodyError"
	NotImplemented                    = "NotImplemented"
	RequestTimeTooSkewed              = "RequestTimeTooSkewed"
	SignatureDoesNotMatch             = "SignatureDoesNotMatch"
	MethodNotAllowed                  = "MethodNotAllowed"
	InvalidPart                       = "InvalidPart"
	InvalidPartOrder                  = "InvalidPartOrder"
	InvalidObjectState                = "InvalidObjectState"
	AuthorizationHeaderMalformed      = "AuthorizationHeaderMalformed"
	MalformedPOSTRequest              = "MalformedPOSTRequest"
	BucketNotEmpty                    = "BucketNotEmpty"
	AllAccessDisabled                 = "AllAccessDisabled"
	MalformedPolicy                   = "MalformedPolicy"
	MissingFields                     = "MissingFields"
	AuthorizationQueryParametersError = "AuthorizationQueryParametersError"
	MalformedDate                     = "MalformedDate"
	BucketAlreadyOwnedByYou           = "BucketAlreadyOwnedByYou"
	InvalidDuration                   = "InvalidDuration"
	XAmzContentSHA256Mismatch         = "XAmzContentSHA256Mismatch"
	XMinioInvalidObjectName           = "XMinioInvalidObjectName"
	NoSuchCORSConfiguration           = "NoSuchCORSConfiguration"
	BucketAlreadyExists               = "BucketAlreadyExists"
	NoSuchVersion                     = "NoSuchVersion"
	NoSuchTagSet                      = "NoSuchTagSet"
	Testing                           = "Testing"
	Success                           = "Success"
)
    Constants for error keys

const MaxJitter = 1.0
    MaxJitter will randomize over the full exponential backoff time

const NoJitter = 0.0
    NoJitter disables the use of jitter for randomizing the exponential backoff
    time

const QOSConfigVersionCurrent = "v1"
    QOSConfigVersionCurrent is the current version of the QoS configuration.

const (
	// RestoreSelect represents the restore SELECT operation
	RestoreSelect = RestoreType("SELECT")
)

VARIABLES

var DefaultRetryCap = time.Second
    DefaultRetryCap - Each retry attempt never waits no longer than this maximum
    time duration.

var DefaultRetryUnit = 200 * time.Millisecond
    DefaultRetryUnit - default unit multiplicative per retry. defaults to 200 *
    time.Millisecond

var DefaultTransport = func(secure bool) (*http.Transport, error) {
	tr := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          256,
		MaxIdleConnsPerHost:   16,
		ResponseHeaderTimeout: time.Minute,
		IdleConnTimeout:       time.Minute,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 10 * time.Second,

		DisableCompression: true,
	}

	if secure {
		tr.TLSClientConfig = &tls.Config{

			MinVersion: tls.VersionTLS12,
		}
		if f := os.Getenv("SSL_CERT_FILE"); f != "" {
			rootCAs := mustGetSystemCertPool()
			data, err := os.ReadFile(f)
			if err == nil {
				rootCAs.AppendCertsFromPEM(data)
			}
			tr.TLSClientConfig.RootCAs = rootCAs
		}
	}
	return tr, nil
}
    DefaultTransport - this default transport is similar to
    http.DefaultTransport but with additional param DisableCompression is set to
    true to avoid decompressing content with 'gzip' encoding.

var MaxRetry = 10
    MaxRetry is the maximum number of retries before stopping.


FUNCTIONS

func IsNetworkOrHostDown(err error, expectTimeouts bool) bool
    IsNetworkOrHostDown - if there was a network error or if the host is down.
    expectTimeouts indicates that *context* timeouts are expected and does not
    indicate a downed host. Other timeouts still returns down.

func OptimalPartInfo(objectSize int64, configuredPartSize uint64) (totalPartsCount int, partSize, lastPartSize int64, err error)
    OptimalPartInfo - calculate the optimal part info for a given object size.

    NOTE: Assumption here is that for any object to be uploaded to any
    S3 compatible object storage it will have the following parameters as
    constants.

        maxPartsCount - 10000
        minPartSize - 16MiB
        maxObjectSize - ~48.83TiB (maxPartSize * maxPartsCount)


TYPES

type AccessControlList struct {
	XMLName    xml.Name `xml:"AccessControlList"`
	Grant      []Grant
	Permission string `xml:"Permission"`
}
    AccessControlList contains the set of grantees and the permissions assigned
    to each grantee.

type AdvancedGetOptions struct {
	ReplicationDeleteMarker           bool
	IsReplicationReadyForDeleteMarker bool
	ReplicationProxyRequest           string
}
    AdvancedGetOptions for internal use by MinIO server - not intended for
    client use.

type AdvancedObjectTaggingOptions struct {
	ReplicationProxyRequest string
}
    AdvancedObjectTaggingOptions for internal use by MinIO server - not intended
    for client use.

type AdvancedPutOptions struct {
	SourceVersionID          string
	SourceETag               string
	ReplicationStatus        ReplicationStatus
	SourceMTime              time.Time
	ReplicationRequest       bool
	RetentionTimestamp       time.Time
	TaggingTimestamp         time.Time
	LegalholdTimestamp       time.Time
	ReplicationValidityCheck bool
}
    AdvancedPutOptions for internal use - to be utilized by replication,
    ILM transition implementation on MinIO server

type AdvancedRemoveOptions struct {
	ReplicationDeleteMarker  bool
	ReplicationStatus        ReplicationStatus
	ReplicationMTime         time.Time
	ReplicationRequest       bool
	ReplicationValidityCheck bool // check permissions
}
    AdvancedRemoveOptions intended for internal use by replication

type AppendObjectOptions struct {
	// Provide a progress reader to indicate the current append() progress.
	Progress io.Reader
	// ChunkSize indicates the maximum append() size,
	// it is useful when you want to control how much data
	// per append() you are interested in sending to server
	// while keeping the input io.Reader of a longer length.
	ChunkSize uint64
	// Aggressively disable sha256 payload, it is automatically
	// turned-off for TLS supporting endpoints, useful in benchmarks
	// where you are interested in the peak() numbers.
	DisableContentSha256 bool

	// Has unexported fields.
}
    AppendObjectOptions
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-append.html

func (opts AppendObjectOptions) Header() (header http.Header)
    Header returns the custom header for AppendObject API

type BucketInfo struct {
	// The name of the bucket.
	Name string `json:"name"`
	// Date the bucket was created.
	CreationDate time.Time `json:"creationDate"`
	// BucketRegion region where the bucket is present
	BucketRegion string `json:"bucketRegion"`
}
    BucketInfo container for bucket metadata.

type BucketLookupType int
    BucketLookupType is type of url lookup supported by server.

const (
	BucketLookupAuto BucketLookupType = iota
	BucketLookupDNS
	BucketLookupPath
)
    Different types of url lookup supported by the server.Initialized to
    BucketLookupAuto

type BucketOptions = RemoveBucketOptions
    Deprecated: BucketOptions will be renamed to RemoveBucketOptions in future
    versions.

type BucketVersioningConfiguration struct {
	XMLName   xml.Name `xml:"VersioningConfiguration"`
	Status    string   `xml:"Status"`
	MFADelete string   `xml:"MfaDelete,omitempty"`
	// MinIO extension - allows selective, prefix-level versioning exclusion.
	// Requires versioning to be enabled
	ExcludedPrefixes []ExcludedPrefix `xml:",omitempty"`
	ExcludeFolders   bool             `xml:",omitempty"`
	PurgeOnDelete    string           `xml:",omitempty"`
}
    BucketVersioningConfiguration is the versioning configuration structure

func (b BucketVersioningConfiguration) Enabled() bool
    Enabled returns true if bucket versioning is enabled

func (b BucketVersioningConfiguration) Suspended() bool
    Suspended returns true if bucket versioning is suspended

type CSVFileHeaderInfo string
    CSVFileHeaderInfo - is the parameter for whether to utilize headers.

const (
	CSVFileHeaderInfoNone   CSVFileHeaderInfo = "NONE"
	CSVFileHeaderInfoIgnore CSVFileHeaderInfo = "IGNORE"
	CSVFileHeaderInfoUse    CSVFileHeaderInfo = "USE"
)
    Constants for file header info.

type CSVInputOptions struct {
	FileHeaderInfo CSVFileHeaderInfo

	RecordDelimiter string

	FieldDelimiter string

	QuoteCharacter string

	QuoteEscapeCharacter string

	Comments string
	// Has unexported fields.
}
    CSVInputOptions csv input specific options

func (c CSVInputOptions) MarshalXML(e *xml.Encoder, start xml.StartElement) error
    MarshalXML - produces the xml representation of the CSV input options struct

func (c *CSVInputOptions) SetComments(val string)
    SetComments sets the comments character in the CSV input options

func (c *CSVInputOptions) SetFieldDelimiter(val string)
    SetFieldDelimiter sets the field delimiter in the CSV input options

func (c *CSVInputOptions) SetFileHeaderInfo(val CSVFileHeaderInfo)
    SetFileHeaderInfo sets the file header info in the CSV input options

func (c *CSVInputOptions) SetQuoteCharacter(val string)
    SetQuoteCharacter sets the quote character in the CSV input options

func (c *CSVInputOptions) SetQuoteEscapeCharacter(val string)
    SetQuoteEscapeCharacter sets the quote escape character in the CSV input
    options

func (c *CSVInputOptions) SetRecordDelimiter(val string)
    SetRecordDelimiter sets the record delimiter in the CSV input options

type CSVOutputOptions struct {
	QuoteFields CSVQuoteFields

	RecordDelimiter string

	FieldDelimiter string

	QuoteCharacter string

	QuoteEscapeCharacter string
	// Has unexported fields.
}
    CSVOutputOptions csv output specific options

func (c CSVOutputOptions) MarshalXML(e *xml.Encoder, start xml.StartElement) error
    MarshalXML - produces the xml representation of the CSVOutputOptions struct

func (c *CSVOutputOptions) SetFieldDelimiter(val string)
    SetFieldDelimiter sets the field delimiter character in the CSV output
    options

func (c *CSVOutputOptions) SetQuoteCharacter(val string)
    SetQuoteCharacter sets the quote character in the CSV output options

func (c *CSVOutputOptions) SetQuoteEscapeCharacter(val string)
    SetQuoteEscapeCharacter sets the quote escape character in the CSV output
    options

func (c *CSVOutputOptions) SetQuoteFields(val CSVQuoteFields)
    SetQuoteFields sets the quote field parameter in the CSV output options

func (c *CSVOutputOptions) SetRecordDelimiter(val string)
    SetRecordDelimiter sets the record delimiter character in the CSV output
    options

type CSVQuoteFields string
    CSVQuoteFields - is the parameter for how CSV fields are quoted.

const (
	CSVQuoteFieldsAlways   CSVQuoteFields = "Always"
	CSVQuoteFieldsAsNeeded CSVQuoteFields = "AsNeeded"
)
    Constants for csv quote styles.

type Checksum struct {
	Type ChecksumType
	// Has unexported fields.
}
    Checksum is a type and encoded value.

func NewChecksum(t ChecksumType, b []byte) Checksum
    NewChecksum sets the checksum to the value of b, which is the raw hash
    output. If the length of c does not match t.RawByteLen, a checksum with
    ChecksumNone is returned.

func NewChecksumString(t ChecksumType, s string) Checksum
    NewChecksumString sets the checksum to the value of s, which is the base 64
    encoded raw hash output. If the length of c does not match t.RawByteLen,
    it is not added.

func (c Checksum) Encoded() string
    Encoded returns the encoded value. Returns the empty string if not set or
    valid.

func (c Checksum) IsSet() bool
    IsSet returns whether the checksum is valid and known.

func (c Checksum) Raw() []byte
    Raw returns the raw checksum value if set.

type ChecksumMode uint32
    ChecksumMode contains information about the checksum mode on the object

const (
	// ChecksumFullObjectMode Full object checksum `csumCombine(csum1, csum2...)...), csumN...)`
	ChecksumFullObjectMode ChecksumMode = 1 << iota

	// ChecksumCompositeMode Composite checksum `csum([csum1 + csum2 ... + csumN])`
	ChecksumCompositeMode

	// ChecksumUnknownMode indicates no or unknown checksum mode.
	ChecksumUnknownMode ChecksumMode = 0
)
func (c ChecksumMode) Is(t ChecksumMode) bool
    Is returns if c is all of t.

func (c ChecksumMode) Key() string
    Key returns the header key.

func (c ChecksumMode) String() string

type ChecksumType uint32
    ChecksumType contains information about the checksum type.

func (c ChecksumType) Base() ChecksumType
    Base returns the base type, without modifiers.

func (c ChecksumType) CanComposite() bool
    CanComposite will return if the checksum type can be used for composite
    multipart upload on AWS.

func (c ChecksumType) CanMergeCRC() bool
    CanMergeCRC will return if the checksum type can be used for multipart
    upload on AWS.

func (c ChecksumType) ChecksumBytes(b []byte) Checksum
    ChecksumBytes returns a checksum of the content b with type c.

func (c ChecksumType) ChecksumReader(r io.Reader) (Checksum, error)
    ChecksumReader reads all of r and returns a checksum of type c. Returns any
    error that may have occurred while reading.

func (c ChecksumType) CompositeChecksum(p []ObjectPart) (*Checksum, error)
    CompositeChecksum returns the composite checksum of all provided parts.

func (c ChecksumType) EncodeToString(b []byte) string
    EncodeToString the encoded hash value of the content provided in b.

func (c ChecksumType) FullObjectChecksum(p []ObjectPart) (*Checksum, error)
    FullObjectChecksum will return the full object checksum from provided parts.

func (c ChecksumType) FullObjectRequested() bool
    FullObjectRequested will return if the checksum type indicates full object
    checksum was requested.

func (c ChecksumType) Hasher() hash.Hash
    Hasher returns a hasher corresponding to the checksum type. Returns nil if
    no checksum.

func (c ChecksumType) Is(t ChecksumType) bool
    Is returns if c is all of t.

func (c ChecksumType) IsSet() bool
    IsSet returns whether the type is valid and known.

func (c ChecksumType) Key() string
    Key returns the header key. returns empty string if invalid or none.

func (c ChecksumType) KeyCapitalized() string
    KeyCapitalized returns the capitalized key as used in HTTP headers.

func (c ChecksumType) RawByteLen() int
    RawByteLen returns the size of the un-encoded checksum.

func (c *ChecksumType) SetDefault(t ChecksumType)
    SetDefault will set the checksum if not already set.

func (c ChecksumType) String() string
    String returns the type as a string. Empty string for unset and "<invalid>"
    if not valid.

type Client struct {
	// Has unexported fields.
}
    Client implements Amazon S3 compatible methods.

func New(endpoint string, opts *Options) (*Client, error)
    New - instantiate minio client with options

func (c *Client) AppendObject(ctx context.Context, bucketName, objectName string, reader io.Reader, objectSize int64,
	opts AppendObjectOptions,
) (info UploadInfo, err error)
    AppendObject - S3 Express Zone
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/directory-buckets-objects-append.html
    Note that appending on a server without append support may overwrite the
    object.

func (c *Client) BucketExists(ctx context.Context, bucketName string) (bool, error)
    BucketExists verifies if bucket exists and you have permission to access it.
    Allows for a Context to control cancellations and timeouts.

func (c *Client) CancelBucketReplicationResync(ctx context.Context, bucketName string, tgtArn string) (id string, err error)
    CancelBucketReplicationResync cancels an in-progress replication resync
    operation.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - tgtArn: ARN of the replication target (empty string for all targets)

    Returns the ID of the canceled resync operation or an error if the operation
    fails.

func (c *Client) CheckBucketReplication(ctx context.Context, bucketName string) (err error)
    CheckBucketReplication validates whether replication is properly configured
    for a bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns nil if replication is valid, or an error describing the validation
    failure.

func (c *Client) ComposeObject(ctx context.Context, dst CopyDestOptions, srcs ...CopySrcOptions) (UploadInfo, error)
    ComposeObject - creates an object using server-side copying of existing
    objects. It takes a list of source objects (with optional offsets) and
    concatenates them into a new object using only server-side copying
    operations. Optionally takes progress reader hook for applications to look
    at current progress.

func (c *Client) CopyObject(ctx context.Context, dst CopyDestOptions, src CopySrcOptions) (UploadInfo, error)
    CopyObject - copy a source object into a new object

func (c *Client) CreateSession(ctx context.Context, bucketName string, sessionMode SessionMode) (cred credentials.Value, err error)
    CreateSession -
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_CreateSession.html
    the returning credentials may be cached depending on the expiration of the
    original credential, credentials will get renewed 10 secs earlier than when
    its gonna expire allowing for some leeway in the renewal process.

func (c *Client) CredContext() *credentials.CredContext
    CredContext returns the context for fetching credentials

func (c *Client) DeleteBucketInventoryConfiguration(ctx context.Context, bucket, id string) error
    DeleteBucketInventoryConfiguration deletes an inventory configuration from a
    bucket. This is a MinIO-specific API and is not compatible with AWS S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - id: Unique identifier for the inventory configuration to delete

    Returns an error if the operation fails or if the configuration doesn't
    exist.

func (c *Client) EnableVersioning(ctx context.Context, bucketName string) error
    EnableVersioning - enable object versioning in given bucket.

func (c *Client) EndpointURL() *url.URL
    EndpointURL returns the URL of the S3-compatible endpoint that this client
    connects to.

    Returns a copy of the endpoint URL to prevent modification of internal
    state.

func (c *Client) FGetObject(ctx context.Context, bucketName, objectName, filePath string, opts GetObjectOptions) error
    FGetObject - download contents of an object to a local file. The options can
    be used to specify the GET request further.

func (c *Client) FPutObject(ctx context.Context, bucketName, objectName, filePath string, opts PutObjectOptions) (info UploadInfo, err error)
    FPutObject - Create an object in a bucket, with contents from file at
    filePath. Allows request cancellation.

func (c *Client) GenerateInventoryConfigYAML(ctx context.Context, bucket, id string) (string, error)
    GenerateInventoryConfigYAML generates a YAML template for an inventory
    configuration. This is a MinIO-specific API and is not compatible with AWS
    S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - id: Unique identifier for the inventory configuration

    Returns a YAML template string that can be customized and used with
    PutBucketInventoryConfiguration.

func (c *Client) GetBucketCors(ctx context.Context, bucketName string) (*cors.Config, error)
    GetBucketCors retrieves the Cross-Origin Resource Sharing (CORS)
    configuration from the bucket. If no CORS configuration exists, returns nil
    with no error.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the CORS configuration or an error if the operation fails.

func (c *Client) GetBucketEncryption(ctx context.Context, bucketName string) (*sse.Configuration, error)
    GetBucketEncryption retrieves the default encryption configuration from a
    bucket. It uses the provided context to control cancellations and timeouts.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the bucket's encryption configuration or an error if the operation
    fails.

func (c *Client) GetBucketInventoryConfiguration(ctx context.Context, bucket, id string) (*InventoryConfiguration, error)
    GetBucketInventoryConfiguration retrieves the inventory configuration for a
    bucket. This is a MinIO-specific API and is not compatible with AWS S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - id: Unique identifier for the inventory configuration

    Returns the inventory configuration or an error if the operation fails or if
    the configuration doesn't exist.

func (c *Client) GetBucketInventoryJobStatus(ctx context.Context, bucket, id string) (*InventoryJobStatus, error)
    GetBucketInventoryJobStatus retrieves the status of an inventory job for a
    bucket. This is a MinIO-specific API and is not compatible with AWS S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - id: Unique identifier for the inventory job

    Returns the inventory job status including execution state, progress,
    and error information, or an error if the operation fails.

func (c *Client) GetBucketLifecycle(ctx context.Context, bucketName string) (*lifecycle.Configuration, error)
    GetBucketLifecycle fetch bucket lifecycle configuration

func (c *Client) GetBucketLifecycleWithInfo(ctx context.Context, bucketName string) (*lifecycle.Configuration, time.Time, error)
    GetBucketLifecycleWithInfo fetch bucket lifecycle configuration along with
    when it was last updated

func (c *Client) GetBucketLocation(ctx context.Context, bucketName string) (string, error)
    GetBucketLocation - get location for the bucket name from location cache,
    if not fetch freshly by making a new request.

func (c *Client) GetBucketNotification(ctx context.Context, bucketName string) (bucketNotification notification.Configuration, err error)
    GetBucketNotification returns current bucket notification configuration

func (c *Client) GetBucketObjectLockConfig(ctx context.Context, bucketName string) (mode *RetentionMode, validity *uint, unit *ValidityUnit, err error)
    GetBucketObjectLockConfig gets object lock configuration of given bucket.

func (c *Client) GetBucketPolicy(ctx context.Context, bucketName string) (string, error)
    GetBucketPolicy retrieves the access permissions policy for the bucket.
    If no bucket policy exists, returns an empty string with no error.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the policy as a JSON string or an error if the operation fails.

func (c *Client) GetBucketQOS(ctx context.Context, bucket string) (*QOSConfig, error)
    GetBucketQOS retrieves the Quality of Service (QoS) configuration for the
    bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket

    Returns the QoS configuration or an error if the operation fails.

func (c *Client) GetBucketQOSMetrics(ctx context.Context, bucketName, nodeName string) (qs []QOSNodeStats, err error)
    GetBucketQOSMetrics retrieves Quality of Service (QoS) metrics for a bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - nodeName: Name of the node (empty string for all nodes)

    Returns QoS metrics per node or an error if the operation fails.

func (c *Client) GetBucketReplication(ctx context.Context, bucketName string) (cfg replication.Config, err error)
    GetBucketReplication retrieves the bucket replication configuration. If no
    replication configuration is found, returns an empty config with nil error.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the replication configuration or an error if the operation fails.

func (c *Client) GetBucketReplicationMetrics(ctx context.Context, bucketName string) (s replication.Metrics, err error)
    GetBucketReplicationMetrics retrieves bucket replication status metrics.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the replication metrics or an error if the operation fails.

func (c *Client) GetBucketReplicationMetricsV2(ctx context.Context, bucketName string) (s replication.MetricsV2, err error)
    GetBucketReplicationMetricsV2 retrieves bucket replication status metrics
    using the V2 API.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the V2 replication metrics or an error if the operation fails.

func (c *Client) GetBucketReplicationResyncStatus(ctx context.Context, bucketName, arn string) (rinfo replication.ResyncTargetsInfo, err error)
    GetBucketReplicationResyncStatus retrieves the status of a replication
    resync operation.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - arn: ARN of the replication target (empty string for all targets)

    Returns resync status information or an error if the operation fails.

func (c *Client) GetBucketTagging(ctx context.Context, bucketName string) (*tags.Tags, error)
    GetBucketTagging fetches the tagging configuration for a bucket. It uses the
    provided context to control cancellations and timeouts.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns the bucket's tags or an error if the operation fails.

func (c *Client) GetBucketVersioning(ctx context.Context, bucketName string) (BucketVersioningConfiguration, error)
    GetBucketVersioning gets the versioning configuration on an existing bucket
    with a context to control cancellations and timeouts.

func (c *Client) GetCreds() (credentials.Value, error)
    GetCreds returns the access creds for the client

func (c *Client) GetObject(ctx context.Context, bucketName, objectName string, opts GetObjectOptions) (*Object, error)
    GetObject wrapper function that accepts a request context

func (c *Client) GetObjectACL(ctx context.Context, bucketName, objectName string) (*ObjectInfo, error)
    GetObjectACL get object ACLs

func (c *Client) GetObjectAttributes(ctx context.Context, bucketName, objectName string, opts ObjectAttributesOptions) (*ObjectAttributes, error)
    GetObjectAttributes API combines HeadObject and ListParts. More details on
    usage can be found in the documentation for ObjectAttributesOptions{}

func (c *Client) GetObjectLegalHold(ctx context.Context, bucketName, objectName string, opts GetObjectLegalHoldOptions) (status *LegalHoldStatus, err error)
    GetObjectLegalHold retrieves the legal hold status for an object and
    specific version.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including optional VersionID to target a specific version

    Returns the legal hold status (LegalHoldEnabled or LegalHoldDisabled) or an
    error if the operation fails.

func (c *Client) GetObjectLockConfig(ctx context.Context, bucketName string) (objectLock string, mode *RetentionMode, validity *uint, unit *ValidityUnit, err error)
    GetObjectLockConfig gets object lock configuration of given bucket.

func (c *Client) GetObjectRetention(ctx context.Context, bucketName, objectName, versionID string) (mode *RetentionMode, retainUntilDate *time.Time, err error)
    GetObjectRetention retrieves the retention configuration for an object and
    specific version.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - versionID: Optional version ID to target a specific version (empty
        string for current version)

    Returns the retention mode (GOVERNANCE or COMPLIANCE), retain-until date,
    and any error.

func (c *Client) GetObjectTagging(ctx context.Context, bucketName, objectName string, opts GetObjectTaggingOptions) (*tags.Tags, error)
    GetObjectTagging retrieves object tag(s) with options to target a specific
    object version in a versioned bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including VersionID to target a specific version

    Returns the object's tags or an error if the operation fails.

func (c *Client) HealthCheck(hcDuration time.Duration) (context.CancelFunc, error)
    HealthCheck starts a healthcheck to see if endpoint is up. Returns a context
    cancellation function, to stop the health check, and an error if health
    check is already started.

func (c *Client) IsOffline() bool
    IsOffline returns true if healthcheck enabled and client is offline If
    HealthCheck function has not been called this will always return false.

func (c *Client) IsOnline() bool
    IsOnline returns true if healthcheck enabled and client is online.
    If HealthCheck function has not been called this will always return true.

func (c *Client) ListBucketInventoryConfigurations(ctx context.Context, bucket, continuationToken string) (lr *InventoryListResult, err error)
    ListBucketInventoryConfigurations lists up to 100 inventory configurations
    for a bucket. This is a MinIO-specific API and is not compatible with AWS
    S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - continuationToken: Token for pagination (empty string for first request)

    Returns a list result with configurations and a continuation token for the
    next page, or an error.

func (c *Client) ListBucketInventoryConfigurationsIterator(ctx context.Context, bucket string) iter.Seq2[InventoryConfiguration, error]
    ListBucketInventoryConfigurationsIterator returns an iterator that lists all
    inventory configurations for a bucket. This is a MinIO-specific API and is
    not compatible with AWS S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket

    Returns an iterator that yields InventoryConfiguration values and
    errors. The iterator automatically handles pagination and fetches all
    configurations.

func (c *Client) ListBuckets(ctx context.Context) ([]BucketInfo, error)
    ListBuckets list all buckets owned by this authenticated user.

    This call requires explicit authentication, no anonymous requests are
    allowed for listing buckets.

        api := client.New(....)
        for message := range api.ListBuckets(context.Background()) {
            fmt.Println(message)
        }

func (c *Client) ListDirectoryBuckets(ctx context.Context) (iter.Seq2[BucketInfo, error], error)
    ListDirectoryBuckets list all buckets owned by this authenticated user.

    This call requires explicit authentication, no anonymous requests are
    allowed for listing buckets.

    api := client.New(....) dirBuckets, err :=
    api.ListDirectoryBuckets(context.Background())

func (c *Client) ListIncompleteUploads(ctx context.Context, bucketName, objectPrefix string, recursive bool) <-chan ObjectMultipartInfo
    ListIncompleteUploads - List incompletely uploaded multipart objects.

    ListIncompleteUploads lists all incompleted objects matching the
    objectPrefix from the specified bucket. If recursion is enabled it would
    list all subdirectories and all its contents.

    Your input parameters are just bucketName, objectPrefix, recursive. If you
    enable recursive as 'true' this function will return back all the multipart
    objects in a given bucket name.

        api := client.New(....)
        // Recurively list all objects in 'mytestbucket'
        recursive := true
        for message := range api.ListIncompleteUploads(context.Background(), "mytestbucket", "starthere", recursive) {
            fmt.Println(message)
        }

func (c *Client) ListObjects(ctx context.Context, bucketName string, opts ListObjectsOptions) <-chan ObjectInfo
    ListObjects returns objects list after evaluating the passed options.

        api := client.New(....)
        for object := range api.ListObjects(ctx, "mytestbucket", minio.ListObjectsOptions{Prefix: "starthere", Recursive:true}) {
            fmt.Println(object)
        }

    If caller cancels the context, then the last entry on the 'chan ObjectInfo'
    will be the context.Error() caller must drain the channel entirely and wait
    until channel is closed before proceeding, without waiting on the channel to
    be closed completely you might leak goroutines.

func (c *Client) ListObjectsIter(ctx context.Context, bucketName string, opts ListObjectsOptions) iter.Seq[ObjectInfo]
    ListObjectsIter returns object list as a iterator sequence. caller must
    cancel the context if they are not interested in iterating further, if no
    more entries the iterator will automatically stop.

        api := client.New(....)
        for object := range api.ListObjectsIter(ctx, "mytestbucket", minio.ListObjectsOptions{Prefix: "starthere", Recursive:true}) {
            if object.Err != nil {
                // handle the errors.
            }
            fmt.Println(object)
        }

    Canceling the context the iterator will stop, if you wish to discard the
    yielding make sure to cancel the passed context without that you might leak
    coroutines

func (c *Client) ListenBucketNotification(ctx context.Context, bucketName, prefix, suffix string, events []string) <-chan notification.Info
    ListenBucketNotification listen for bucket events, this is a MinIO specific
    API

func (c *Client) ListenNotification(ctx context.Context, prefix, suffix string, events []string) <-chan notification.Info
    ListenNotification listen for all events, this is a MinIO specific API

func (c *Client) MakeBucket(ctx context.Context, bucketName string, opts MakeBucketOptions) (err error)
    MakeBucket creates a new bucket with bucketName with a context to control
    cancellations and timeouts.

    Location is an optional argument, by default all buckets are created in US
    Standard Region.

    For Amazon S3 for more supported regions -
    http://docs.aws.amazon.com/general/latest/gr/rande.html
    For Google Cloud Storage for more supported regions -
    https://cloud.google.com/storage/docs/bucket-locations

func (c *Client) Presign(ctx context.Context, method, bucketName, objectName string, expires time.Duration, reqParams url.Values) (u *url.URL, err error)
    Presign - returns a presigned URL for any http method of your choice along
    with custom request params and extra signed headers. URL can have a maximum
    expiry of upto 7days or a minimum of 1sec.

func (c *Client) PresignHeader(ctx context.Context, method, bucketName, objectName string, expires time.Duration, reqParams url.Values, extraHeaders http.Header) (u *url.URL, err error)
    PresignHeader - similar to Presign() but allows including HTTP headers
    that will be used to build the signature. The request using the resulting
    URL will need to have the exact same headers to be added for signature
    validation to pass.

    FIXME: The extra header parameter should be included in Presign() in the
    next major version bump, and this function should then be deprecated.

func (c *Client) PresignedGetObject(ctx context.Context, bucketName, objectName string, expires time.Duration, reqParams url.Values) (u *url.URL, err error)
    PresignedGetObject - Returns a presigned URL to access an object data
    without credentials. URL can have a maximum expiry of upto 7days or a
    minimum of 1sec. Additionally you can override a set of response headers
    using the query parameters.

func (c *Client) PresignedHeadObject(ctx context.Context, bucketName, objectName string, expires time.Duration, reqParams url.Values) (u *url.URL, err error)
    PresignedHeadObject - Returns a presigned URL to access object metadata
    without credentials. URL can have a maximum expiry of upto 7days or a
    minimum of 1sec. Additionally you can override a set of response headers
    using the query parameters.

func (c *Client) PresignedPostPolicy(ctx context.Context, p *PostPolicy) (u *url.URL, formData map[string]string, err error)
    PresignedPostPolicy - Returns POST urlString, form data to upload an object.

func (c *Client) PresignedPutObject(ctx context.Context, bucketName, objectName string, expires time.Duration) (u *url.URL, err error)
    PresignedPutObject - Returns a presigned URL to upload an object without
    credentials. URL can have a maximum expiry of upto 7days or a minimum of
    1sec.

func (c *Client) PromptObject(ctx context.Context, bucketName, objectName, prompt string, opts PromptObjectOptions) (io.ReadCloser, error)
    PromptObject performs language model inference with the prompt and
    referenced object as context. Inference is performed using a Lambda handler
    that can process the prompt and object. Currently, this functionality is
    limited to certain MinIO servers.

func (c *Client) PutBucketInventoryConfiguration(ctx context.Context, bucket string, id string, yamlDef string, _ ...InventoryPutConfigOption) error
    PutBucketInventoryConfiguration creates or updates an inventory
    configuration for a bucket. This is a MinIO-specific API and is not
    compatible with AWS S3.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - id: Unique identifier for the inventory configuration
      - yamlDef: YAML definition of the inventory configuration

    Returns an error if the operation fails, or if bucket name, id, or yamlDef
    is empty.

func (c *Client) PutObject(ctx context.Context, bucketName, objectName string, reader io.Reader, size int64,
	opts PutObjectOptions,
) (info UploadInfo, err error)
    PutObject creates an object in a bucket.

    You must have WRITE permissions on a bucket to create an object.

      - For size smaller than 16MiB PutObject automatically does a single atomic
        PUT operation.

      - For size larger than 16MiB PutObject automatically does a multipart
        upload operation.

      - For size input as -1 PutObject does a multipart Put operation until
        input stream reaches EOF. Maximum object size that can be uploaded
        through this operation will be 5TiB by default. For larger objects (up
        to ~48.83TiB), set PutObjectOptions.PartSize to control memory usage and
        enable uploads beyond 5TiB.

        WARNING: Passing down '-1' will use memory and these cannot be reused
        for best outcomes for PutObject(), pass the size always.

    NOTE: Upon errors during upload multipart operation is entirely aborted.

func (c *Client) PutObjectFanOut(ctx context.Context, bucket string, fanOutData io.Reader, fanOutReq PutObjectFanOutRequest) ([]PutObjectFanOutResponse, error)
    PutObjectFanOut - is a variant of PutObject instead of writing a single
    object from a single stream multiple objects are written, defined via a list
    of PutObjectFanOutRequests. Each entry in PutObjectFanOutRequest carries
    an object keyname and its relevant metadata if any. `Key` is mandatory,
    rest of the other options in PutObjectFanOutRequest are optional.

func (c *Client) PutObjectLegalHold(ctx context.Context, bucketName, objectName string, opts PutObjectLegalHoldOptions) error
    PutObjectLegalHold sets the legal hold status for an object and specific
    version. Legal hold prevents an object version from being overwritten or
    deleted, regardless of retention settings.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including Status (LegalHoldEnabled or LegalHoldDisabled)
        and optional VersionID

    Returns an error if the operation fails or if the status is invalid.

func (c *Client) PutObjectRetention(ctx context.Context, bucketName, objectName string, opts PutObjectRetentionOptions) error
    PutObjectRetention sets the retention configuration for an object and
    specific version. Object retention prevents an object version from being
    deleted or overwritten for a specified period.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including Mode (GOVERNANCE or COMPLIANCE),
        RetainUntilDate, optional VersionID, and GovernanceBypass

    Returns an error if the operation fails or if the retention settings are
    invalid.

func (c *Client) PutObjectTagging(ctx context.Context, bucketName, objectName string, otags *tags.Tags, opts PutObjectTaggingOptions) error
    PutObjectTagging replaces or creates object tag(s) and can target a specific
    object version in a versioned bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - otags: Tags to apply to the object
      - opts: Options including VersionID to target a specific version

    Returns an error if the operation fails.

func (c *Client) PutObjectsSnowball(ctx context.Context, bucketName string, opts SnowballOptions, objs <-chan SnowballObject) (err error)
    PutObjectsSnowball will put multiple objects with a single put call.
    A (compressed) TAR file will be created which will contain multiple objects.
    The key for each object will be used for the destination in the specified
    bucket. Total size should be < 5TB. This function blocks until 'objs' is
    closed and the content has been uploaded.

func (c *Client) RemoveAllBucketNotification(ctx context.Context, bucketName string) error
    RemoveAllBucketNotification - Remove bucket notification clears all
    previously specified config

func (c *Client) RemoveBucket(ctx context.Context, bucketName string) error
    RemoveBucket deletes the bucket name.

        All objects (including all object versions and delete markers).
        in the bucket must be deleted before successfully attempting this request.

func (c *Client) RemoveBucketEncryption(ctx context.Context, bucketName string) error
    RemoveBucketEncryption removes the default encryption configuration from a
    bucket. After removal, the bucket will no longer apply default encryption
    to new objects. It uses the provided context to control cancellations and
    timeouts.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns an error if the operation fails.

func (c *Client) RemoveBucketReplication(ctx context.Context, bucketName string) error
    RemoveBucketReplication removes the replication configuration from an
    existing bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns an error if the operation fails.

func (c *Client) RemoveBucketTagging(ctx context.Context, bucketName string) error
    RemoveBucketTagging removes the tagging configuration from a bucket.
    It uses the provided context to control cancellations and timeouts.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket

    Returns an error if the operation fails.

func (c *Client) RemoveBucketWithOptions(ctx context.Context, bucketName string, opts RemoveBucketOptions) error
    RemoveBucketWithOptions deletes the bucket name.

    All objects (including all object versions and delete markers) in the bucket
    will be deleted forcibly if bucket options set ForceDelete to 'true'.

func (c *Client) RemoveIncompleteUpload(ctx context.Context, bucketName, objectName string) error
    RemoveIncompleteUpload aborts an partially uploaded object.

func (c *Client) RemoveObject(ctx context.Context, bucketName, objectName string, opts RemoveObjectOptions) error
    RemoveObject removes an object from a bucket.

func (c *Client) RemoveObjectTagging(ctx context.Context, bucketName, objectName string, opts RemoveObjectTaggingOptions) error
    RemoveObjectTagging removes object tag(s) with options to target a specific
    object version in a versioned bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including VersionID to target a specific version

    Returns an error if the operation fails.

func (c *Client) RemoveObjects(ctx context.Context, bucketName string, objectsCh <-chan ObjectInfo, opts RemoveObjectsOptions) <-chan RemoveObjectError
    RemoveObjects removes multiple objects from a bucket while it is possible to
    specify objects versions which are received from objectsCh. Remove failures
    are sent back via error channel.

func (c *Client) RemoveObjectsWithIter(ctx context.Context, bucketName string, objectsIter iter.Seq[ObjectInfo], opts RemoveObjectsOptions) (iter.Seq[RemoveObjectResult], error)
    RemoveObjectsWithIter bulk deletes multiple objects from a bucket. Objects
    (with optional versions) to be removed must be provided with an iterator.
    Objects are removed asynchronously and results must be consumed. If the
    returned result iterator is stopped, the context is canceled, or a remote
    call failed, the provided iterator will no longer accept more objects.

func (c *Client) RemoveObjectsWithResult(ctx context.Context, bucketName string, objectsCh <-chan ObjectInfo, opts RemoveObjectsOptions) <-chan RemoveObjectResult
    RemoveObjectsWithResult removes multiple objects from a bucket while it is
    possible to specify objects versions which are received from objectsCh.
    Remove results, successes and failures are sent back via RemoveObjectResult
    channel

func (c *Client) ResetBucketReplication(ctx context.Context, bucketName string, olderThan time.Duration) (rID string, err error)
    ResetBucketReplication initiates replication of previously replicated
    objects. This requires ExistingObjectReplication to be enabled in the
    replication configuration.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - olderThan: Only replicate objects older than this duration (0 for all
        objects)

    Returns a reset ID that can be used to track the operation, or an error if
    the operation fails.

func (c *Client) ResetBucketReplicationOnTarget(ctx context.Context, bucketName string, olderThan time.Duration, tgtArn string) (replication.ResyncTargetsInfo, error)
    ResetBucketReplicationOnTarget initiates replication of
    previously replicated objects to a specific target. This requires
    ExistingObjectReplication to be enabled in the replication configuration.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - olderThan: Only replicate objects older than this duration (0 for all
        objects)
      - tgtArn: ARN of the target to reset replication for

    Returns resync target information or an error if the operation fails.

func (c *Client) RestoreObject(ctx context.Context, bucketName, objectName, versionID string, req RestoreRequest) error
    RestoreObject is a implementation of
    https://docs.aws.amazon.com/AmazonS3/latest/API/API_RestoreObject.html AWS
    S3 API

func (c *Client) SelectObjectContent(ctx context.Context, bucketName, objectName string, opts SelectObjectOptions) (*SelectResults, error)
    SelectObjectContent is a implementation of
    http://docs.aws.amazon.com/AmazonS3/latest/API/RESTObjectSELECTContent.html
    AWS S3 API.

func (c *Client) SetAppInfo(appName, appVersion string)
    SetAppInfo adds custom application name and version to the User-Agent header
    for all requests. This helps identify your application in server logs and
    metrics.

    Parameters:
      - appName: Name of the application
      - appVersion: Version of the application

    Both parameters must be non-empty for the custom User-Agent to be set.

func (c *Client) SetBucketCors(ctx context.Context, bucketName string, corsConfig *cors.Config) error
    SetBucketCors sets the Cross-Origin Resource Sharing (CORS) configuration
    for the bucket. If corsConfig is nil, the existing CORS configuration will
    be removed.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - corsConfig: CORS configuration to apply (nil to remove existing
        configuration)

    Returns an error if the operation fails.

func (c *Client) SetBucketEncryption(ctx context.Context, bucketName string, config *sse.Configuration) error
    SetBucketEncryption sets the default encryption configuration on an existing
    bucket. The encryption configuration specifies the default encryption
    behavior for objects uploaded to the bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - config: Server-side encryption configuration to apply

    Returns an error if the operation fails or if config is nil.

func (c *Client) SetBucketLifecycle(ctx context.Context, bucketName string, config *lifecycle.Configuration) error
    SetBucketLifecycle set the lifecycle on an existing bucket.

func (c *Client) SetBucketNotification(ctx context.Context, bucketName string, config notification.Configuration) error
    SetBucketNotification saves a new bucket notification with a context to
    control cancellations and timeouts.

func (c *Client) SetBucketObjectLockConfig(ctx context.Context, bucketName string, mode *RetentionMode, validity *uint, unit *ValidityUnit) error
    SetBucketObjectLockConfig sets object lock configuration in given bucket.
    mode, validity and unit are either all set or all nil.

func (c *Client) SetBucketPolicy(ctx context.Context, bucketName, policy string) error
    SetBucketPolicy sets the access permissions policy on an existing bucket.
    The policy should be a valid JSON string that conforms to the IAM policy
    format. If policy is an empty string, the existing bucket policy will be
    removed.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - policy: JSON policy string (empty string to remove existing policy)

    Returns an error if the operation fails.

func (c *Client) SetBucketQOS(ctx context.Context, bucket string, qosCfg *QOSConfig) error
    SetBucketQOS sets the Quality of Service (QoS) configuration for a bucket.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucket: Name of the bucket
      - qosCfg: QoS configuration to apply

    Returns an error if the operation fails.

func (c *Client) SetBucketReplication(ctx context.Context, bucketName string, cfg replication.Config) error
    SetBucketReplication sets the replication configuration on an existing
    bucket. If the provided configuration is empty, this method removes the
    existing replication configuration.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - cfg: Replication configuration to apply

    Returns an error if the operation fails.

func (c *Client) SetBucketTagging(ctx context.Context, bucketName string, tags *tags.Tags) error
    SetBucketTagging sets the tagging configuration for a bucket. It uses the
    provided context to control cancellations and timeouts.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - tags: Tag set to apply to the bucket

    Returns an error if the operation fails or if tags is nil.

func (c *Client) SetBucketVersioning(ctx context.Context, bucketName string, config BucketVersioningConfiguration) error
    SetBucketVersioning sets a bucket versioning configuration

func (c *Client) SetObjectLockConfig(ctx context.Context, bucketName string, mode *RetentionMode, validity *uint, unit *ValidityUnit) error
    SetObjectLockConfig sets object lock configuration in given bucket. mode,
    validity and unit are either all set or all nil.

func (c *Client) SetS3EnableDualstack(enabled bool)
    SetS3EnableDualstack turns s3 dual-stack endpoints on or off for all
    requests. The feature is only specific to S3 and is on by default.
    To read more about Amazon S3 dual-stack endpoints visit -
    https://docs.aws.amazon.com/AmazonS3/latest/userguide/dual-stack-endpoints.html

func (c *Client) SetS3TransferAccelerate(accelerateEndpoint string)
    SetS3TransferAccelerate - turns s3 accelerated endpoint on
    or off for all your requests. This feature is only specific
    to S3 for all other endpoints this function does nothing.
    To read further details on s3 transfer acceleration please vist -
    http://docs.aws.amazon.com/AmazonS3/latest/dev/transfer-acceleration.html

func (c *Client) StatObject(ctx context.Context, bucketName, objectName string, opts StatObjectOptions) (ObjectInfo, error)
    StatObject verifies if object exists, you have permission to access it and
    returns information about the object.

func (c *Client) SuspendVersioning(ctx context.Context, bucketName string) error
    SuspendVersioning - suspend object versioning in given bucket.

func (c *Client) TraceErrorsOnlyOff()
    TraceErrorsOnlyOff disables errors-only mode and traces all requests.
    To disable all tracing, call TraceOff() instead.

func (c *Client) TraceErrorsOnlyOn(outputStream io.Writer)
    TraceErrorsOnlyOn enables HTTP tracing but only for requests that result
    in errors. This is useful for debugging without the overhead of tracing all
    requests.

    Parameters:
      - outputStream: Writer where trace output will be written (defaults to
        os.Stdout if nil)

func (c *Client) TraceOff()
    TraceOff disables all HTTP tracing (both normal and errors-only modes).

func (c *Client) TraceOn(outputStream io.Writer)
    TraceOn enables HTTP request and response tracing for debugging purposes.
    All HTTP traffic will be written to the provided output stream.

    Parameters:
      - outputStream: Writer where trace output will be written (defaults to
        os.Stdout if nil)

func (c *Client) UpdateObjectEncryption(ctx context.Context, bucketName, objectName string, opts UpdateObjectEncryptionOptions) (UpdateObjectEncryptionResult, error)
    UpdateObjectEncryption changes the encryption configuration of an existing
    object in-place. The object must already be encrypted with SSE-S3 or
    SSE-KMS. SSE-C objects are not supported. This operation rotates the data
    encryption key envelope without re-reading/re-writing object data.

    Parameters:
      - ctx: Context for request cancellation and timeout
      - bucketName: Name of the bucket
      - objectName: Name of the object
      - opts: Options including KMSKeyArn (required), optional BucketKeyEnabled,
        and optional VersionID

    Returns the version ID of the updated object (if versioning is enabled) and
    an error if the operation fails.

type CommonPrefix struct {
	Prefix string
}
    CommonPrefix container for prefix response.

type CompletePart struct {
	// Part number identifies the part.
	PartNumber int
	ETag       string

	// Checksum values
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumMD5       string `xml:",omitempty"`
	ChecksumSHA512    string `xml:",omitempty"`
	ChecksumXXHash64  string `xml:"ChecksumXXHASH64,omitempty"`
	ChecksumXXHash3   string `xml:"ChecksumXXHASH3,omitempty"`
	ChecksumXXHash128 string `xml:"ChecksumXXHASH128,omitempty"`
}
    CompletePart sub container lists individual part numbers and their md5sum,
    part of completeMultipartUpload.

func (c CompletePart) Checksum(t ChecksumType) string
    Checksum will return the checksum for the given type. Will return the empty
    string if not set.

type CopyDestOptions struct {
	Bucket string // points to destination bucket
	Object string // points to destination object

	// `Encryption` is the key info for server-side-encryption with customer
	// provided key. If it is nil, no encryption is performed.
	Encryption encrypt.ServerSide

	ChecksumType ChecksumType

	// `userMeta` is the user-metadata key-value pairs to be set on the
	// destination. The keys are automatically prefixed with `x-amz-meta-`
	// if needed. If nil is passed, and if only a single source (of any
	// size) is provided in the ComposeObject call, then metadata from the
	// source is copied to the destination.
	// if no user-metadata is provided, it is copied from source
	// (when there is only one source object in the compose
	// request)
	UserMetadata map[string]string
	// UserMetadata is only set to destination if ReplaceMetadata is true
	// other value is UserMetadata is ignored and we preserve src.UserMetadata
	// NOTE: if you set this value to true and now metadata is present
	// in UserMetadata your destination object will not have any metadata
	// set.
	ReplaceMetadata bool

	// `userTags` is the user defined object tags to be set on destination.
	// This will be set only if the `replaceTags` field is set to true.
	// Otherwise this field is ignored
	UserTags    map[string]string
	ReplaceTags bool

	// Specifies whether you want to apply a Legal Hold to the copied object.
	LegalHold LegalHoldStatus

	// Object Retention related fields
	Mode               RetentionMode
	RetainUntilDate    time.Time
	Expires            time.Time
	ContentType        string
	ContentEncoding    string
	ContentDisposition string
	ContentLanguage    string
	CacheControl       string

	Size int64 // Needs to be specified if progress bar is specified.
	// Progress of the entire copy operation will be sent here.
	Progress io.Reader
	// PartSize specifies the part size for multipart copy operations.
	// If not specified, defaults to maxPartSize (5 GiB).
	PartSize uint64
}
    CopyDestOptions represents options specified by user for
    CopyObject/ComposeObject APIs

func (opts CopyDestOptions) Marshal(header http.Header)
    Marshal converts all the CopyDestOptions into their equivalent HTTP header
    representation

type CopySrcOptions struct {
	Bucket, Object       string
	VersionID            string
	MatchETag            string
	NoMatchETag          string
	MatchModifiedSince   time.Time
	MatchUnmodifiedSince time.Time
	MatchRange           bool
	Start, End           int64
	Encryption           encrypt.ServerSide
}
    CopySrcOptions represents a source object to be copied, using server-side
    copying APIs.

func (opts CopySrcOptions) Marshal(header http.Header)
    Marshal converts all the CopySrcOptions into their equivalent HTTP header
    representation

type Core struct {
	*Client
}
    Core - Inherits Client and adds new methods to expose the low level S3 APIs.

func NewCore(endpoint string, opts *Options) (*Core, error)
    NewCore - Returns new initialized a Core client, this CoreClient should be
    only used under special conditions such as need to access lower primitives
    and being able to use them to write your own wrappers.

func (c Core) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error
    AbortMultipartUpload - Abort an incomplete upload.

func (c Core) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, parts []CompletePart, opts PutObjectOptions) (UploadInfo, error)
    CompleteMultipartUpload - Concatenate uploaded parts and commit to an
    object.

func (c Core) CopyObject(ctx context.Context, sourceBucket, sourceObject, destBucket, destObject string, metadata map[string]string, srcOpts CopySrcOptions, dstOpts PutObjectOptions) (ObjectInfo, error)
    CopyObject - copies an object from source object to destination object on
    server side.

func (c Core) CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject, uploadID string,
	partID int, startOffset, length int64, metadata map[string]string,
) (p CompletePart, err error)
    CopyObjectPart - creates a part in a multipart upload by copying (a part of)
    an existing object.

func (c Core) GetBucketPolicy(ctx context.Context, bucket string) (string, error)
    GetBucketPolicy - fetches bucket access policy for a given bucket.

func (c Core) GetObject(ctx context.Context, bucketName, objectName string, opts GetObjectOptions) (io.ReadCloser, ObjectInfo, http.Header, error)
    GetObject is a lower level API implemented to support reading partial
    objects and also downloading objects with special conditions matching etag,
    modtime etc.

func (c Core) ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (result ListMultipartUploadsResult, err error)
    ListMultipartUploads - List incomplete uploads.

func (c Core) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker, maxParts int) (result ListObjectPartsResult, err error)
    ListObjectParts - List uploaded parts of an incomplete upload.x

func (c Core) ListObjects(bucket, prefix, marker, delimiter string, maxKeys int) (result ListBucketResult, err error)
    ListObjects - List all the objects at a prefix, optionally with marker and
    delimiter you can further filter the results.

func (c Core) ListObjectsV2(bucketName, objectPrefix, startAfter, continuationToken, delimiter string, maxkeys int) (ListBucketV2Result, error)
    ListObjectsV2 - Lists all the objects at a prefix, similar to ListObjects()
    but uses continuationToken instead of marker to support iteration over the
    results.

func (c Core) NewMultipartUpload(ctx context.Context, bucket, object string, opts PutObjectOptions) (uploadID string, err error)
    NewMultipartUpload - Initiates new multipart upload and returns the new
    uploadID.

func (c Core) PutBucketPolicy(ctx context.Context, bucket, bucketPolicy string) error
    PutBucketPolicy - applies a new bucket access policy for a given bucket.

func (c Core) PutObject(ctx context.Context, bucket, object string, data io.Reader, size int64, md5Base64, sha256Hex string, opts PutObjectOptions) (UploadInfo, error)
    PutObject - Upload object. Uploads using single PUT call.

func (c Core) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int,
	data io.Reader, size int64, opts PutObjectPartOptions,
) (ObjectPart, error)
    PutObjectPart - Upload an object part.

type CounterMetric struct {
	Last1m  uint64 `json:"last1m"`
	Last1hr uint64 `json:"last1hr"`
	Total   uint64 `json:"total"`
}
    CounterMetric returns stats for a counter

type Encryption struct {
	EncryptionType string
	KMSContext     string
	KMSKeyID       string `xml:"KMSKeyId"`
}
    Encryption contains the type of server-side encryption used during object
    retrieval

type ErrorResponse struct {
	XMLName    xml.Name `xml:"Error" json:"-"`
	Code       string
	Message    string
	BucketName string
	Key        string
	Resource   string
	RequestID  string `xml:"RequestId"`
	HostID     string `xml:"HostId"`

	// Region where the bucket is located. This header is returned
	// only in HEAD bucket and ListObjects response.
	Region string

	// Captures the server string returned in response header.
	Server string

	// Underlying HTTP status code for the returned error
	StatusCode int `xml:"-" json:"-"`
}
    ErrorResponse - Is the typed error returned by all API operations.
    ErrorResponse struct should be comparable since it is compared inside golang
    http API (https://github.com/golang/go/issues/29768)

func ToErrorResponse(err error) ErrorResponse
    ToErrorResponse - Returns parsed ErrorResponse struct from body and http
    headers.

    For example:

        import s3 "github.com/minio/minio-go/v7"
        ...
        ...
        reader, stat, err := s3.GetObject(...)
        if err != nil {
           resp := s3.ToErrorResponse(err)
        }
        ...

func (e ErrorResponse) Error() string
    Error - Returns S3 error string.

type ExcludedPrefix struct {
	Prefix string
}
    ExcludedPrefix - holds individual prefixes excluded from being versioned.

type GetObjectLegalHoldOptions struct {
	VersionID string
}
    GetObjectLegalHoldOptions represents options specified by user for
    GetObjectLegalHold call

type GetObjectOptions struct {
	ServerSideEncryption encrypt.ServerSide
	VersionID            string
	PartNumber           int

	// Include any checksums, if object was uploaded with checksum.
	// For multipart objects this is a checksum of part checksums.
	// https://docs.aws.amazon.com/AmazonS3/latest/userguide/checking-object-integrity.html
	Checksum bool

	// To be not used by external applications
	Internal AdvancedGetOptions
	// Has unexported fields.
}
    GetObjectOptions are used to specify additional headers or options during
    GET requests.

func (o *GetObjectOptions) AddReqParam(key, value string)
    AddReqParam - add request query string parameter supported key: see
    supportedQueryValues and allowedCustomQueryPrefix. If an unsupported key is
    passed in, it will be ignored and nothing will be done.

func (o GetObjectOptions) Header() http.Header
    Header returns the http.Header representation of the GET options.

func (o *GetObjectOptions) Set(key, value string)
    Set adds a key value pair to the options. The key-value pair will be part of
    the HTTP GET request headers.

func (o *GetObjectOptions) SetMatchETag(etag string) error
    SetMatchETag - set match etag.

func (o *GetObjectOptions) SetMatchETagExcept(etag string) error
    SetMatchETagExcept - set match etag except.

func (o *GetObjectOptions) SetModified(modTime time.Time) error
    SetModified - set modified time since.

func (o *GetObjectOptions) SetRange(start, end int64) error
    SetRange - set the start and end offset of the object to be read. See
    https://tools.ietf.org/html/rfc7233#section-3.1 for reference.

func (o *GetObjectOptions) SetReqParam(key, value string)
    SetReqParam - set request query string parameter supported key: see
    supportedQueryValues and allowedCustomQueryPrefix. If an unsupported key is
    passed in, it will be ignored and nothing will be done.

func (o *GetObjectOptions) SetUnmodified(modTime time.Time) error
    SetUnmodified - set unmodified time since.

type GetObjectTaggingOptions struct {
	VersionID string
	Internal  AdvancedObjectTaggingOptions
}
    GetObjectTaggingOptions holds the object version ID to fetch the tagging
    key/value pairs

type GlacierJobParameters struct {
	Tier TierType
}
    GlacierJobParameters represents the retrieval tier parameter

type Grant struct {
	XMLName    xml.Name `xml:"Grant"`
	Grantee    Grantee
	Permission string `xml:"Permission"`
}
    Grant holds grant information

type Grantee struct {
	XMLName     xml.Name `xml:"Grantee"`
	ID          string   `xml:"ID"`
	DisplayName string   `xml:"DisplayName"`
	URI         string   `xml:"URI"`
}
    Grantee represents the person being granted permissions.

type InventoryConfiguration struct {
	Bucket  string `json:"bucket"`
	ID      string `json:"id"`
	User    string `json:"user"`
	YamlDef string `json:"yamlDef,omitempty"`
}
    InventoryConfiguration represents the inventory configuration

type InventoryJobStatus struct {
	Bucket            string    `json:"bucket"`
	ID                string    `json:"id"`
	User              string    `json:"user"`
	AccessKey         string    `json:"accessKey"`
	Schedule          string    `json:"schedule"`
	State             string    `json:"state"`
	NextScheduledTime time.Time `json:"nextScheduledTime,omitempty"`
	StartTime         time.Time `json:"startTime,omitempty"`
	EndTime           time.Time `json:"endTime,omitempty"`
	LastUpdate        time.Time `json:"lastUpdate,omitempty"`
	Scanned           string    `json:"scanned,omitempty"`
	Matched           string    `json:"matched,omitempty"`
	ScannedCount      uint64    `json:"scannedCount,omitempty"`
	MatchedCount      uint64    `json:"matchedCount,omitempty"`
	RecordsWritten    uint64    `json:"recordsWritten,omitempty"`
	OutputFilesCount  uint64    `json:"outputFilesCount,omitempty"`
	ExecutionTime     string    `json:"executionTime,omitempty"`
	NumStarts         uint64    `json:"numStarts,omitempty"`
	NumErrors         uint64    `json:"numErrors,omitempty"`
	NumLockLosses     uint64    `json:"numLockLosses,omitempty"`
	ManifestPath      string    `json:"manifestPath,omitempty"`
	RetryAttempts     uint64    `json:"retryAttempts,omitempty"`
	LastFailTime      time.Time `json:"lastFailTime,omitempty"`
	LastFailErrors    []string  `json:"lastFailErrors,omitempty"`
}
    InventoryJobStatus represents the status of an inventory job.

type InventoryListResult struct {
	Items                 []InventoryConfiguration `json:"items"`
	NextContinuationToken string                   `json:"nextContinuationToken,omitempty"`
}
    InventoryListResult represents the result of listing inventory
    configurations.

type InventoryPutConfigOption func(*inventoryPutConfigOpts)
    InventoryPutConfigOption is to allow for functional options for
    PutBucketInventoryConfiguration. It may be used in the future to customize
    the PutBucketInventoryConfiguration request, but currently does not do
    anything.

type JSONInputOptions struct {
	Type JSONType
	// Has unexported fields.
}
    JSONInputOptions json input specific options

func (j JSONInputOptions) MarshalXML(e *xml.Encoder, start xml.StartElement) error
    MarshalXML - produces the xml representation of the JSONInputOptions struct

func (j *JSONInputOptions) SetType(typ JSONType)
    SetType sets the JSON type in the JSON input options

type JSONOutputOptions struct {
	RecordDelimiter string
	// Has unexported fields.
}
    JSONOutputOptions - json output specific options

func (j JSONOutputOptions) MarshalXML(e *xml.Encoder, start xml.StartElement) error
    MarshalXML - produces the xml representation of the JSONOutputOptions struct

func (j *JSONOutputOptions) SetRecordDelimiter(val string)
    SetRecordDelimiter sets the record delimiter in the JSON output options

type JSONType string
    JSONType determines json input serialization type.

const (
	JSONDocumentType JSONType = "DOCUMENT"
	JSONLinesType    JSONType = "LINES"
)
    Constants for JSONTypes.

type LegalHoldStatus string
    LegalHoldStatus - object legal hold status.

const (
	// LegalHoldEnabled indicates legal hold is enabled
	LegalHoldEnabled LegalHoldStatus = "ON"

	// LegalHoldDisabled indicates legal hold is disabled
	LegalHoldDisabled LegalHoldStatus = "OFF"
)
func (r LegalHoldStatus) IsValid() bool
    IsValid - check whether this legal hold status is valid or not.

func (r LegalHoldStatus) String() string

type ListBucketResult struct {
	// A response can contain CommonPrefixes only if you have
	// specified a delimiter.
	CommonPrefixes []CommonPrefix
	// Metadata about each object returned.
	Contents  []ObjectInfo
	Delimiter string

	// Encoding type used to encode object keys in the response.
	EncodingType string

	// A flag that indicates whether or not ListObjects returned all of the results
	// that satisfied the search criteria.
	IsTruncated bool
	Marker      string
	MaxKeys     int64
	Name        string

	// When response is truncated (the IsTruncated element value in
	// the response is true), you can use the key name in this field
	// as marker in the subsequent request to get next set of objects.
	// Object storage lists objects in alphabetical order Note: This
	// element is returned only if you have delimiter request
	// parameter specified. If response does not include the NextMaker
	// and it is truncated, you can use the value of the last Key in
	// the response as the marker in the subsequent request to get the
	// next set of object keys.
	NextMarker string
	Prefix     string
}
    ListBucketResult container for listObjects response.

type ListBucketV2Result struct {
	// A response can contain CommonPrefixes only if you have
	// specified a delimiter.
	CommonPrefixes []CommonPrefix
	// Metadata about each object returned.
	Contents  []ObjectInfo
	Delimiter string

	// Encoding type used to encode object keys in the response.
	EncodingType string

	// A flag that indicates whether or not ListObjects returned all of the results
	// that satisfied the search criteria.
	IsTruncated bool
	MaxKeys     int64
	Name        string

	// Hold the token that will be sent in the next request to fetch the next group of keys
	NextContinuationToken string

	ContinuationToken string
	Prefix            string

	// FetchOwner and StartAfter are currently not used
	FetchOwner string
	StartAfter string
}
    ListBucketV2Result container for listObjects response version 2.

type ListMultipartUploadsResult struct {
	Bucket             string
	KeyMarker          string
	UploadIDMarker     string `xml:"UploadIdMarker"`
	NextKeyMarker      string
	NextUploadIDMarker string `xml:"NextUploadIdMarker"`
	EncodingType       string
	MaxUploads         int64
	IsTruncated        bool
	Uploads            []ObjectMultipartInfo `xml:"Upload"`
	Prefix             string
	Delimiter          string
	// A response can contain CommonPrefixes only if you specify a delimiter.
	CommonPrefixes []CommonPrefix
}
    ListMultipartUploadsResult container for ListMultipartUploads response

type ListObjectPartsResult struct {
	Bucket   string
	Key      string
	UploadID string `xml:"UploadId"`

	Initiator initiator
	Owner     owner

	StorageClass         string
	PartNumberMarker     int
	NextPartNumberMarker int
	MaxParts             int

	// ChecksumAlgorithm will be CRC32, CRC32C, etc.
	ChecksumAlgorithm string

	// ChecksumType is FULL_OBJECT or COMPOSITE (assume COMPOSITE when unset)
	ChecksumType string

	// Indicates whether the returned list of parts is truncated.
	IsTruncated bool
	ObjectParts []ObjectPart `xml:"Part"`

	EncodingType string
}
    ListObjectPartsResult container for ListObjectParts response.

type ListObjectsOptions struct {
	// ReverseVersions - reverse the order of the object versions
	ReverseVersions bool
	// Include objects versions in the listing
	WithVersions bool
	// Include objects metadata in the listing
	WithMetadata bool
	// Only list objects with the prefix
	Prefix string
	// Ignore '/' delimiter
	Recursive bool
	// The maximum number of objects requested per
	// batch, advanced use-case not useful for most
	// applications
	MaxKeys int
	// StartAfter start listing lexically at this
	// object onwards, this value can also be set
	// for Marker when `UseV1` is set to true.
	StartAfter string

	// Use the deprecated list objects V1 API
	UseV1 bool

	// Has unexported fields.
}
    ListObjectsOptions holds all options of a list object request

func (o *ListObjectsOptions) Set(key, value string)
    Set adds a key value pair to the options. The key-value pair will be part of
    the HTTP GET request headers.

type ListVersionsResult struct {
	Versions []Version

	CommonPrefixes      []CommonPrefix
	Name                string
	Prefix              string
	Delimiter           string
	MaxKeys             int64
	EncodingType        string
	IsTruncated         bool
	KeyMarker           string
	VersionIDMarker     string
	NextKeyMarker       string
	NextVersionIDMarker string
}
    ListVersionsResult is an element in the list object versions response
    and has a special Unmarshaler because we need to preserver the order of
    <Version> and <DeleteMarker> in ListVersionsResult.Versions slice

func (l *ListVersionsResult) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) (err error)
    UnmarshalXML is a custom unmarshal code for the response of
    ListObjectVersions, the custom code will unmarshal <Version> and
    <DeleteMarker> tags and save them in Versions field to preserve the lexical
    order of the listing.

type MakeBucketOptions struct {
	// Bucket location
	Region string
	// Enable object locking
	ObjectLocking bool

	// ForceCreate - this is a MinIO specific extension.
	ForceCreate bool
}
    MakeBucketOptions holds all options to tweak bucket creation

type MetadataEntry struct {
	Name  string
	Value string
}
    MetadataEntry represents a metadata information of the restored object.

type Object struct {
	// Has unexported fields.
}
    Object represents an open object. It implements Reader, ReaderAt, Seeker,
    Closer for a HTTP stream.

func (o *Object) Close() (err error)
    Close - The behavior of Close after the first call returns error for
    subsequent Close() calls.

func (o *Object) Read(b []byte) (n int, err error)
    Read reads up to len(b) bytes into b. It returns the number of bytes read (0
    <= n <= len(b)) and any error encountered. Returns io.EOF upon end of file.

func (o *Object) ReadAt(b []byte, offset int64) (n int, err error)
    ReadAt reads len(b) bytes from the File starting at byte offset off.
    It returns the number of bytes read and the error, if any. ReadAt always
    returns a non-nil error when n < len(b). At end of file, that error is
    io.EOF.

func (o *Object) Seek(offset int64, whence int) (n int64, err error)
    Seek sets the offset for the next Read or Write to offset, interpreted
    according to whence: 0 means relative to the origin of the file,
    1 means relative to the current offset, and 2 means relative to the end.
    Seek returns the new offset and an error, if any.

    Seeking to a negative offset is an error. Seeking to any positive offset is
    legal, subsequent io operations succeed until the underlying object is not
    closed.

func (o *Object) Stat() (ObjectInfo, error)
    Stat returns the ObjectInfo structure describing Object.

type ObjectAttributePart struct {
	ChecksumCRC32     string `xml:",omitempty"`
	ChecksumCRC32C    string `xml:",omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumSHA1      string `xml:",omitempty"`
	ChecksumSHA256    string `xml:",omitempty"`
	ChecksumMD5       string `xml:",omitempty"`
	ChecksumSHA512    string `xml:",omitempty"`
	ChecksumXXHash64  string `xml:"ChecksumXXHASH64,omitempty"`
	ChecksumXXHash3   string `xml:"ChecksumXXHASH3,omitempty"`
	ChecksumXXHash128 string `xml:"ChecksumXXHASH128,omitempty"`
	PartNumber        int
	Size              int
}
    ObjectAttributePart is used by ObjectAttributesResponse to describe an
    object part

type ObjectAttributes struct {
	VersionID    string
	LastModified time.Time
	ObjectAttributesResponse
}
    ObjectAttributes is the response object returned by the GetObjectAttributes
    API

    - VersionID The object version

    - LastModified The last time the object was modified

    - ObjectAttributesResponse Contains more information about the object

type ObjectAttributesOptions struct {
	MaxParts             int
	VersionID            string
	PartNumberMarker     int
	ServerSideEncryption encrypt.ServerSide
}
    ObjectAttributesOptions are options used for the GetObjectAttributes API

    - MaxParts How many parts the caller wants to be returned (default: 1000)

    - VersionID The object version you want to attributes for

    - PartNumberMarker the listing will start AFTER the part matching
    PartNumberMarker

    - ServerSideEncryption The server-side encryption algorithm used when
    storing this object in Minio

type ObjectAttributesResponse struct {
	ETag         string `xml:",omitempty"`
	StorageClass string
	ObjectSize   int
	Checksum     struct {
		ChecksumCRC32     string `xml:",omitempty"`
		ChecksumCRC32C    string `xml:",omitempty"`
		ChecksumCRC64NVME string `xml:",omitempty"`
		ChecksumSHA1      string `xml:",omitempty"`
		ChecksumSHA256    string `xml:",omitempty"`
		ChecksumMD5       string `xml:",omitempty"`
		ChecksumSHA512    string `xml:",omitempty"`
		ChecksumXXHash64  string `xml:"ChecksumXXHASH64,omitempty"`
		ChecksumXXHash3   string `xml:"ChecksumXXHASH3,omitempty"`
		ChecksumXXHash128 string `xml:"ChecksumXXHASH128,omitempty"`
		ChecksumType      string `xml:",omitempty"`
	}
	ObjectParts struct {
		PartsCount           int
		PartNumberMarker     int
		NextPartNumberMarker int
		MaxParts             int
		IsTruncated          bool
		Parts                []*ObjectAttributePart `xml:"Part"`
	}
}
    ObjectAttributesResponse contains details returned by the
    GetObjectAttributes API

    Noteworthy fields:

    - ObjectParts.PartsCount Contains the total part count for the object (not
    the current response)

    - ObjectParts.PartNumberMarker Pagination of parts will begin at (but not
    include) PartNumberMarker

    - ObjectParts.NextPartNumberMarket The next PartNumberMarker to be used in
    order to continue pagination

    - ObjectParts.IsTruncated Indicates if the last part is included in the
    request (does not check if parts are missing from the start of the list,
    ONLY the end)

    - ObjectParts.MaxParts Reflects the MaxParts used by the caller or the
    default MaxParts value of the API

func (o *ObjectAttributesResponse) ChecksumMap() map[string]string
    ChecksumMap returns a map of checksums for the object.

func (o *ObjectAttributesResponse) ChecksumMode() ChecksumMode
    ChecksumMode returns the checksum mode of the object. If unable to
    determine, returns ChecksumUnknownMode.

func (o *ObjectAttributesResponse) ChecksumType() ChecksumType
    ChecksumType returns the checksum type of the object. If none is set,
    returns ChecksumNone.

type ObjectInfo struct {
	// An ETag is optionally set to md5sum of an object.  In case of multipart objects,
	// ETag is of the form MD5SUM-N where MD5SUM is md5sum of all individual md5sums of
	// each parts concatenated into one string.
	ETag string `json:"etag"`

	Key             string    `json:"name"`            // Name of the object
	LastModified    time.Time `json:"lastModified"`    // Date and time the object was last modified.
	Size            int64     `json:"size"`            // Size in bytes of the object.
	ContentType     string    `json:"contentType"`     // A standard MIME type describing the format of the object data.
	ContentEncoding string    `json:"contentEncoding"` // A standard MIME type describing encoding of the object data.
	Expires         time.Time `json:"expires"`         // The date and time at which the object is no longer able to be cached.

	// Collection of additional metadata on the object.
	// eg: x-amz-meta-*, content-encoding etc.
	Metadata http.Header `json:"metadata" xml:"-"`

	// x-amz-meta-* headers stripped "x-amz-meta-" prefix containing the first value.
	// Only returned by MinIO servers.
	UserMetadata StringMap `json:"userMetadata,omitempty"`

	// x-amz-tagging values in their k/v values.
	// Only returned by MinIO servers.
	UserTags URLMap `json:"userTags,omitempty" xml:"UserTags"`

	// x-amz-tagging-count value
	UserTagCount int

	// Owner name.
	Owner Owner

	// ACL grant.
	Grant []Grant

	// The class of storage used to store the object.
	StorageClass string `json:"storageClass"`

	// Versioning related information
	IsLatest       bool
	IsDeleteMarker bool
	VersionID      string `xml:"VersionId"`

	// x-amz-replication-status value is either in one of the following states
	// - COMPLETED
	// - PENDING
	// - FAILED
	// - REPLICA (on the destination)
	ReplicationStatus string `xml:"ReplicationStatus"`
	// set to true if delete marker has backing object version on target, and eligible to replicate
	ReplicationReady bool
	// Lifecycle expiry-date and ruleID associated with the expiry
	// not to be confused with `Expires` HTTP header.
	Expiration       time.Time
	ExpirationRuleID string
	// NumVersions is the number of versions of the object.
	NumVersions int

	Restore *RestoreInfo

	// Checksum values
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumSHA1      string
	ChecksumSHA256    string
	ChecksumCRC64NVME string
	ChecksumMD5       string
	ChecksumSHA512    string
	ChecksumXXHash64  string
	ChecksumXXHash3   string
	ChecksumXXHash128 string
	ChecksumAlgorithm string
	ChecksumMode      string `xml:"ChecksumType"`

	Internal *struct {
		K int // Data blocks
		M int // Parity blocks
	} `xml:"Internal"`

	// Error
	Err error `json:"-"`
}
    ObjectInfo container for object metadata.

func ToObjectInfo(bucketName, objectName string, h http.Header) (ObjectInfo, error)
    ToObjectInfo converts http header values into ObjectInfo type, extracts
    metadata and fills in all the necessary fields in ObjectInfo.

type ObjectMultipartInfo struct {
	// Date and time at which the multipart upload was initiated.
	Initiated time.Time `type:"timestamp" timestampFormat:"iso8601"`

	Initiator initiator
	Owner     owner

	// The type of storage to use for the object. Defaults to 'STANDARD'.
	StorageClass string

	// Key of the object for which the multipart upload was initiated.
	Key string

	// Size in bytes of the object.
	Size int64

	// Upload ID that identifies the multipart upload.
	UploadID string `xml:"UploadId"`

	// Error
	Err error
}
    ObjectMultipartInfo container for multipart object metadata.

type ObjectPart struct {
	// Part number identifies the part.
	PartNumber int

	// Date and time the part was uploaded.
	LastModified time.Time

	// Entity tag returned when the part was uploaded, usually md5sum
	// of the part.
	ETag string

	// Size of the uploaded part data.
	Size int64

	// Checksum values of each part.
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumSHA1      string
	ChecksumSHA256    string
	ChecksumCRC64NVME string
	ChecksumMD5       string
	ChecksumSHA512    string
	ChecksumXXHash64  string `xml:"ChecksumXXHASH64,omitempty"`
	ChecksumXXHash3   string `xml:"ChecksumXXHASH3,omitempty"`
	ChecksumXXHash128 string `xml:"ChecksumXXHASH128,omitempty"`
}
    ObjectPart container for particular part of an object.

func (c ObjectPart) Checksum(t ChecksumType) string
    Checksum will return the checksum for the given type. Will return the empty
    string if not set.

func (c ObjectPart) ChecksumRaw(t ChecksumType) ([]byte, error)
    ChecksumRaw returns the decoded checksum from the part.

type Options struct {
	Creds        *credentials.Credentials
	Secure       bool
	Transport    http.RoundTripper
	Trace        *httptrace.ClientTrace
	Region       string
	BucketLookup BucketLookupType

	// Allows setting a custom region lookup based on URL pattern
	// not all URL patterns are covered by this library so if you
	// have a custom endpoints with many regions you can use this
	// function to perform region lookups appropriately.
	CustomRegionViaURL func(u url.URL) string

	// Provide a custom function that returns BucketLookupType based
	// on the input URL, this is just like s3utils.IsVirtualHostSupported()
	// function but allows users to provide their own implementation.
	// Once this is set it overrides all settings for opts.BucketLookup
	// if this function returns BucketLookupAuto then default detection
	// via s3utils.IsVirtualHostSupported() is used, otherwise the
	// function is expected to return appropriate value as expected for
	// the URL the user wishes to honor.
	//
	// BucketName is passed additionally for the caller to ensure
	// handle situations where `bucketNames` have multiple `.` separators
	// in such case HTTPs certs will not work properly for *.<domain>
	// wildcards, so you need to specifically handle these situations
	// and not return bucket as part of DNS since those requests may fail.
	//
	// For better understanding look at s3utils.IsVirtualHostSupported()
	// implementation.
	BucketLookupViaURL func(u url.URL, bucketName string) BucketLookupType

	// TrailingHeaders indicates server support of trailing headers.
	// Only supported for v4 signatures.
	TrailingHeaders bool

	// Custom hash routines. Leave nil to use standard.
	CustomMD5    func() md5simd.Hasher
	CustomSHA256 func() md5simd.Hasher

	// Number of times a request is retried. Defaults to 10 retries if this option is not configured.
	// Set to 1 to disable retries.
	MaxRetries int
}
    Options for New method

type OutputLocation struct {
	XMLName xml.Name `xml:"OutputLocation"`
	S3      S3       `xml:"S3"`
}
    OutputLocation holds properties of the copy of the archived object

type Owner struct {
	XMLName     xml.Name `xml:"Owner" json:"owner"`
	DisplayName string   `xml:"ID" json:"name"`
	ID          string   `xml:"DisplayName" json:"id"`
}
    Owner name.

type ParquetInputOptions struct{}
    ParquetInputOptions parquet input specific options

type PostPolicy struct {
	// Has unexported fields.
}
    PostPolicy - Provides strict static type conversion and validation for
    Amazon S3's POST policy JSON string.

func NewPostPolicy() *PostPolicy
    NewPostPolicy - Instantiate new post policy.

func (p *PostPolicy) SetBucket(bucketName string) error
    SetBucket - Sets bucket at which objects will be uploaded to.

func (p *PostPolicy) SetChecksum(c Checksum) error
    SetChecksum sets the checksum of the request.

func (p *PostPolicy) SetCondition(matchType, condition, value string) error
    SetCondition - Sets condition for credentials, date and algorithm

func (p *PostPolicy) SetContentDisposition(contentDisposition string) error
    SetContentDisposition - Sets content-disposition of the object for this
    policy

func (p *PostPolicy) SetContentEncoding(contentEncoding string) error
    SetContentEncoding - Sets content-encoding of the object for this policy

func (p *PostPolicy) SetContentLengthRange(minLen, maxLen int64) error
    SetContentLengthRange - Set new min and max content length condition for all
    incoming uploads.

func (p *PostPolicy) SetContentType(contentType string) error
    SetContentType - Sets content-type of the object for this policy based
    upload.

func (p *PostPolicy) SetContentTypeStartsWith(contentTypeStartsWith string) error
    SetContentTypeStartsWith - Sets what content-type of the object for this
    policy based upload can start with. Can use an empty value ("") to allow any
    content-type.

func (p *PostPolicy) SetEncryption(sse encrypt.ServerSide)
    SetEncryption - sets encryption headers for POST API

func (p *PostPolicy) SetExpires(t time.Time) error
    SetExpires - Sets expiration time for the new policy.

func (p *PostPolicy) SetKey(key string) error
    SetKey - Sets an object name for the policy based upload.

func (p *PostPolicy) SetKeyStartsWith(keyStartsWith string) error
    SetKeyStartsWith - Sets an object name that an policy based upload can start
    with. Can use an empty value ("") to allow any key.

func (p *PostPolicy) SetSuccessActionRedirect(redirect string) error
    SetSuccessActionRedirect - Sets the redirect success url of the object for
    this policy based upload.

func (p *PostPolicy) SetSuccessStatusAction(status string) error
    SetSuccessStatusAction - Sets the status success code of the object for this
    policy based upload.

func (p *PostPolicy) SetTagging(tagging string) error
    SetTagging - Sets tagging for the object for this policy based upload.

func (p *PostPolicy) SetUserData(key, value string) error
    SetUserData - Set user data as a key/value couple. Can be retrieved through
    a HEAD request or an event.

func (p *PostPolicy) SetUserMetadata(key, value string) error
    SetUserMetadata - Set user metadata as a key/value couple. Can be retrieved
    through a HEAD request or an event.

func (p *PostPolicy) SetUserMetadataStartsWith(key, value string) error
    SetUserMetadataStartsWith - Set how an user metadata should starts with.
    Can be retrieved through a HEAD request or an event.

func (p PostPolicy) String() string
    String function for printing policy in json formatted string.

type ProgressMessage struct {
	XMLName xml.Name `xml:"Progress" json:"-"`
	StatsMessage
}
    ProgressMessage is a struct for progress xml message.

type PromptObjectOptions struct {
	LambdaArn  string
	PromptArgs map[string]any

	// Has unexported fields.
}
    PromptObjectOptions provides options to PromptObject call. LambdaArn is the
    ARN of the Prompt Lambda to be invoked. PromptArgs is a map of key-value
    pairs to be passed to the inference action on the Prompt Lambda. "prompt" is
    a reserved key and should not be used as a key in PromptArgs.

func (o *PromptObjectOptions) AddLambdaArnToReqParams(lambdaArn string)
    AddLambdaArnToReqParams adds the lambdaArn to the request query string
    parameters.

func (o *PromptObjectOptions) AddPromptArg(key string, value any)
    AddPromptArg Add a key value pair to the prompt arguments where the key is a
    string and the value is a JSON serializable.

func (o PromptObjectOptions) Header() http.Header
    Header returns the http.Header representation of the POST options.

func (o *PromptObjectOptions) SetHeader(key, value string)
    SetHeader adds a key value pair to the options. The key-value pair will be
    part of the HTTP POST request headers.

type PutObjectFanOutEntry struct {
	Key                string            `json:"key"`
	UserMetadata       map[string]string `json:"metadata,omitempty"`
	UserTags           map[string]string `json:"tags,omitempty"`
	ContentType        string            `json:"contentType,omitempty"`
	ContentEncoding    string            `json:"contentEncoding,omitempty"`
	ContentDisposition string            `json:"contentDisposition,omitempty"`
	ContentLanguage    string            `json:"contentLanguage,omitempty"`
	CacheControl       string            `json:"cacheControl,omitempty"`
	Retention          RetentionMode     `json:"retention,omitempty"`
	RetainUntilDate    *time.Time        `json:"retainUntil,omitempty"`
}
    PutObjectFanOutEntry is per object entry fan-out metadata

type PutObjectFanOutRequest struct {
	Entries  []PutObjectFanOutEntry
	Checksum Checksum
	SSE      encrypt.ServerSide
}
    PutObjectFanOutRequest this is the request structure sent to the server to
    fan-out the stream to multiple objects.

type PutObjectFanOutResponse struct {
	Key          string     `json:"key"`
	ETag         string     `json:"etag,omitempty"`
	VersionID    string     `json:"versionId,omitempty"`
	LastModified *time.Time `json:"lastModified,omitempty"`
	Error        string     `json:"error,omitempty"`
}
    PutObjectFanOutResponse this is the response structure sent by the server
    upon success or failure for each object fan-out keys. Additionally, this
    response carries ETag, VersionID and LastModified for each object fan-out.

type PutObjectLegalHoldOptions struct {
	VersionID string
	Status    *LegalHoldStatus
}
    PutObjectLegalHoldOptions represents options specified by user for
    PutObjectLegalHold call

type PutObjectOptions struct {
	UserMetadata            map[string]string
	UserTags                map[string]string
	Progress                io.Reader
	ContentType             string
	ContentEncoding         string
	ContentDisposition      string
	ContentLanguage         string
	CacheControl            string
	Expires                 time.Time
	Mode                    RetentionMode
	RetainUntilDate         time.Time
	ServerSideEncryption    encrypt.ServerSide
	NumThreads              uint
	StorageClass            string
	WebsiteRedirectLocation string
	PartSize                uint64
	LegalHold               LegalHoldStatus
	SendContentMd5          bool
	DisableContentSha256    bool
	DisableMultipart        bool

	// AutoChecksum is the type of checksum that will be added if no other checksum is added,
	// like MD5 or SHA256 streaming checksum, and it is feasible for the upload type.
	// If none is specified CRC32C is used, since it is generally the fastest.
	AutoChecksum ChecksumType

	// Checksum will force a checksum of the specific type.
	// This requires that the client was created with "TrailingHeaders:true" option,
	// and that the destination server supports it.
	// Unavailable with V2 signatures & Google endpoints.
	// This will disable content MD5 checksums if set.
	Checksum ChecksumType

	// ConcurrentStreamParts will create NumThreads buffers of PartSize bytes,
	// fill them serially and upload them in parallel.
	// This can be used for faster uploads on non-seekable or slow-to-seek input.
	ConcurrentStreamParts bool
	Internal              AdvancedPutOptions

	// Has unexported fields.
}
    PutObjectOptions represents options specified by user for PutObject call

func (opts PutObjectOptions) Header() (header http.Header)
    Header - constructs the headers from metadata entered by user in
    PutObjectOptions struct

func (opts *PutObjectOptions) SetMatchETag(etag string)
    SetMatchETag if etag matches while PUT MinIO returns an error this is a
    MinIO specific extension to support optimistic locking semantics.

func (opts *PutObjectOptions) SetMatchETagExcept(etag string)
    SetMatchETagExcept if etag does not match while PUT MinIO returns an error
    this is a MinIO specific extension to support optimistic locking semantics.

type PutObjectPartOptions struct {
	Md5Base64, Sha256Hex  string
	SSE                   encrypt.ServerSide
	CustomHeader, Trailer http.Header
	DisableContentSha256  bool
}
    PutObjectPartOptions contains options for PutObjectPart API

type PutObjectRetentionOptions struct {
	GovernanceBypass bool
	Mode             *RetentionMode
	RetainUntilDate  *time.Time
	VersionID        string
}
    PutObjectRetentionOptions represents options specified by user for PutObject
    call

type PutObjectTaggingOptions struct {
	VersionID string
	Internal  AdvancedObjectTaggingOptions
}
    PutObjectTaggingOptions holds an object version id to update tag(s) of a
    specific object version

type QOSConfig struct {
	Version string    `yaml:"version"`
	Rules   []QOSRule `yaml:"rules"`
}
    QOSConfig represents the QoS configuration for a bucket.

func NewQOSConfig() *QOSConfig
    NewQOSConfig creates a new empty QoS configuration.

type QOSMetric struct {
	APIName            string        `json:"apiName"`
	Rule               QOSRule       `json:"rule"`
	Totals             CounterMetric `json:"totals"`
	Throttled          CounterMetric `json:"throttleCount"`
	ExceededRateLimit  CounterMetric `json:"exceededRateLimitCount"`
	ClientDisconnCount CounterMetric `json:"clientDisconnectCount"`
	ReqTimeoutCount    CounterMetric `json:"reqTimeoutCount"`
}
    QOSMetric - metric for a qos rule per bucket

type QOSNodeStats struct {
	Stats    []QOSMetric `json:"stats"`
	NodeName string      `json:"node"`
}
    QOSNodeStats represents stats for a bucket on a single node

type QOSRule struct {
	ID           string `yaml:"id"`
	Label        string `yaml:"label,omitempty"`
	Priority     int    `yaml:"priority"`
	ObjectPrefix string `yaml:"objectPrefix"`
	API          string `yaml:"api"`
	Rate         int64  `yaml:"rate"`
	Burst        int64  `yaml:"burst"` // not required for concurrency limit
	Limit        string `yaml:"limit"` // "concurrency" or "rps"
}
    QOSRule represents a single QoS rule.

type QueryExpressionType string
    QueryExpressionType - is of what syntax the expression is, this should only
    be SQL

const (
	QueryExpressionTypeSQL QueryExpressionType = "SQL"
)
    Constants for expression type.

type RemoveBucketOptions struct {
	ForceDelete bool
}
    RemoveBucketOptions special headers to purge buckets, only useful when
    endpoint is MinIO

type RemoveObjectError struct {
	ObjectName string
	VersionID  string
	Err        error
}
    RemoveObjectError - container of Multi Delete S3 API error

func (err *RemoveObjectError) Error() string

type RemoveObjectOptions struct {
	ForceDelete      bool
	GovernanceBypass bool
	VersionID        string
	Internal         AdvancedRemoveOptions
}
    RemoveObjectOptions represents options specified by user for RemoveObject
    call

type RemoveObjectResult struct {
	ObjectName      string
	ObjectVersionID string

	DeleteMarker          bool
	DeleteMarkerVersionID string

	Err error
}
    RemoveObjectResult - container of Multi Delete S3 API result

type RemoveObjectTaggingOptions struct {
	VersionID string
	Internal  AdvancedObjectTaggingOptions
}
    RemoveObjectTaggingOptions holds the version id of the object to remove

type RemoveObjectsOptions struct {
	GovernanceBypass bool
}
    RemoveObjectsOptions represents options specified by user for RemoveObjects
    call

type ReplicationStatus string
    ReplicationStatus represents replication status of object

const (
	// ReplicationStatusPending indicates replication is pending
	ReplicationStatusPending ReplicationStatus = "PENDING"
	// ReplicationStatusComplete indicates replication completed ok
	ReplicationStatusComplete ReplicationStatus = "COMPLETED"
	// ReplicationStatusFailed indicates replication failed
	ReplicationStatusFailed ReplicationStatus = "FAILED"
	// ReplicationStatusReplica indicates object is a replica of a source
	ReplicationStatusReplica ReplicationStatus = "REPLICA"
	// ReplicationStatusReplicaEdge indicates object is a replica of a edge source
	ReplicationStatusReplicaEdge ReplicationStatus = "REPLICA-EDGE"
)
func (r ReplicationStatus) Empty() bool
    Empty returns true if no replication status set.

type RestoreInfo struct {
	// Is the restoring operation is still ongoing
	OngoingRestore bool
	// When the restored copy of the archived object will be removed
	ExpiryTime time.Time
}
    RestoreInfo contains information of the restore operation of an archived
    object

type RestoreRequest struct {
	XMLName              xml.Name              `xml:"http://s3.amazonaws.com/doc/2006-03-01/ RestoreRequest"`
	Type                 *RestoreType          `xml:"Type,omitempty"`
	Tier                 *TierType             `xml:"Tier,omitempty"`
	Days                 *int                  `xml:"Days,omitempty"`
	GlacierJobParameters *GlacierJobParameters `xml:"GlacierJobParameters,omitempty"`
	Description          *string               `xml:"Description,omitempty"`
	SelectParameters     *SelectParameters     `xml:"SelectParameters,omitempty"`
	OutputLocation       *OutputLocation       `xml:"OutputLocation,omitempty"`
}
    RestoreRequest holds properties of the restore object request

func (r *RestoreRequest) SetDays(v int)
    SetDays sets the days parameter of the restore request

func (r *RestoreRequest) SetDescription(v string)
    SetDescription sets the description of the restore request

func (r *RestoreRequest) SetGlacierJobParameters(v GlacierJobParameters)
    SetGlacierJobParameters sets the GlacierJobParameters of the restore request

func (r *RestoreRequest) SetOutputLocation(v OutputLocation)
    SetOutputLocation sets the properties of the copy of the archived object

func (r *RestoreRequest) SetSelectParameters(v SelectParameters)
    SetSelectParameters sets SelectParameters of the restore select request

func (r *RestoreRequest) SetTier(v TierType)
    SetTier sets the retrieval tier of the restore request

func (r *RestoreRequest) SetType(v RestoreType)
    SetType sets the type of the restore request

type RestoreType string
    RestoreType represents the restore request type

type Retention struct {
	Mode     RetentionMode
	Validity time.Duration
}
    Retention - bucket level retention configuration.

func (r Retention) IsEmpty() bool
    IsEmpty - returns whether retention is empty or not.

func (r Retention) String() string

type RetentionMode string
    RetentionMode - object retention mode.

const (
	// Governance - governance mode.
	Governance RetentionMode = "GOVERNANCE"

	// Compliance - compliance mode.
	Compliance RetentionMode = "COMPLIANCE"
)
func (r RetentionMode) IsValid() bool
    IsValid - check whether this retention mode is valid or not.

func (r RetentionMode) String() string

type S3 struct {
	AccessControlList *AccessControlList `xml:"AccessControlList,omitempty"`
	BucketName        string
	Prefix            string
	CannedACL         *string        `xml:"CannedACL,omitempty"`
	Encryption        *Encryption    `xml:"Encryption,omitempty"`
	StorageClass      *string        `xml:"StorageClass,omitempty"`
	Tagging           *tags.Tags     `xml:"Tagging,omitempty"`
	UserMetadata      *MetadataEntry `xml:"UserMetadata,omitempty"`
}
    S3 holds properties of the copy of the archived object

type SelectCompressionType string
    SelectCompressionType - is the parameter for what type of compression is
    present

const (
	SelectCompressionNONE SelectCompressionType = "NONE"
	SelectCompressionGZIP SelectCompressionType = "GZIP"
	SelectCompressionBZIP SelectCompressionType = "BZIP2"

	SelectCompressionZSTD   SelectCompressionType = "ZSTD"   // Zstandard compression.
	SelectCompressionLZ4    SelectCompressionType = "LZ4"    // LZ4 Stream
	SelectCompressionS2     SelectCompressionType = "S2"     // S2 Stream
	SelectCompressionSNAPPY SelectCompressionType = "SNAPPY" // Snappy stream
)
    Constants for compression types under select API.

type SelectObjectInputSerialization struct {
	CompressionType SelectCompressionType `xml:"CompressionType,omitempty"`
	Parquet         *ParquetInputOptions  `xml:"Parquet,omitempty"`
	CSV             *CSVInputOptions      `xml:"CSV,omitempty"`
	JSON            *JSONInputOptions     `xml:"JSON,omitempty"`
}
    SelectObjectInputSerialization - input serialization parameters

type SelectObjectOptions struct {
	XMLName              xml.Name           `xml:"SelectObjectContentRequest" json:"-"`
	ServerSideEncryption encrypt.ServerSide `xml:"-"`
	Expression           string
	ExpressionType       QueryExpressionType
	InputSerialization   SelectObjectInputSerialization
	OutputSerialization  SelectObjectOutputSerialization
	RequestProgress      struct {
		Enabled bool
	}
}
    SelectObjectOptions - represents the input select body

func (o SelectObjectOptions) Header() http.Header
    Header returns the http.Header representation of the SelectObject options.

type SelectObjectOutputSerialization struct {
	CSV  *CSVOutputOptions  `xml:"CSV,omitempty"`
	JSON *JSONOutputOptions `xml:"JSON,omitempty"`
}
    SelectObjectOutputSerialization - output serialization parameters.

type SelectObjectType string
    SelectObjectType - is the parameter which defines what type of object the
    operation is being performed on.

const (
	SelectObjectTypeCSV     SelectObjectType = "CSV"
	SelectObjectTypeJSON    SelectObjectType = "JSON"
	SelectObjectTypeParquet SelectObjectType = "Parquet"
)
    Constants for input data types.

type SelectParameters struct {
	XMLName             xml.Name `xml:"SelectParameters"`
	ExpressionType      QueryExpressionType
	Expression          string
	InputSerialization  SelectObjectInputSerialization
	OutputSerialization SelectObjectOutputSerialization
}
    SelectParameters holds the select request parameters

type SelectResults struct {
	// Has unexported fields.
}
    SelectResults is used for the streaming responses from the server.

func NewSelectResults(resp *http.Response, bucketName string) (*SelectResults, error)
    NewSelectResults creates a Select Result parser that parses the response and
    returns a Reader that will return parsed and assembled select output.

func (s *SelectResults) Close() error
    Close - closes the underlying response body and the stream reader.

func (s *SelectResults) Progress() *ProgressMessage
    Progress - information about the progress of a request.

func (s *SelectResults) Read(b []byte) (n int, err error)
    Read - is a reader compatible implementation for SelectObjectContent
    records.

func (s *SelectResults) Stats() *StatsMessage
    Stats - information about a request's stats when processing is complete.

type SessionMode string
    SessionMode - session mode type there are only two types

const (
	SessionReadWrite SessionMode = "ReadWrite"
	SessionReadOnly  SessionMode = "ReadOnly"
)
    Session constants

type SnowballObject struct {
	// Key is the destination key, including prefix.
	Key string

	// Size is the content size of this object.
	Size int64

	// Modtime to apply to the object.
	// If Modtime is the zero value current time will be used.
	ModTime time.Time

	// Content of the object.
	// Exactly 'Size' number of bytes must be provided.
	Content io.Reader

	// VersionID of the object; if empty, a new versionID will be generated
	VersionID string

	// Headers contains more options for this object upload, the same as you
	// would include in a regular PutObject operation, such as user metadata
	// and content-disposition, expires, ..
	Headers http.Header

	// Close will be called when an object has finished processing.
	// Note that if PutObjectsSnowball returns because of an error,
	// objects not consumed from the input will NOT have been closed.
	// Leave as nil for no callback.
	Close func()
}
    SnowballObject contains information about a single object to be added to the
    snowball.

type SnowballOptions struct {
	// Opts is options applied to all objects.
	Opts PutObjectOptions

	// InMemory specifies that all objects should be collected in memory
	// before they are uploaded.
	// If false a temporary file will be created.
	InMemory bool

	// Compress enabled content compression before upload.
	// Compression will typically reduce memory and network usage,
	// Compression can safely be enabled with MinIO hosts.
	Compress bool

	// SkipErrs if enabled will skip any errors while reading the
	// object content while creating the snowball archive
	SkipErrs bool
}
    SnowballOptions contains options for PutObjectsSnowball calls.

type StatObjectOptions = GetObjectOptions
    StatObjectOptions are used to specify additional headers or options during
    GET info/stat requests.

type StatsMessage struct {
	XMLName        xml.Name `xml:"Stats" json:"-"`
	BytesScanned   int64
	BytesProcessed int64
	BytesReturned  int64
}
    StatsMessage is a struct for stat xml message.

type StringMap map[string]string
    StringMap represents map with custom UnmarshalXML

func (m *StringMap) UnmarshalXML(d *xml.Decoder, _ xml.StartElement) error
    UnmarshalXML unmarshals the XML into a map of string to strings, creating a
    key in the map for each tag and setting it's value to the tags contents.

    The fact this function is on the pointer of Map is important, so that if
    m is nil it can be initialized, which is often the case if m is nested in
    another xml structural. This is also why the first thing done on the first
    line is initialize it.

type TierType string
    TierType represents a retrieval tier

type URLMap map[string]string
    URLMap represents map with custom UnmarshalXML

func (m *URLMap) UnmarshalXML(d *xml.Decoder, se xml.StartElement) error
    UnmarshalXML unmarshals the XML into a map of string to strings, creating a
    key in the map for each tag and setting it's value to the tags contents.

    The fact this function is on the pointer of Map is important, so that if
    m is nil it can be initialized, which is often the case if m is nested in
    another xml structural. This is also why the first thing done on the first
    line is initialize it.

type UpdateObjectEncryptionOptions struct {
	// KMSKeyArn is the KMS key name or ARN to encrypt the object with.
	KMSKeyArn string

	// BucketKeyEnabled enables S3 Bucket Key for KMS encryption.
	BucketKeyEnabled bool

	// VersionID targets a specific object version.
	VersionID string
}
    UpdateObjectEncryptionOptions holds options for the UpdateObjectEncryption
    call.

type UpdateObjectEncryptionResult struct {
	// VersionID is the version ID of the object that was updated, if versioning is enabled.
	VersionID string
}
    UpdateObjectEncryptionResult holds the result of an UpdateObjectEncryption
    call.

type UploadInfo struct {
	Bucket       string
	Key          string
	ETag         string
	Size         int64
	LastModified time.Time
	Location     string
	VersionID    string

	// Lifecycle expiry-date and ruleID associated with the expiry
	// not to be confused with `Expires` HTTP header.
	Expiration       time.Time
	ExpirationRuleID string

	// Verified checksum values, if any.
	// Values are base64 (standard) encoded.
	// For multipart objects this is a checksum of the checksum of each part.
	ChecksumCRC32     string
	ChecksumCRC32C    string
	ChecksumSHA1      string
	ChecksumSHA256    string
	ChecksumCRC64NVME string
	ChecksumMD5       string
	ChecksumSHA512    string
	ChecksumXXHash64  string
	ChecksumXXHash3   string
	ChecksumXXHash128 string
	ChecksumMode      string
}
    UploadInfo contains information about the newly uploaded or copied object.

type ValidityUnit string
    ValidityUnit - retention validity unit.

const (
	// Days - denotes no. of days.
	Days ValidityUnit = "DAYS"

	// Years - denotes no. of years.
	Years ValidityUnit = "YEARS"
)
func (unit ValidityUnit) String() string

type Version struct {
	ETag         string
	IsLatest     bool
	Key          string
	LastModified time.Time
	Owner        Owner
	Size         int64
	StorageClass string
	VersionID    string `xml:"VersionId"`

	// x-amz-meta-* headers stripped "x-amz-meta-" prefix containing the first value.
	// Only returned by MinIO servers.
	UserMetadata StringMap `json:"userMetadata,omitempty"`

	// x-amz-tagging values in their k/v values.
	// Only returned by MinIO servers.
	UserTags URLMap `json:"userTags,omitempty" xml:"UserTags"`

	Internal *struct {
		K int // Data blocks
		M int // Parity blocks
	} `xml:"Internal"`

	// Checksum values. Only returned by AiStor servers.
	ChecksumCRC32     string `xml:",omitempty"`
	ChecksumCRC32C    string `xml:",omitempty"`
	ChecksumSHA1      string `xml:",omitempty"`
	ChecksumSHA256    string `xml:",omitempty"`
	ChecksumCRC64NVME string `xml:",omitempty"`
	ChecksumMD5       string `xml:",omitempty"`
	ChecksumSHA512    string `xml:",omitempty"`
	ChecksumXXHash64  string `xml:"ChecksumXXHASH64,omitempty"`
	ChecksumXXHash3   string `xml:"ChecksumXXHASH3,omitempty"`
	ChecksumXXHash128 string `xml:"ChecksumXXHASH128,omitempty"`
	ChecksumAlgorithm string `xml:",omitempty"`
	ChecksumType      string `xml:",omitempty"`

	// Has unexported fields.
}
    Version is an element in the list object versions response

