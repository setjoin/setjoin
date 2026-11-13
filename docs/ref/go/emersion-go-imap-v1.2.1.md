package imap // import "github.com/emersion/go-imap"

Package imap implements IMAP4rev1 (RFC 3501).

CONSTANTS

const (
	// In the connecting state, the server has not yet sent a greeting and no
	// command can be issued.
	ConnectingState = 0

	// In the not authenticated state, the client MUST supply
	// authentication credentials before most commands will be
	// permitted.  This state is entered when a connection starts
	// unless the connection has been pre-authenticated.
	NotAuthenticatedState ConnState = 1 << 0

	// In the authenticated state, the client is authenticated and MUST
	// select a mailbox to access before commands that affect messages
	// will be permitted.  This state is entered when a
	// pre-authenticated connection starts, when acceptable
	// authentication credentials have been provided, after an error in
	// selecting a mailbox, or after a successful CLOSE command.
	AuthenticatedState = 1 << 1

	// In a selected state, a mailbox has been selected to access.
	// This state is entered when a mailbox has been successfully
	// selected.
	SelectedState = AuthenticatedState + 1<<2

	// In the logout state, the connection is being terminated. This
	// state can be entered as a result of a client request (via the
	// LOGOUT command) or by unilateral action on the part of either
	// the client or server.
	LogoutState = 1 << 3

	// ConnectedState is either NotAuthenticatedState, AuthenticatedState or
	// SelectedState.
	ConnectedState = NotAuthenticatedState | AuthenticatedState | SelectedState
)
const (
	// Defined in RFC 3501 as date-text on page 83.
	DateLayout = "_2-Jan-2006"
	// Defined in RFC 3501 as date-time on page 83.
	DateTimeLayout = "_2-Jan-2006 15:04:05 -0700"
)
    Date and time layouts. Dovecot adds a leading zero to dates:

        https://github.com/dovecot/core/blob/4fbd5c5e113078e72f29465ccc96d44955ceadc2/src/lib-imap/imap-date.c#L166

    Cyrus adds a leading space to dates:

        https://github.com/cyrusimap/cyrus-imapd/blob/1cb805a3bffbdf829df0964f3b802cdc917e76db/lib/times.c#L543

    GMail doesn't support leading spaces in dates used in SEARCH commands.

const (
	// SetFlags replaces existing flags by new ones.
	SetFlags FlagsOp = "FLAGS"
	// AddFlags adds new flags.
	AddFlags = "+FLAGS"
	// RemoveFlags removes existing flags.
	RemoveFlags = "-FLAGS"
)
const (
	// It is not possible for any child levels of hierarchy to exist under this\
	// name; no child levels exist now and none can be created in the future.
	NoInferiorsAttr = "\\Noinferiors"
	// It is not possible to use this name as a selectable mailbox.
	NoSelectAttr = "\\Noselect"
	// The mailbox has been marked "interesting" by the server; the mailbox
	// probably contains messages that have been added since the last time the
	// mailbox was selected.
	MarkedAttr = "\\Marked"
	// The mailbox does not contain any additional messages since the last time
	// the mailbox was selected.
	UnmarkedAttr = "\\Unmarked"
)
    Mailbox attributes definied in RFC 3501 section 7.2.2.

const (
	// This mailbox presents all messages in the user's message store.
	AllAttr = "\\All"
	// This mailbox is used to archive messages.
	ArchiveAttr = "\\Archive"
	// This mailbox is used to hold draft messages -- typically, messages that are
	// being composed but have not yet been sent.
	DraftsAttr = "\\Drafts"
	// This mailbox presents all messages marked in some way as "important".
	FlaggedAttr = "\\Flagged"
	// This mailbox is where messages deemed to be junk mail are held.
	JunkAttr = "\\Junk"
	// This mailbox is used to hold copies of messages that have been sent.
	SentAttr = "\\Sent"
	// This mailbox is used to hold messages that have been deleted or marked for
	// deletion.
	TrashAttr = "\\Trash"
)
    Mailbox attributes defined in RFC 6154 section 2 (SPECIAL-USE extension).

const (
	// The presence of this attribute indicates that the mailbox has child
	// mailboxes.
	HasChildrenAttr = "\\HasChildren"
	// The presence of this attribute indicates that the mailbox has no child
	// mailboxes.
	HasNoChildrenAttr = "\\HasNoChildren"
)
    Mailbox attributes defined in RFC 3348 (CHILDREN extension)

const (
	SeenFlag     = "\\Seen"
	AnsweredFlag = "\\Answered"
	FlaggedFlag  = "\\Flagged"
	DeletedFlag  = "\\Deleted"
	DraftFlag    = "\\Draft"
	RecentFlag   = "\\Recent"
)
    System message flags, defined in RFC 3501 section 2.3.2.

const (
	// Refers to the entire part, including headers.
	EntireSpecifier PartSpecifier = ""
	// Refers to the header of the part. Must include the final CRLF delimiting
	// the header and the body.
	HeaderSpecifier = "HEADER"
	// Refers to the text body of the part, omitting the header.
	TextSpecifier = "TEXT"
	// Refers to the MIME Internet Message Body header.  Must include the final
	// CRLF delimiting the header and the body.
	MIMESpecifier = "MIME"
)
    Part specifiers described in RFC 3501 page 55.

const ImportantAttr = "\\Important"
    This mailbox attribute is a signal that the mailbox contains messages that
    are likely important to the user. This attribute is defined in RFC 8457
    section 3.

const ImportantFlag = "$Important"
    ImportantFlag is a message flag to signal that a message is likely important
    to the user. This flag is defined in RFC 8457 section 2.

const InboxName = "INBOX"
    The primary mailbox, as defined in RFC 3501 section 5.1.

const TryCreateFlag = "\\*"
    TryCreateFlag is a special flag in MailboxStatus.PermanentFlags indicating
    that it is possible to create new keywords by attempting to store those
    flags in the mailbox.


VARIABLES

var CharsetReader func(charset string, r io.Reader) (io.Reader, error)
    CharsetReader, if non-nil, defines a function to generate charset-conversion
    readers, converting from the provided charset into UTF-8. Charsets are
    always lower-case. utf-8 and us-ascii charsets are handled by default.
    One of the the CharsetReader's result values must be non-nil.


FUNCTIONS

func CanonicalFlag(flag string) string
    CanonicalFlag returns the canonical form of a flag. Flags are
    case-insensitive.

    If the flag is defined in RFC 3501, it returns the flag with the case of the
    RFC. Otherwise, it returns the lowercase version of the flag.

func CanonicalMailboxName(name string) string
    CanonicalMailboxName returns the canonical form of a mailbox name. Mailbox
    names can be case-sensitive or case-insensitive depending on the backend
    implementation. The special INBOX mailbox is case-insensitive.

func FormatAddressList(addrs []*Address) interface{}
    Format an address list to fields.

func FormatMailboxName(name string) interface{}
func FormatParamList(params map[string]string) []interface{}
func FormatStringList(list []string) (fields []interface{})
    Convert a string list to a field list.

func IsParseError(err error) bool
    IsParseError returns true if the provided error is a parse error produced by
    Reader.

func NewDebugWriter(local, remote io.Writer) io.Writer
    NewDebugWriter creates a new io.Writer that will write local network
    activity to local and remote network activity to remote.

func NewLockedWriter(w io.Writer) io.Writer
    NewLockedWriter - goroutine safe writer.

func ParseBodySectionName(s FetchItem) (*BodySectionName, error)
    ParseBodySectionName parses a body section name.

func ParseFlagsOp(item StoreItem) (op FlagsOp, silent bool, err error)
    ParseFlagsOp parses a flags operation from StoreItem.

func ParseNamedResp(resp Resp) (name string, fields []interface{}, ok bool)
    ParseNamedResp attempts to parse a named data response.

func ParseNumber(f interface{}) (uint32, error)
    ParseNumber parses a number.

func ParseParamList(fields []interface{}) (map[string]string, error)
func ParseSeqSet(set string) (s *SeqSet, err error)
    ParseSeqSet returns a new SeqSet instance after parsing the set string.

func ParseString(f interface{}) (string, error)
    ParseString parses a string, which is either a literal, a quoted string or
    an atom.

func ParseStringList(f interface{}) ([]string, error)
    Convert a field list to a string list.

func ReadResp(r *Reader) (Resp, error)
    ReadResp reads a single response from a Reader.


TYPES

type Address struct {
	// The personal name.
	PersonalName string
	// The SMTP at-domain-list (source route).
	AtDomainList string
	// The mailbox name.
	MailboxName string
	// The host name.
	HostName string
}
    An address.

func ParseAddressList(fields []interface{}) (addrs []*Address)
    Parse an address list from fields.

func (addr *Address) Address() string
    Address returns the mailbox address (e.g. "foo@example.org").

func (addr *Address) Format() []interface{}
    Format an address to fields.

func (addr *Address) Parse(fields []interface{}) error
    Parse an address from fields.

type BodyPartName struct {
	// The specifier of the requested part.
	Specifier PartSpecifier
	// The part path. Parts indexes start at 1.
	Path []int
	// If Specifier is HEADER, contains header fields that will/won't be returned,
	// depending of the value of NotFields.
	Fields []string
	// If set to true, Fields is a blacklist of fields instead of a whitelist.
	NotFields bool
}
    A body part name.

func (part *BodyPartName) Equal(other *BodyPartName) bool
    Equal checks whether two body part names are equal.

type BodySectionName struct {
	BodyPartName

	// If set to true, do not implicitly set the \Seen flag.
	Peek bool
	// The substring of the section requested. The first value is the position of
	// the first desired octet and the second value is the maximum number of
	// octets desired.
	Partial []int

	// Has unexported fields.
}
    A body section name. See RFC 3501 page 55.

func (section *BodySectionName) Equal(other *BodySectionName) bool
    Equal checks whether two sections are equal.

func (section *BodySectionName) ExtractPartial(b []byte) []byte
    ExtractPartial returns a subset of the specified bytes matching the partial
    requested in the section name.

func (section *BodySectionName) FetchItem() FetchItem

type BodyStructure struct {

	// The MIME type (e.g. "text", "image")
	MIMEType string
	// The MIME subtype (e.g. "plain", "png")
	MIMESubType string
	// The MIME parameters.
	Params map[string]string

	// The Content-Id header.
	Id string
	// The Content-Description header.
	Description string
	// The Content-Encoding header.
	Encoding string
	// The Content-Length header.
	Size uint32

	// The children parts, if multipart.
	Parts []*BodyStructure
	// The envelope, if message/rfc822.
	Envelope *Envelope
	// The body structure, if message/rfc822.
	BodyStructure *BodyStructure
	// The number of lines, if text or message/rfc822.
	Lines uint32

	// True if the body structure contains extension data.
	Extended bool

	// The Content-Disposition header field value.
	Disposition string
	// The Content-Disposition header field parameters.
	DispositionParams map[string]string
	// The Content-Language header field, if multipart.
	Language []string
	// The content URI, if multipart.
	Location []string

	// The MD5 checksum.
	MD5 string
}
    A body structure. See RFC 3501 page 74.

func (bs *BodyStructure) Filename() (string, error)
    Filename parses the body structure's filename, if it's an attachment.
    An empty string is returned if the filename isn't specified. An error is
    returned if and only if a charset error occurs, in which case the undecoded
    filename is returned too.

func (bs *BodyStructure) Format() (fields []interface{})

func (bs *BodyStructure) Parse(fields []interface{}) error

func (bs *BodyStructure) Walk(f BodyStructureWalkFunc)
    Walk walks the body structure tree, calling f for each part in the tree,
    including bs itself. The parts are visited in DFS pre-order.

type BodyStructureWalkFunc func(path []int, part *BodyStructure) (walkChildren bool)
    BodyStructureWalkFunc is the type of the function called for each body
    structure visited by BodyStructure.Walk. The path argument contains the IMAP
    part path (see BodyPartName).

    The function should return true to visit all of the part's children or false
    to skip them.

type Command struct {
	// The command tag. It acts as a unique identifier for this command. If empty,
	// the command is untagged.
	Tag string
	// The command name.
	Name string
	// The command arguments.
	Arguments []interface{}
}
    A command.

func (cmd *Command) Command() *Command
    Implements the Commander interface.

func (cmd *Command) Parse(fields []interface{}) error
    Parse a command from fields.

func (cmd *Command) WriteTo(w *Writer) error

type Commander interface {
	Command() *Command
}
    A value that can be converted to a command.

type Conn struct {
	net.Conn
	*Reader
	*Writer

	// Has unexported fields.
}
    An IMAP connection.

func NewConn(conn net.Conn, r *Reader, w *Writer) *Conn
    NewConn creates a new IMAP connection.

func (c *Conn) Flush() error
    Flush writes any buffered data to the underlying connection.

func (c *Conn) Info() *ConnInfo

func (c *Conn) SetDebug(w io.Writer)
    SetDebug defines an io.Writer to which all network activity will be logged.
    If nil is provided, network activity will not be logged.

func (c *Conn) Upgrade(upgrader ConnUpgrader) error
    Upgrade a connection, e.g. wrap an unencrypted connection with an encrypted
    tunnel.

func (c *Conn) Wait()
    Called by reader/writer goroutines to wait for Upgrade to finish

func (c *Conn) WaitReady()
    Called by Upgrader to wait for reader/writer goroutines to be ready for
    upgrade.

func (c *Conn) Write(b []byte) (n int, err error)
    Write implements io.Writer.

type ConnInfo struct {
	RemoteAddr net.Addr
	LocalAddr  net.Addr

	// nil if connection is not using TLS.
	TLS *tls.ConnectionState
}
    Underlying connection state information.

type ConnState int
    A connection state. See RFC 3501 section 3.

type ConnUpgrader func(conn net.Conn) (net.Conn, error)
    A function that upgrades a connection.

    This should only be used by libraries implementing an IMAP extension (e.g.
    COMPRESS).

type ContinuationReq struct {
	// The info message sent with the continuation request.
	Info string
}
    ContinuationReq is a continuation request response.

func (r *ContinuationReq) WriteTo(w *Writer) error

type DataResp struct {
	// The response tag. Can be either "" for untagged responses, "+" for continuation
	// requests or a previous command's tag.
	Tag string
	// The parsed response fields.
	Fields []interface{}
}
    DataResp is an IMAP response containing data.

func NewUntaggedResp(fields []interface{}) *DataResp
    NewUntaggedResp creates a new untagged response.

func (r *DataResp) WriteTo(w *Writer) error

type Date time.Time
    time.Time with a specific layout.

type DateTime time.Time
    time.Time with a specific layout.

type Envelope struct {
	// The message date.
	Date time.Time
	// The message subject.
	Subject string
	// The From header addresses.
	From []*Address
	// The message senders.
	Sender []*Address
	// The Reply-To header addresses.
	ReplyTo []*Address
	// The To header addresses.
	To []*Address
	// The Cc header addresses.
	Cc []*Address
	// The Bcc header addresses.
	Bcc []*Address
	// The In-Reply-To header. Contains the parent Message-Id.
	InReplyTo string
	// The Message-Id header.
	MessageId string
}
    A message envelope, ie. message metadata from its headers. See RFC 3501 page
    77.

func (e *Envelope) Format() (fields []interface{})
    Format an envelope to fields.

func (e *Envelope) Parse(fields []interface{}) error
    Parse an envelope from fields.

type ErrBadSeqSet string
    ErrBadSeqSet is used to report problems with the format of a sequence set
    value.

func (err ErrBadSeqSet) Error() string

type ErrStatusResp struct {
	// Response to send instead of default.
	Resp *StatusResp
}
    ErrStatusResp can be returned by a server.Handler to replace the default
    status response. The response tag must be empty.

    To suppress default response, Resp should be set to nil.

func (err *ErrStatusResp) Error() string

type FetchItem string
    A FetchItem is a message data item that can be fetched.

const (
	// Macros
	FetchAll  FetchItem = "ALL"
	FetchFast FetchItem = "FAST"
	FetchFull FetchItem = "FULL"

	// Items
	FetchBody          FetchItem = "BODY"
	FetchBodyStructure FetchItem = "BODYSTRUCTURE"
	FetchEnvelope      FetchItem = "ENVELOPE"
	FetchFlags         FetchItem = "FLAGS"
	FetchInternalDate  FetchItem = "INTERNALDATE"
	FetchRFC822        FetchItem = "RFC822"
	FetchRFC822Header  FetchItem = "RFC822.HEADER"
	FetchRFC822Size    FetchItem = "RFC822.SIZE"
	FetchRFC822Text    FetchItem = "RFC822.TEXT"
	FetchUid           FetchItem = "UID"
)
    List of items that can be fetched.

func (item FetchItem) Expand() []FetchItem
    Expand expands the item if it's a macro.

type FlagsOp string
    FlagsOp is an operation that will be applied on message flags.

type Literal interface {
	io.Reader

	// Len returns the number of bytes of the literal.
	Len() int
}
    A literal, as defined in RFC 3501 section 4.3.

type LiteralLengthErr struct {
	Actual   int
	Expected int
}
    LiteralLengthErr is returned when the Len() of the Literal object does not
    match the actual length of the byte stream.

func (e LiteralLengthErr) Error() string

type LockedWriter struct {
	// Has unexported fields.
}

func (w *LockedWriter) Write(b []byte) (int, error)

type Logger interface {
	Printf(format string, v ...interface{})
	Println(v ...interface{})
}
    Logger is the behaviour used by server/client to report errors for accepting
    connections and unexpected behavior from handlers.

type MailboxInfo struct {
	// The mailbox attributes.
	Attributes []string
	// The server's path separator.
	Delimiter string
	// The mailbox name.
	Name string
}
    Basic mailbox info.

func (info *MailboxInfo) Format() []interface{}
    Format mailbox info to fields.

func (info *MailboxInfo) Match(reference, pattern string) bool
    Match checks if a reference and a pattern matches this mailbox name,
    as defined in RFC 3501 section 6.3.8.

func (info *MailboxInfo) Parse(fields []interface{}) error
    Parse mailbox info from fields.

type MailboxStatus struct {
	// The mailbox name.
	Name string
	// True if the mailbox is open in read-only mode.
	ReadOnly bool
	// The mailbox items that are currently filled in. This map's values
	// should not be used directly, they must only be used by libraries
	// implementing extensions of the IMAP protocol.
	Items map[StatusItem]interface{}

	// The Items map may be accessed in different goroutines. Protect
	// concurrent writes.
	ItemsLocker sync.Mutex

	// The mailbox flags.
	Flags []string
	// The mailbox permanent flags.
	PermanentFlags []string
	// The sequence number of the first unseen message in the mailbox.
	UnseenSeqNum uint32

	// The number of messages in this mailbox.
	Messages uint32
	// The number of messages not seen since the last time the mailbox was opened.
	Recent uint32
	// The number of unread messages.
	Unseen uint32
	// The next UID.
	UidNext uint32
	// Together with a UID, it is a unique identifier for a message.
	// Must be greater than or equal to 1.
	UidValidity uint32

	// Per-mailbox limit of message size. Set only if server supports the
	// APPENDLIMIT extension.
	AppendLimit uint32
}
    A mailbox status.

func NewMailboxStatus(name string, items []StatusItem) *MailboxStatus
    Create a new mailbox status that will contain the specified items.

func (status *MailboxStatus) Format() []interface{}

func (status *MailboxStatus) Parse(fields []interface{}) error

type Message struct {
	// The message sequence number. It must be greater than or equal to 1.
	SeqNum uint32
	// The mailbox items that are currently filled in. This map's values
	// should not be used directly, they must only be used by libraries
	// implementing extensions of the IMAP protocol.
	Items map[FetchItem]interface{}

	// The message envelope.
	Envelope *Envelope
	// The message body structure (either BODYSTRUCTURE or BODY).
	BodyStructure *BodyStructure
	// The message flags.
	Flags []string
	// The date the message was received by the server.
	InternalDate time.Time
	// The message size.
	Size uint32
	// The message unique identifier. It must be greater than or equal to 1.
	Uid uint32
	// The message body sections.
	Body map[*BodySectionName]Literal

	// Has unexported fields.
}
    A message.

func NewMessage(seqNum uint32, items []FetchItem) *Message
    Create a new empty message that will contain the specified items.

func (m *Message) Format() []interface{}

func (m *Message) GetBody(section *BodySectionName) Literal
    GetBody gets the body section with the specified name. Returns nil if it's
    not found.

func (m *Message) Parse(fields []interface{}) error
    Parse a message from fields.

type Parser interface {
	Parse(fields []interface{}) error
}

type PartSpecifier string
    A PartSpecifier specifies which parts of the MIME entity should be returned.

type RawString string
    A raw string.

type Reader struct {
	MaxLiteralSize uint32 // The maximum literal size.

	// Has unexported fields.
}
    An IMAP reader.

func NewReader(r reader) *Reader

func NewServerReader(r reader, continues chan<- bool) *Reader

func (r *Reader) ReadAtom() (interface{}, error)

func (r *Reader) ReadCrlf() (err error)

func (r *Reader) ReadFields() (fields []interface{}, err error)

func (r *Reader) ReadInfo() (info string, err error)

func (r *Reader) ReadLine() (fields []interface{}, err error)

func (r *Reader) ReadList() (fields []interface{}, err error)

func (r *Reader) ReadLiteral() (Literal, error)

func (r *Reader) ReadQuotedString() (string, error)

func (r *Reader) ReadRespCode() (code StatusRespCode, fields []interface{}, err error)

func (r *Reader) ReadSp() error

type Resp interface {
	// Has unexported methods.
}
    Resp is an IMAP response. It is either a *DataResp, a *ContinuationReq or a
    *StatusResp.

type SearchCriteria struct {
	SeqNum *SeqSet // Sequence number is in sequence set
	Uid    *SeqSet // UID is in sequence set

	// Time and timezone are ignored
	Since      time.Time // Internal date is since this date
	Before     time.Time // Internal date is before this date
	SentSince  time.Time // Date header field is since this date
	SentBefore time.Time // Date header field is before this date

	Header textproto.MIMEHeader // Each header field value is present
	Body   []string             // Each string is in the body
	Text   []string             // Each string is in the text (header + body)

	WithFlags    []string // Each flag is present
	WithoutFlags []string // Each flag is not present

	Larger  uint32 // Size is larger than this number
	Smaller uint32 // Size is smaller than this number

	Not []*SearchCriteria    // Each criteria doesn't match
	Or  [][2]*SearchCriteria // Each criteria pair has at least one match of two
}
    SearchCriteria is a search criteria. A message matches the criteria if and
    only if it matches each one of its fields.

func NewSearchCriteria() *SearchCriteria
    NewSearchCriteria creates a new search criteria.

func (c *SearchCriteria) Format() []interface{}
    Format formats search criteria to fields. UTF-8 is used.

func (c *SearchCriteria) ParseWithCharset(fields []interface{}, charsetReader func(io.Reader) io.Reader) error
    ParseWithCharset parses a search criteria from the provided fields.
    charsetReader is an optional function that converts from the fields charset
    to UTF-8.

type Seq struct {
	Start, Stop uint32
}
    Seq represents a single seq-number or seq-range value (RFC 3501 ABNF).
    Values may be static (e.g. "1", "2:4") or dynamic (e.g. "*", "1:*").
    A seq-number is represented by setting Start = Stop. Zero is used to
    represent "*", which is safe because seq-number uses nz-number rule.
    The order of values is always Start <= Stop, except when representing "n:*",
    where Start = n and Stop = 0.

func (s Seq) Contains(q uint32) bool
    Contains returns true if the seq-number q is contained in sequence value s.
    The dynamic value "*" contains only other "*" values, the dynamic range
    "n:*" contains "*" and all numbers >= n.

func (s Seq) Less(q uint32) bool
    Less returns true if s precedes and does not contain seq-number q.

func (s Seq) Merge(t Seq) (union Seq, ok bool)
    Merge combines sequence values s and t into a single union if the two
    intersect or one is a superset of the other. The order of s and t does not
    matter. If the values cannot be merged, s is returned unmodified and ok is
    set to false.

func (s Seq) String() string
    String returns sequence value s as a seq-number or seq-range string.

type SeqSet struct {
	Set []Seq
}
    SeqSet is used to represent a set of message sequence numbers or UIDs (see
    sequence-set ABNF rule). The zero value is an empty set.

func (s *SeqSet) Add(set string) error
    Add inserts new sequence values into the set. The string format is described
    by RFC 3501 sequence-set ABNF rule. If an error is encountered, all values
    inserted successfully prior to the error remain in the set.

func (s *SeqSet) AddNum(q ...uint32)
    AddNum inserts new sequence numbers into the set. The value 0 represents
    "*".

func (s *SeqSet) AddRange(Start, Stop uint32)
    AddRange inserts a new sequence range into the set.

func (s *SeqSet) AddSet(t *SeqSet)
    AddSet inserts all values from t into s.

func (s *SeqSet) Clear()
    Clear removes all values from the set.

func (s SeqSet) Contains(q uint32) bool
    Contains returns true if the non-zero sequence number or UID q is contained
    in the set. The dynamic range "n:*" contains all q >= n. It is the caller's
    responsibility to handle the special case where q is the maximum UID in the
    mailbox and q < n (i.e. the set cannot match UIDs against "*:n" or "*" since
    it doesn't know what the maximum value is).

func (s SeqSet) Dynamic() bool
    Dynamic returns true if the set contains "*" or "n:*" values.

func (s SeqSet) Empty() bool
    Empty returns true if the sequence set does not contain any values.

func (s SeqSet) String() string
    String returns a sorted representation of all contained sequence values.

type StatusItem string
    A StatusItem is a mailbox status data item that can be retrieved with a
    STATUS command. See RFC 3501 section 6.3.10.

const (
	StatusMessages    StatusItem = "MESSAGES"
	StatusRecent      StatusItem = "RECENT"
	StatusUidNext     StatusItem = "UIDNEXT"
	StatusUidValidity StatusItem = "UIDVALIDITY"
	StatusUnseen      StatusItem = "UNSEEN"

	StatusAppendLimit StatusItem = "APPENDLIMIT"
)
type StatusResp struct {
	// The response tag. If empty, it defaults to *.
	Tag string
	// The status type.
	Type StatusRespType
	// The status code.
	// See https://www.iana.org/assignments/imap-response-codes/imap-response-codes.xhtml
	Code StatusRespCode
	// Arguments provided with the status code.
	Arguments []interface{}
	// The status info.
	Info string
}
    A status response. See RFC 3501 section 7.1

func (r *StatusResp) Err() error
    If this status is NO or BAD, returns an error with the status info.
    Otherwise, returns nil.

func (r *StatusResp) WriteTo(w *Writer) error

type StatusRespCode string

const (
	CodeAlert          StatusRespCode = "ALERT"
	CodeBadCharset     StatusRespCode = "BADCHARSET"
	CodeCapability     StatusRespCode = "CAPABILITY"
	CodeParse          StatusRespCode = "PARSE"
	CodePermanentFlags StatusRespCode = "PERMANENTFLAGS"
	CodeReadOnly       StatusRespCode = "READ-ONLY"
	CodeReadWrite      StatusRespCode = "READ-WRITE"
	CodeTryCreate      StatusRespCode = "TRYCREATE"
	CodeUidNext        StatusRespCode = "UIDNEXT"
	CodeUidValidity    StatusRespCode = "UIDVALIDITY"
	CodeUnseen         StatusRespCode = "UNSEEN"
)
    Status response codes defined in RFC 3501 section 7.1.

type StatusRespType string
    A status response type.

const (
	// The OK response indicates an information message from the server.  When
	// tagged, it indicates successful completion of the associated command.
	// The untagged form indicates an information-only message.
	StatusRespOk StatusRespType = "OK"

	// The NO response indicates an operational error message from the
	// server.  When tagged, it indicates unsuccessful completion of the
	// associated command.  The untagged form indicates a warning; the
	// command can still complete successfully.
	StatusRespNo StatusRespType = "NO"

	// The BAD response indicates an error message from the server.  When
	// tagged, it reports a protocol-level error in the client's command;
	// the tag indicates the command that caused the error.  The untagged
	// form indicates a protocol-level error for which the associated
	// command can not be determined; it can also indicate an internal
	// server failure.
	StatusRespBad StatusRespType = "BAD"

	// The PREAUTH response is always untagged, and is one of three
	// possible greetings at connection startup.  It indicates that the
	// connection has already been authenticated by external means; thus
	// no LOGIN command is needed.
	StatusRespPreauth StatusRespType = "PREAUTH"

	// The BYE response is always untagged, and indicates that the server
	// is about to close the connection.
	StatusRespBye StatusRespType = "BYE"
)
    Status response types defined in RFC 3501 section 7.1.

type StoreItem string
    A StoreItem is a message data item that can be updated.

func FormatFlagsOp(op FlagsOp, silent bool) StoreItem
    FormatFlagsOp returns the StoreItem that executes the flags operation op.

type StringReader interface {
	// ReadString reads until the first occurrence of delim in the input,
	// returning a string containing the data up to and including the delimiter.
	// See https://golang.org/pkg/bufio/#Reader.ReadString
	ReadString(delim byte) (line string, err error)
}
    A string reader.

type Waiter struct {
	// Has unexported fields.
}

func NewWaiter() *Waiter

func (w *Waiter) Close()

func (w *Waiter) Wait()

func (w *Waiter) WaitReady()

type Writer struct {
	io.Writer

	AllowAsyncLiterals bool

	// Has unexported fields.
}
    An IMAP writer.

func NewClientWriter(w io.Writer, continues <-chan bool) *Writer

func NewWriter(w io.Writer) *Writer

func (w *Writer) Flush() error

type WriterTo interface {
	WriteTo(w *Writer) error
}

package client // import "github.com/emersion/go-imap/client"

Package client provides an IMAP client.

It is not safe to use the same Client from multiple goroutines. In general,
the IMAP protocol doesn't make it possible to send multiple independent IMAP
commands on the same connection.

VARIABLES

var (
	// ErrAlreadyLoggedIn is returned if Login or Authenticate is called when the
	// client is already logged in.
	ErrAlreadyLoggedIn = errors.New("Already logged in")
	// ErrTLSAlreadyEnabled is returned if StartTLS is called when TLS is already
	// enabled.
	ErrTLSAlreadyEnabled = errors.New("TLS is already enabled")
	// ErrLoginDisabled is returned if Login or Authenticate is called when the
	// server has disabled authentication. Most of the time, calling enabling TLS
	// solves the problem.
	ErrLoginDisabled = errors.New("Login is disabled in current state")
)
var (
	// ErrNoMailboxSelected is returned if a command that requires a mailbox to be
	// selected is called when there isn't.
	ErrNoMailboxSelected = errors.New("No mailbox selected")

	// ErrExtensionUnsupported is returned if a command uses a extension that
	// is not supported by the server.
	ErrExtensionUnsupported = errors.New("The required extension is not supported by the server")
)
var ErrAlreadyLoggedOut = errors.New("Already logged out")
    ErrAlreadyLoggedOut is returned if Logout is called when the client is
    already logged out.

var ErrNotLoggedIn = errors.New("Not logged in")
    ErrNotLoggedIn is returned if a function that requires the client to be
    logged in is called then the client isn't.


TYPES

type Client struct {

	// A channel to which unilateral updates from the server will be sent. An
	// update can be one of: *StatusUpdate, *MailboxUpdate, *MessageUpdate,
	// *ExpungeUpdate. Note that blocking this channel blocks the whole client,
	// so it's recommended to use a separate goroutine and a buffered channel to
	// prevent deadlocks.
	Updates chan<- Update

	// ErrorLog specifies an optional logger for errors accepting connections and
	// unexpected behavior from handlers. By default, logging goes to os.Stderr
	// via the log package's standard logger. The logger must be safe to use
	// simultaneously from multiple goroutines.
	ErrorLog imap.Logger

	// Timeout specifies a maximum amount of time to wait on a command.
	//
	// A Timeout of zero means no timeout. This is the default.
	Timeout time.Duration
	// Has unexported fields.
}
    Client is an IMAP client.

func Dial(addr string) (*Client, error)
    Dial connects to an IMAP server using an unencrypted connection.

func DialTLS(addr string, tlsConfig *tls.Config) (*Client, error)
    DialTLS connects to an IMAP server using an encrypted connection.

func DialWithDialer(dialer Dialer, addr string) (*Client, error)
    DialWithDialer connects to an IMAP server using an unencrypted connection
    using dialer.Dial.

    Among other uses, this allows to apply a dial timeout.

func DialWithDialerTLS(dialer Dialer, addr string, tlsConfig *tls.Config) (*Client, error)
    DialWithDialerTLS connects to an IMAP server using an encrypted connection
    using dialer.Dial.

    Among other uses, this allows to apply a dial timeout.

func New(conn net.Conn) (*Client, error)
    New creates a new client from an existing connection.

func (c *Client) Append(mbox string, flags []string, date time.Time, msg imap.Literal) error
    Append appends the literal argument as a new message to the end of the
    specified destination mailbox. This argument SHOULD be in the format of an
    RFC 2822 message. flags and date are optional arguments and can be set to
    nil and the empty struct.

func (c *Client) Authenticate(auth sasl.Client) error
    Authenticate indicates a SASL authentication mechanism to the server.
    If the server supports the requested authentication mechanism, it performs
    an authentication protocol exchange to authenticate and identify the client.

func (c *Client) Capability() (map[string]bool, error)
    Capability requests a listing of capabilities that the server supports.
    Capabilities are often returned by the server with the greeting or with the
    STARTTLS and LOGIN responses, so usually explicitly requesting capabilities
    isn't needed.

    Most of the time, Support should be used instead.

func (c *Client) Check() error
    Check requests a checkpoint of the currently selected mailbox. A checkpoint
    refers to any implementation-dependent housekeeping associated with the
    mailbox that is not normally executed as part of each command.

func (c *Client) Close() error
    Close permanently removes all messages that have the \Deleted flag set from
    the currently selected mailbox, and returns to the authenticated state from
    the selected state.

func (c *Client) Copy(seqset *imap.SeqSet, dest string) error
    Copy copies the specified message(s) to the end of the specified destination
    mailbox.

func (c *Client) Create(name string) error
    Create creates a mailbox with the given name.

func (c *Client) Delete(name string) error
    Delete permanently removes the mailbox with the given name.

func (c *Client) Enable(caps []string) ([]string, error)
    Enable requests the server to enable the named extensions. The extensions
    which were successfully enabled are returned.

    See RFC 5161 section 3.1.

func (c *Client) Execute(cmdr imap.Commander, h responses.Handler) (*imap.StatusResp, error)
    Execute executes a generic command. cmdr is a value that can be converted
    to a raw command and h is a response handler. The function returns when
    the command has completed or failed, in this case err is nil. A non-nil err
    value indicates a network error.

    This function should not be called directly, it must only be used by
    libraries implementing extensions of the IMAP protocol.

func (c *Client) Expunge(ch chan uint32) error
    Expunge permanently removes all messages that have the \Deleted flag set
    from the currently selected mailbox. If ch is not nil, sends sequence IDs of
    each deleted message to this channel.

func (c *Client) Fetch(seqset *imap.SeqSet, items []imap.FetchItem, ch chan *imap.Message) error
    Fetch retrieves data associated with a message in the mailbox. See RFC 3501
    section 6.4.5 for a list of items that can be requested.

func (c *Client) Idle(stop <-chan struct{}, opts *IdleOptions) error
    Idle indicates to the server that the client is ready to receive unsolicited
    mailbox update messages. When the client wants to send commands again,
    it must first close stop.

    If the server doesn't support IDLE, go-imap falls back to polling.

func (c *Client) IsTLS() bool
    IsTLS checks if this client's connection has TLS enabled.

func (c *Client) List(ref, name string, ch chan *imap.MailboxInfo) error
    List returns a subset of names from the complete set of all names available
    to the client.

    An empty name argument is a special request to return the hierarchy
    delimiter and the root name of the name given in the reference.
    The character "*" is a wildcard, and matches zero or more characters at
    this position. The character "%" is similar to "*", but it does not match a
    hierarchy delimiter.

func (c *Client) LoggedOut() <-chan struct{}
    LoggedOut returns a channel which is closed when the connection to the
    server is closed.

func (c *Client) Login(username, password string) error
    Login identifies the client to the server and carries the plaintext password
    authenticating this user.

func (c *Client) Logout() error
    Logout gracefully closes the connection.

func (c *Client) Lsub(ref, name string, ch chan *imap.MailboxInfo) error
    Lsub returns a subset of names from the set of names that the user has
    declared as being "active" or "subscribed".

func (c *Client) Mailbox() *imap.MailboxStatus
    Mailbox returns the selected mailbox. It returns nil if there isn't one.

func (c *Client) Move(seqset *imap.SeqSet, dest string) error
    Move moves the specified message(s) to the end of the specified destination
    mailbox.

    If the server doesn't support the MOVE extension defined in RFC 6851,
    go-imap will fallback to copy, store and expunge.

func (c *Client) Noop() error
    Noop always succeeds and does nothing.

    It can be used as a periodic poll for new messages or message status updates
    during a period of inactivity. It can also be used to reset any inactivity
    autologout timer on the server.

func (c *Client) Rename(existingName, newName string) error
    Rename changes the name of a mailbox.

func (c *Client) Search(criteria *imap.SearchCriteria) (seqNums []uint32, err error)
    Search searches the mailbox for messages that match the given searching
    criteria. Searching criteria consist of one or more search keys.
    The response contains a list of message sequence IDs corresponding to
    those messages that match the searching criteria. When multiple keys are
    specified, the result is the intersection (AND function) of all the messages
    that match those keys. Criteria must be UTF-8 encoded. See RFC 3501 section
    6.4.4 for a list of searching criteria. When no criteria has been set,
    all messages in the mailbox will be searched using ALL criteria.

func (c *Client) Select(name string, readOnly bool) (*imap.MailboxStatus, error)
    Select selects a mailbox so that messages in the mailbox can be accessed.
    Any currently selected mailbox is deselected before attempting the new
    selection. Even if the readOnly parameter is set to false, the server can
    decide to open the mailbox in read-only mode.

func (c *Client) SetDebug(w io.Writer)
    SetDebug defines an io.Writer to which all network activity will be logged.
    If nil is provided, network activity will not be logged.

func (c *Client) SetState(state imap.ConnState, mailbox *imap.MailboxStatus)
    SetState sets this connection's internal state.

    This function should not be called directly, it must only be used by
    libraries implementing extensions of the IMAP protocol.

func (c *Client) StartTLS(tlsConfig *tls.Config) error
    StartTLS starts TLS negotiation.

func (c *Client) State() imap.ConnState
    State returns the current connection state.

func (c *Client) Status(name string, items []imap.StatusItem) (*imap.MailboxStatus, error)
    Status requests the status of the indicated mailbox. It does not change the
    currently selected mailbox, nor does it affect the state of any messages in
    the queried mailbox.

    See RFC 3501 section 6.3.10 for a list of items that can be requested.

func (c *Client) Store(seqset *imap.SeqSet, item imap.StoreItem, value interface{}, ch chan *imap.Message) error
    Store alters data associated with a message in the mailbox. If ch is not
    nil, the updated value of the data will be sent to this channel. See RFC
    3501 section 6.4.6 for a list of items that can be updated.

func (c *Client) Subscribe(name string) error
    Subscribe adds the specified mailbox name to the server's set of "active" or
    "subscribed" mailboxes.

func (c *Client) Support(cap string) (bool, error)
    Support checks if cap is a capability supported by the server. If the server
    hasn't sent its capabilities yet, Support requests them.

func (c *Client) SupportAuth(mech string) (bool, error)
    SupportAuth checks if the server supports a given authentication mechanism.

func (c *Client) SupportStartTLS() (bool, error)
    SupportStartTLS checks if the server supports STARTTLS.

func (c *Client) Terminate() error
    Terminate closes the tcp connection

func (c *Client) UidCopy(seqset *imap.SeqSet, dest string) error
    UidCopy is identical to Copy, but seqset is interpreted as containing unique
    identifiers instead of message sequence numbers.

func (c *Client) UidFetch(seqset *imap.SeqSet, items []imap.FetchItem, ch chan *imap.Message) error
    UidFetch is identical to Fetch, but seqset is interpreted as containing
    unique identifiers instead of message sequence numbers.

func (c *Client) UidMove(seqset *imap.SeqSet, dest string) error
    UidMove is identical to Move, but seqset is interpreted as containing unique
    identifiers instead of message sequence numbers.

func (c *Client) UidSearch(criteria *imap.SearchCriteria) (uids []uint32, err error)
    UidSearch is identical to Search, but UIDs are returned instead of message
    sequence numbers.

func (c *Client) UidStore(seqset *imap.SeqSet, item imap.StoreItem, value interface{}, ch chan *imap.Message) error
    UidStore is identical to Store, but seqset is interpreted as containing
    unique identifiers instead of message sequence numbers.

func (c *Client) Unselect() error
    Unselect frees server's resources associated with the selected mailbox and
    returns the server to the authenticated state. This command performs the
    same actions as Close, except that no messages are permanently removed from
    the currently selected mailbox.

    If client does not support the UNSELECT extension, ErrExtensionUnsupported
    is returned.

func (c *Client) Unsubscribe(name string) error
    Unsubscribe removes the specified mailbox name from the server's set of
    "active" or "subscribed" mailboxes.

func (c *Client) Upgrade(upgrader imap.ConnUpgrader) error
    Upgrade a connection, e.g. wrap an unencrypted connection with an encrypted
    tunnel.

    This function should not be called directly, it must only be used by
    libraries implementing extensions of the IMAP protocol.

func (c *Client) Writer() *imap.Writer
    Writer returns the imap.Writer for this client's connection.

    This function should not be called directly, it must only be used by
    libraries implementing extensions of the IMAP protocol.

type Dialer interface {
	// Dial connects to the given address.
	Dial(network, addr string) (net.Conn, error)
}

type ExpungeUpdate struct {
	SeqNum uint32
}
    ExpungeUpdate is delivered when a message is deleted.

type IdleOptions struct {
	// LogoutTimeout is used to avoid being logged out by the server when
	// idling. Each LogoutTimeout, the IDLE command is restarted. If set to
	// zero, a default is used. If negative, this behavior is disabled.
	LogoutTimeout time.Duration
	// Poll interval when the server doesn't support IDLE. If zero, a default
	// is used. If negative, polling is always disabled.
	PollInterval time.Duration
}
    IdleOptions holds options for Client.Idle.

type MailboxUpdate struct {
	Mailbox *imap.MailboxStatus
}
    MailboxUpdate is delivered when a mailbox status changes.

type MessageUpdate struct {
	Message *imap.Message
}
    MessageUpdate is delivered when a message attribute changes.

type StatusUpdate struct {
	Status *imap.StatusResp
}
    StatusUpdate is delivered when a status update is received.

type Update interface {
	// Has unexported methods.
}
    Update is an unilateral server update.

