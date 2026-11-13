package websocket // import "github.com/gorilla/websocket"

Package websocket implements the WebSocket protocol defined in RFC 6455.

# Overview

The Conn type represents a WebSocket connection. A server application calls the
Upgrader.Upgrade method from an HTTP request handler to get a *Conn:

    var upgrader = websocket.Upgrader{
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
    }

    func handler(w http.ResponseWriter, r *http.Request) {
        conn, err := upgrader.Upgrade(w, r, nil)
        if err != nil {
            log.Println(err)
            return
        }
        ... Use conn to send and receive messages.
    }

Call the connection's WriteMessage and ReadMessage methods to send and receive
messages as a slice of bytes. This snippet of code shows how to echo messages
using these methods:

    for {
        messageType, p, err := conn.ReadMessage()
        if err != nil {
            log.Println(err)
            return
        }
        if err := conn.WriteMessage(messageType, p); err != nil {
            log.Println(err)
            return
        }
    }

In above snippet of code, p is a []byte and messageType is an int with value
websocket.BinaryMessage or websocket.TextMessage.

An application can also send and receive messages using the io.WriteCloser and
io.Reader interfaces. To send a message, call the connection NextWriter method
to get an io.WriteCloser, write the message to the writer and close the writer
when done. To receive a message, call the connection NextReader method to get
an io.Reader and read until io.EOF is returned. This snippet shows how to echo
messages using the NextWriter and NextReader methods:

    for {
        messageType, r, err := conn.NextReader()
        if err != nil {
            return
        }
        w, err := conn.NextWriter(messageType)
        if err != nil {
            return err
        }
        if _, err := io.Copy(w, r); err != nil {
            return err
        }
        if err := w.Close(); err != nil {
            return err
        }
    }

# Data Messages

The WebSocket protocol distinguishes between text and binary data messages.
Text messages are interpreted as UTF-8 encoded text. The interpretation of
binary messages is left to the application.

This package uses the TextMessage and BinaryMessage integer constants to
identify the two data message types. The ReadMessage and NextReader methods
return the type of the received message. The messageType argument to the
WriteMessage and NextWriter methods specifies the type of a sent message.

It is the application's responsibility to ensure that text messages are valid
UTF-8 encoded text.

# Control Messages

The WebSocket protocol defines three types of control messages: close, ping and
pong. Call the connection WriteControl, WriteMessage or NextWriter methods to
send a control message to the peer.

Connections handle received close messages by calling the handler function
set with the SetCloseHandler method and by returning a *CloseError from the
NextReader, ReadMessage or the message Read method. The default close handler
sends a close message to the peer.

Connections handle received ping messages by calling the handler function set
with the SetPingHandler method. The default ping handler sends a pong message to
the peer.

Connections handle received pong messages by calling the handler function set
with the SetPongHandler method. The default pong handler does nothing. If an
application sends ping messages, then the application should set a pong handler
to receive the corresponding pong.

The control message handler functions are called from the NextReader,
ReadMessage and message reader Read methods. The default close and ping
handlers can block these methods for a short time when the handler writes to the
connection.

The application must read the connection to process close, ping and pong
messages sent from the peer. If the application is not otherwise interested in
messages from the peer, then the application should start a goroutine to read
and discard messages from the peer. A simple example is:

    func readLoop(c *websocket.Conn) {
        for {
            if _, _, err := c.NextReader(); err != nil {
                c.Close()
                break
            }
        }
    }

# Concurrency

Connections support one concurrent reader and one concurrent writer.

Applications are responsible for ensuring that no more than one goroutine
calls the write methods (NextWriter, SetWriteDeadline, WriteMessage, WriteJSON,
EnableWriteCompression, SetCompressionLevel) concurrently and that no more than
one goroutine calls the read methods (NextReader, SetReadDeadline, ReadMessage,
ReadJSON, SetPongHandler, SetPingHandler) concurrently.

The Close and WriteControl methods can be called concurrently with all other
methods.

# Origin Considerations

Web browsers allow Javascript applications to open a WebSocket connection to any
host. It's up to the server to enforce an origin policy using the Origin request
header sent by the browser.

The Upgrader calls the function specified in the CheckOrigin field to check the
origin. If the CheckOrigin function returns false, then the Upgrade method fails
the WebSocket handshake with HTTP status 403.

If the CheckOrigin field is nil, then the Upgrader uses a safe default: fail
the handshake if the Origin request header is present and the Origin host is not
equal to the Host request header.

The deprecated package-level Upgrade function does not perform origin checking.
The application is responsible for checking the Origin header before calling the
Upgrade function.

# Buffers

Connections buffer network input and output to reduce the number of system calls
when reading or writing messages.

Write buffers are also used for constructing WebSocket frames. See RFC 6455,
Section 5 for a discussion of message framing. A WebSocket frame header is
written to the network each time a write buffer is flushed to the network.
Decreasing the size of the write buffer can increase the amount of framing
overhead on the connection.

The buffer sizes in bytes are specified by the ReadBufferSize and
WriteBufferSize fields in the Dialer and Upgrader. The Dialer uses a default
size of 4096 when a buffer size field is set to zero. The Upgrader reuses
buffers created by the HTTP server when a buffer size field is set to zero.
The HTTP server buffers have a size of 4096 at the time of this writing.

The buffer sizes do not limit the size of a message that can be read or written
by a connection.

Buffers are held for the lifetime of the connection by default. If the Dialer or
Upgrader WriteBufferPool field is set, then a connection holds the write buffer
only when writing a message.

Applications should tune the buffer sizes to balance memory use and performance.
Increasing the buffer size uses more memory, but can reduce the number of system
calls to read or write the network. In the case of writing, increasing the
buffer size can reduce the number of frame headers written to the network.

Some guidelines for setting buffer parameters are:

Limit the buffer sizes to the maximum expected message size. Buffers larger than
the largest message do not provide any benefit.

Depending on the distribution of message sizes, setting the buffer size to a
value less than the maximum expected message size can greatly reduce memory use
with a small impact on performance. Here's an example: If 99% of the messages
are smaller than 256 bytes and the maximum message size is 512 bytes, then a
buffer size of 256 bytes will result in 1.01 more system calls than a buffer
size of 512 bytes. The memory savings is 50%.

A write buffer pool is useful when the application has a modest number writes
over a large number of connections. when buffers are pooled, a larger buffer
size has a reduced impact on total memory use and has the benefit of reducing
system calls and frame overhead.

# Compression EXPERIMENTAL

Per message compression extensions (RFC 7692) are experimentally supported by
this package in a limited capacity. Setting the EnableCompression option to true
in Dialer or Upgrader will attempt to negotiate per message deflate support.

    var upgrader = websocket.Upgrader{
        EnableCompression: true,
    }

If compression was successfully negotiated with the connection's peer,
any message received in compressed form will be automatically decompressed.
All Read methods will return uncompressed bytes.

Per message compression of messages written to a connection can be enabled or
disabled by calling the corresponding Conn method:

    conn.EnableWriteCompression(false)

Currently this package does not support compression with "context takeover".
This means that messages must be compressed and decompressed in isolation,
without retaining sliding window or dictionary state across messages. For more
details refer to RFC 7692.

Use of compression is experimental and may result in decreased performance.

CONSTANTS

const (
	CloseNormalClosure           = 1000
	CloseGoingAway               = 1001
	CloseProtocolError           = 1002
	CloseUnsupportedData         = 1003
	CloseNoStatusReceived        = 1005
	CloseAbnormalClosure         = 1006
	CloseInvalidFramePayloadData = 1007
	ClosePolicyViolation         = 1008
	CloseMessageTooBig           = 1009
	CloseMandatoryExtension      = 1010
	CloseInternalServerErr       = 1011
	CloseServiceRestart          = 1012
	CloseTryAgainLater           = 1013
	CloseTLSHandshake            = 1015
)
    Close codes defined in RFC 6455, section 11.7.

const (
	// TextMessage denotes a text data message. The text message payload is
	// interpreted as UTF-8 encoded text data.
	TextMessage = 1

	// BinaryMessage denotes a binary data message.
	BinaryMessage = 2

	// CloseMessage denotes a close control message. The optional message
	// payload contains a numeric code and text. Use the FormatCloseMessage
	// function to format a close message payload.
	CloseMessage = 8

	// PingMessage denotes a ping control message. The optional message payload
	// is UTF-8 encoded text.
	PingMessage = 9

	// PongMessage denotes a pong control message. The optional message payload
	// is UTF-8 encoded text.
	PongMessage = 10
)
    The message types are defined in RFC 6455, section 11.8.


VARIABLES

var DefaultDialer = &Dialer{
	Proxy:            http.ProxyFromEnvironment,
	HandshakeTimeout: 45 * time.Second,
}
    DefaultDialer is a dialer with all fields set to the default values.

var ErrBadHandshake = errors.New("websocket: bad handshake")
    ErrBadHandshake is returned when the server response to opening handshake is
    invalid.

var ErrCloseSent = errors.New("websocket: close sent")
    ErrCloseSent is returned when the application writes a message to the
    connection after sending a close message.

var ErrReadLimit = errors.New("websocket: read limit exceeded")
    ErrReadLimit is returned when reading a message that is larger than the read
    limit set for the connection.


FUNCTIONS

func FormatCloseMessage(closeCode int, text string) []byte
    FormatCloseMessage formats closeCode and text as a WebSocket close message.
    An empty message is returned for code CloseNoStatusReceived.

func IsCloseError(err error, codes ...int) bool
    IsCloseError returns boolean indicating whether the error is a *CloseError
    with one of the specified codes.

func IsUnexpectedCloseError(err error, expectedCodes ...int) bool
    IsUnexpectedCloseError returns boolean indicating whether the error is a
    *CloseError with a code not in the list of expected codes.

func IsWebSocketUpgrade(r *http.Request) bool
    IsWebSocketUpgrade returns true if the client requested upgrade to the
    WebSocket protocol.

func JoinMessages(c *Conn, term string) io.Reader
    JoinMessages concatenates received messages to create a single io.Reader.
    The string term is appended to each message. The returned reader does not
    support concurrent calls to the Read method.

func ReadJSON(c *Conn, v interface{}) error
    ReadJSON reads the next JSON-encoded message from the connection and stores
    it in the value pointed to by v.

    Deprecated: Use c.ReadJSON instead.

func Subprotocols(r *http.Request) []string
    Subprotocols returns the subprotocols requested by the client in the
    Sec-Websocket-Protocol header.

func WriteJSON(c *Conn, v interface{}) error
    WriteJSON writes the JSON encoding of v as a message.

    Deprecated: Use c.WriteJSON instead.


TYPES

type BufferPool interface {
	// Get gets a value from the pool or returns nil if the pool is empty.
	Get() interface{}
	// Put adds a value to the pool.
	Put(interface{})
}
    BufferPool represents a pool of buffers. The *sync.Pool type satisfies this
    interface. The type of the value stored in a pool is not specified.

type CloseError struct {
	// Code is defined in RFC 6455, section 11.7.
	Code int

	// Text is the optional text payload.
	Text string
}
    CloseError represents a close message.

func (e *CloseError) Error() string

type Conn struct {
	// Has unexported fields.
}
    The Conn type represents a WebSocket connection.

func NewClient(netConn net.Conn, u *url.URL, requestHeader http.Header, readBufSize, writeBufSize int) (c *Conn, response *http.Response, err error)
    NewClient creates a new client connection using the given net connection.
    The URL u specifies the host and request URI. Use requestHeader to
    specify the origin (Origin), subprotocols (Sec-WebSocket-Protocol) and
    cookies (Cookie). Use the response.Header to get the selected subprotocol
    (Sec-WebSocket-Protocol) and cookies (Set-Cookie).

    If the WebSocket handshake fails, ErrBadHandshake is returned along with a
    non-nil *http.Response so that callers can handle redirects, authentication,
    etc.

    Deprecated: Use Dialer instead.

func Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header, readBufSize, writeBufSize int) (*Conn, error)
    Upgrade upgrades the HTTP server connection to the WebSocket protocol.

    Deprecated: Use websocket.Upgrader instead.

    Upgrade does not perform origin checking. The application is responsible for
    checking the Origin header before calling Upgrade. An example implementation
    of the same origin policy check is:

        if req.Header.Get("Origin") != "http://"+req.Host {
        	http.Error(w, "Origin not allowed", http.StatusForbidden)
        	return
        }

    If the endpoint supports subprotocols, then the application is responsible
    for negotiating the protocol used on the connection. Use the Subprotocols()
    function to get the subprotocols requested by the client. Use the
    Sec-Websocket-Protocol response header to specify the subprotocol selected
    by the application.

    The responseHeader is included in the response to the client's upgrade
    request. Use the responseHeader to specify cookies (Set-Cookie) and the
    negotiated subprotocol (Sec-Websocket-Protocol).

    The connection buffers IO to the underlying network connection. The
    readBufSize and writeBufSize parameters specify the size of the buffers to
    use. Messages can be larger than the buffers.

    If the request is not a valid WebSocket handshake, then Upgrade returns
    an error of type HandshakeError. Applications should handle this error by
    replying to the client with an HTTP error response.

func (c *Conn) Close() error
    Close closes the underlying network connection without sending or waiting
    for a close message.

func (c *Conn) CloseHandler() func(code int, text string) error
    CloseHandler returns the current close handler

func (c *Conn) EnableWriteCompression(enable bool)
    EnableWriteCompression enables and disables write compression of subsequent
    text and binary messages. This function is a noop if compression was not
    negotiated with the peer.

func (c *Conn) LocalAddr() net.Addr
    LocalAddr returns the local network address.

func (c *Conn) NetConn() net.Conn
    NetConn returns the underlying connection that is wrapped by c. Note that
    writing to or reading from this connection directly will corrupt the
    WebSocket connection.

func (c *Conn) NextReader() (messageType int, r io.Reader, err error)
    NextReader returns the next data message received from the peer. The
    returned messageType is either TextMessage or BinaryMessage.

    There can be at most one open reader on a connection. NextReader discards
    the previous message if the application has not already consumed it.

    Applications must break out of the application's read loop when this
    method returns a non-nil error value. Errors returned from this method are
    permanent. Once this method returns a non-nil error, all subsequent calls to
    this method return the same error.

func (c *Conn) NextWriter(messageType int) (io.WriteCloser, error)
    NextWriter returns a writer for the next message to send. The writer's Close
    method flushes the complete message to the network.

    There can be at most one open writer on a connection. NextWriter closes the
    previous writer if the application has not already done so.

    All message types (TextMessage, BinaryMessage, CloseMessage, PingMessage and
    PongMessage) are supported.

func (c *Conn) PingHandler() func(appData string) error
    PingHandler returns the current ping handler

func (c *Conn) PongHandler() func(appData string) error
    PongHandler returns the current pong handler

func (c *Conn) ReadJSON(v interface{}) error
    ReadJSON reads the next JSON-encoded message from the connection and stores
    it in the value pointed to by v.

    See the documentation for the encoding/json Unmarshal function for details
    about the conversion of JSON to a Go value.

func (c *Conn) ReadMessage() (messageType int, p []byte, err error)
    ReadMessage is a helper method for getting a reader using NextReader and
    reading from that reader to a buffer.

func (c *Conn) RemoteAddr() net.Addr
    RemoteAddr returns the remote network address.

func (c *Conn) SetCloseHandler(h func(code int, text string) error)
    SetCloseHandler sets the handler for close messages received from the peer.
    The code argument to h is the received close code or CloseNoStatusReceived
    if the close message is empty. The default close handler sends a close
    message back to the peer.

    The handler function is called from the NextReader, ReadMessage and message
    reader Read methods. The application must read the connection to process
    close messages as described in the section on Control Messages above.

    The connection read methods return a CloseError when a close message is
    received. Most applications should handle close messages as part of their
    normal error handling. Applications should only set a close handler when the
    application must perform some action before sending a close message back to
    the peer.

func (c *Conn) SetCompressionLevel(level int) error
    SetCompressionLevel sets the flate compression level for subsequent
    text and binary messages. This function is a noop if compression was not
    negotiated with the peer. See the compress/flate package for a description
    of compression levels.

func (c *Conn) SetPingHandler(h func(appData string) error)
    SetPingHandler sets the handler for ping messages received from the peer.
    The appData argument to h is the PING message application data. The default
    ping handler sends a pong to the peer.

    The handler function is called from the NextReader, ReadMessage and message
    reader Read methods. The application must read the connection to process
    ping messages as described in the section on Control Messages above.

func (c *Conn) SetPongHandler(h func(appData string) error)
    SetPongHandler sets the handler for pong messages received from the peer.
    The appData argument to h is the PONG message application data. The default
    pong handler does nothing.

    The handler function is called from the NextReader, ReadMessage and message
    reader Read methods. The application must read the connection to process
    pong messages as described in the section on Control Messages above.

func (c *Conn) SetReadDeadline(t time.Time) error
    SetReadDeadline sets the read deadline on the underlying network connection.
    After a read has timed out, the websocket connection state is corrupt and
    all future reads will return an error. A zero value for t means reads will
    not time out.

func (c *Conn) SetReadLimit(limit int64)
    SetReadLimit sets the maximum size in bytes for a message read from the
    peer. If a message exceeds the limit, the connection sends a close message
    to the peer and returns ErrReadLimit to the application.

func (c *Conn) SetWriteDeadline(t time.Time) error
    SetWriteDeadline sets the write deadline on the underlying network
    connection. After a write has timed out, the websocket state is corrupt and
    all future writes will return an error. A zero value for t means writes will
    not time out.

func (c *Conn) Subprotocol() string
    Subprotocol returns the negotiated protocol for the connection.

func (c *Conn) UnderlyingConn() net.Conn
    UnderlyingConn returns the internal net.Conn. This can be used to further
    modifications to connection specific flags. Deprecated: Use the NetConn
    method.

func (c *Conn) WriteControl(messageType int, data []byte, deadline time.Time) error
    WriteControl writes a control message with the given deadline. The allowed
    message types are CloseMessage, PingMessage and PongMessage.

func (c *Conn) WriteJSON(v interface{}) error
    WriteJSON writes the JSON encoding of v as a message.

    See the documentation for encoding/json Marshal for details about the
    conversion of Go values to JSON.

func (c *Conn) WriteMessage(messageType int, data []byte) error
    WriteMessage is a helper method for getting a writer using NextWriter,
    writing the message and closing the writer.

func (c *Conn) WritePreparedMessage(pm *PreparedMessage) error
    WritePreparedMessage writes prepared message into connection.

type Dialer struct {
	// NetDial specifies the dial function for creating TCP connections. If
	// NetDial is nil, net.Dial is used.
	NetDial func(network, addr string) (net.Conn, error)

	// NetDialContext specifies the dial function for creating TCP connections. If
	// NetDialContext is nil, NetDial is used.
	NetDialContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// NetDialTLSContext specifies the dial function for creating TLS/TCP connections. If
	// NetDialTLSContext is nil, NetDialContext is used.
	// If NetDialTLSContext is set, Dial assumes the TLS handshake is done there and
	// TLSClientConfig is ignored.
	NetDialTLSContext func(ctx context.Context, network, addr string) (net.Conn, error)

	// Proxy specifies a function to return a proxy for a given
	// Request. If the function returns a non-nil error, the
	// request is aborted with the provided error.
	// If Proxy is nil or returns a nil *URL, no proxy is used.
	Proxy func(*http.Request) (*url.URL, error)

	// TLSClientConfig specifies the TLS configuration to use with tls.Client.
	// If nil, the default configuration is used.
	// If either NetDialTLS or NetDialTLSContext are set, Dial assumes the TLS handshake
	// is done there and TLSClientConfig is ignored.
	TLSClientConfig *tls.Config

	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then a useful default size is used. The I/O buffer sizes
	// do not limit the size of the messages that can be sent or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the client's requested subprotocols.
	Subprotocols []string

	// EnableCompression specifies if the client should attempt to negotiate
	// per message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool

	// Jar specifies the cookie jar.
	// If Jar is nil, cookies are not sent in requests and ignored
	// in responses.
	Jar http.CookieJar
}
    A Dialer contains options for connecting to WebSocket server.

    It is safe to call Dialer's methods concurrently.

func (d *Dialer) Dial(urlStr string, requestHeader http.Header) (*Conn, *http.Response, error)
    Dial creates a new client connection by calling DialContext with a
    background context.

func (d *Dialer) DialContext(ctx context.Context, urlStr string, requestHeader http.Header) (*Conn, *http.Response, error)
    DialContext creates a new client connection. Use requestHeader to specify
    the origin (Origin), subprotocols (Sec-WebSocket-Protocol) and cookies
    (Cookie). Use the response.Header to get the selected subprotocol
    (Sec-WebSocket-Protocol) and cookies (Set-Cookie).

    The context will be used in the request and in the Dialer.

    If the WebSocket handshake fails, ErrBadHandshake is returned along with a
    non-nil *http.Response so that callers can handle redirects, authentication,
    etcetera. The response body may not contain the entire response and does not
    need to be closed by the application.

type HandshakeError struct {
	// Has unexported fields.
}
    HandshakeError describes an error with the handshake from the peer.

func (e HandshakeError) Error() string

type PreparedMessage struct {
	// Has unexported fields.
}
    PreparedMessage caches on the wire representations of a message payload.
    Use PreparedMessage to efficiently send a message payload to multiple
    connections. PreparedMessage is especially useful when compression is used
    because the CPU and memory expensive compression operation can be executed
    once for a given set of compression options.

func NewPreparedMessage(messageType int, data []byte) (*PreparedMessage, error)
    NewPreparedMessage returns an initialized PreparedMessage. You can then
    send it to connection using WritePreparedMessage method. Valid wire
    representation will be calculated lazily only once for a set of current
    connection options.

type Upgrader struct {
	// HandshakeTimeout specifies the duration for the handshake to complete.
	HandshakeTimeout time.Duration

	// ReadBufferSize and WriteBufferSize specify I/O buffer sizes in bytes. If a buffer
	// size is zero, then buffers allocated by the HTTP server are used. The
	// I/O buffer sizes do not limit the size of the messages that can be sent
	// or received.
	ReadBufferSize, WriteBufferSize int

	// WriteBufferPool is a pool of buffers for write operations. If the value
	// is not set, then write buffers are allocated to the connection for the
	// lifetime of the connection.
	//
	// A pool is most useful when the application has a modest volume of writes
	// across a large number of connections.
	//
	// Applications should use a single pool for each unique value of
	// WriteBufferSize.
	WriteBufferPool BufferPool

	// Subprotocols specifies the server's supported protocols in order of
	// preference. If this field is not nil, then the Upgrade method negotiates a
	// subprotocol by selecting the first match in this list with a protocol
	// requested by the client. If there's no match, then no protocol is
	// negotiated (the Sec-Websocket-Protocol header is not included in the
	// handshake response).
	Subprotocols []string

	// Error specifies the function for generating HTTP error responses. If Error
	// is nil, then http.Error is used to generate the HTTP response.
	Error func(w http.ResponseWriter, r *http.Request, status int, reason error)

	// CheckOrigin returns true if the request Origin header is acceptable. If
	// CheckOrigin is nil, then a safe default is used: return false if the
	// Origin request header is present and the origin host is not equal to
	// request Host header.
	//
	// A CheckOrigin function should carefully validate the request origin to
	// prevent cross-site request forgery.
	CheckOrigin func(r *http.Request) bool

	// EnableCompression specify if the server should attempt to negotiate per
	// message compression (RFC 7692). Setting this value to true does not
	// guarantee that compression will be supported. Currently only "no context
	// takeover" modes are supported.
	EnableCompression bool
}
    Upgrader specifies parameters for upgrading an HTTP connection to a
    WebSocket connection.

    It is safe to call Upgrader's methods concurrently.

func (u *Upgrader) Upgrade(w http.ResponseWriter, r *http.Request, responseHeader http.Header) (*Conn, error)
    Upgrade upgrades the HTTP server connection to the WebSocket protocol.

    The responseHeader is included in the response to the client's upgrade
    request. Use the responseHeader to specify cookies (Set-Cookie). To specify
    subprotocols supported by the server, set Upgrader.Subprotocols directly.

    If the upgrade fails, then Upgrade replies to the client with an HTTP error
    response.

