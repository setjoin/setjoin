# Scope and case plan (#318)

Ownership: `GET /jmap/ws` (F18 WebSocket push) and the explicitly transferred
`GET /chat/presence` (F12). SSE belongs to #319. Its implementation must use
the same JMAP connection registry, preserving one online count across transports.

| Group | Observable contract |
|---|---|
| Controls | Enable is silent; Disable returns error; unknown types return unknownType; malformed JSON is ignored |
| Handshake | Cookie-only access token, push scope containment, guest satellite belt, revocation, origin, RFC 6455 validation |
| JMAP Request | Response/RequestError projection, batch limits/capabilities, result references, native ported methods and account isolation |
| Mailbox pushes | Four mailbox channels, 20 ms batching, authoritative per-capability state tokens, controls before StateChange |
| App pushes | Self-scoped drive/chat/meet, live permission-gated drive alarms, guest entitlement gates |
| Closure | Disconnect cleanup, all/JTI/family revocation, expiry/permission recheck, device gate, bounded messages and keepalive |
| Presence | Multiple sockets, last disconnect, raw numeric key spellings, invalid IDs, guest co-membership scoping |

The controls case is the initial tracer bullet. Each further group is implemented
with its own frozen-Go recording and red/green replay. No production tokens or
foreign database are used. Default-ON metadata is added only after qualification.
