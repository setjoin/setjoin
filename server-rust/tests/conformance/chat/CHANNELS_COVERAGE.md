# Frozen-Go channel coverage (#267)

Measured from frozen Go `1d9d2b58caa0c73bac2eba9331414c8bf411b1e8` (Go 1.26.6), executable SHA-256
`daa2214c139bf00dcdd3f8ee3fd698f906be9b44723d82ef652e4c254ab1865e`. The unchanged Chat handlers are instrumented with
`-cover -coverpkg=./mailserver/internal/chat,./mailserver/cmd/mailserverd`.
`go tool covdata textfmt` merges the counters from 146 immutable HTTP
recordings; `go tool cover -func` measures Go statements in the unchanged source.
The request pool uses the constrained app credential; no Go source was edited.

| Handler | Go statements covered |
| --- | --- |
| `createChannel` | 100.0% |
| `openDM` | 100.0% |
| `openFederatedDM` | 94.7% |
| `listConversations` | 100.0% |
| `ensureSpace` | 100.0% |
| `browseChannels` | 100.0% |
| `joinChannel` | 100.0% |
| `updateChannel` | 100.0% |
| `previewGuestMember` | 100.0% |
| `addMember` | 100.0% |
| `removeMember` | 100.0% |
| `setChannelNotif` | 100.0% |
| `bindFederation` | 100.0% |
| `inviteFederationMember` | 100.0% |
| `removeFederationMember` | 100.0% |
| `federationRoster` | 100.0% |
| `sendMessage` | 100.0% |
| `listMessages` | 100.0% |
| `sinceMessages` | 100.0% |
| `listPins` | 100.0% |
| `createPoll` | 100.0% |
| `markRead` | 100.0% |
| `typingSignal` | 88.9% |
| `getChannelReaders` | 100.0% |
| `channelRoster` | 100.0% |
| `mentionSearch` | 100.0% |
| `scheduleMessage` | 100.0% |

Twenty-five handlers reach 100%. All handler branches that emit an error status
or call a different reducer are reached within the admitted native scope.
The two remaining handler statements have explicit boundaries:

- `openFederatedDM`'s final 200 writer is unreachable under the canonical
  constrained-app posture: the invoker-rights reducer's channel INSERT is denied
  by channel RLS, including repeated valid requests. The oracle preserves the
  observed 500; malformed input, disabled federation and missing address are
  separately recorded. No owner/worker credential is substituted to fabricate
  a successful recording.
- This measurement predates native transport/enrichment. #347/#418 qualify
  admitted typing through recorded Go frames and real fedharness peers in both
  TLS roles. #418 adds URL-send HTTP/effect goldens plus detached page/image,
  redirect, compression and SSRF worker recordings. No URL-bearing send or
  federated-typing shape remains forwarded. The table retains its original
  measured corpus; integration coverage is rerun by the merge queue.

Registration helpers are fully covered. Other Part B handlers and its process-
local presence registry are outside this slice. Optional-integer helpers retain
unreached positive-value returns; their error writers are covered. Unfurl
admission's exhausted-window path and transport debounce scheduling are deferred
helper behavior, rather than a claim of whole-family coverage.

Native Rust per-route line/region coverage is measured by the committed catalog
and the required `bash scripts/check-server-rust.sh` lane. Every registration has
its real HTTP floor and status mutant; the family also rejects missing notify,
missing audit, missing authority filtering and double state bumps. Actual COMMIT
cuts cover both outcomes of the user-scoped reducer/receipt transaction. See
[the HTTP matrix](CHANNELS.md) for fixtures, normalization and rollback.
