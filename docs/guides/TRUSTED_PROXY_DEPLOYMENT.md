# TRUSTED_PROXY_IP — reverse proxy / load balancer deployment guide

How to configure `TRUSTED_PROXY_IP` when setjoin runs behind a TLS-terminating
reverse proxy or load balancer. The variable is the single trust switch for
real-client-IP resolution (`shared/clientip` — the one `X-Forwarded-For` trust
boundary shared by the gateway, access middleware and threat pipeline). Misconfiguring
it either attributes every client to the proxy IP (breaking rate limits, spray
detection, geo/conditional access and audit attribution) or lets clients spoof
their identity. Read the semantics section before deploying.

Package contract: `shared/clientip/clientip.go` (registered in `shared/DOX.md`).

## What it controls

Two per-request resolutions behind the gateway:

- **Client IP** (`clientip.Extract`): used by the authproxy to forward the
  observed client to the authserver (`X-Forwarded-For`), where IP-based threat
  controls run — rate limiting, password-spray detection, geo-blocking, CAPTCHA,
  tarpit, audit. It is the sole authority on these headers.
- **Client-facing scheme** (`clientip.ForwardedProto`): an `https` verdict from
  a trusted peer drives `Secure` session cookies — the authproxy forwards the
  verdict as `X-Forwarded-Proto`, and the authserver sets `Secure` on session
  cookies when a trusted hop reports TLS. HSTS is a separate surface: the
  gateway emits `Strict-Transport-Security` only on its own direct-TLS
  listener, so behind `HTTP_MODE=proxy` gateway responses carry **no** HSTS
  header — the proxy tier must set it. Behind a TLS-terminating proxy without
  `TRUSTED_PROXY_IP`, every request reads as `http` and `Secure` cookies are
  dropped.

## Exact semantics (what the code actually does)

- The value is read **once at process init** from the environment. Changing it
  requires a gateway restart; hot-reload does not apply.
- It is matched as a **single IP literal, exact string equality** against the
  immediate socket peer (`RemoteAddr` minus port). Not supported: CIDR ranges,
  hostnames, multiple comma-separated addresses, bracketed IPv6 (`[::1]`).
- **Unset or empty (default): forwarded-header trust is fully disabled.** The
  socket peer is always returned as the client IP; the scheme comes from the
  socket only. This is the safe default and direct-TLS deployments need nothing.
- **Set, but the peer never matches:** identical to unset (fail closed) — any
  forwarded header is discarded as spoofed input.
- **Set and the immediate peer matches:**
  - Client IP = the **rightmost valid entry of the full `X-Forwarded-For`
    chain** (every header line joined). The leftmost entry is attacker-controlled;
    the rightmost is the one the trusted proxy itself observed and appended.
    A malformed rightmost entry **fails closed** to the trusted proxy's own
    address — earlier chain entries are never scanned as a fallback.
  - Scheme = the **last `X-Forwarded-Proto` line**, case-insensitive `http`/`https`.
    Direct TLS on the gateway socket is authoritative and skips headers entirely.
    Missing or malformed fails closed to `http`.

The trust anchor is always the **immediate peer** (whoever's socket connects to
the gateway), never anything inside the request.

## Choosing the value

1. Set it to the address of the **last hop** — whatever connects directly to
   the gateway — not the browser-facing proxy.
2. Don't guess it. Confirm the actual peer from gateway/authserver logs or a
   temp echo of `RemoteAddr`: containerized topologies often show the Docker
   bridge gateway, kube-proxy/SNAT node IP or sidecar address instead of the
   ingress host you assumed.
3. IPv6: use the **bare, lowercase, canonical form without brackets** (`::1`,
   `fd7a::10`) exactly as the socket reports it. If the proxy connects over
   IPv6, configure its IPv6 address.
4. Remember the threat surface: once the peer matches, the rightmost XFF value
   becomes client identity. Only processes that can connect **from** that source
   address may exist. Restrict the gateway's plain-HTTP port to the proxy
   (loopback, private subnet, firewall/ACL).

## Baseline configuration

`TRUSTED_PROXY_IP` is a plain environment variable read via `os.Getenv` — put
it in the same `/etc/setjoin/config.env` used for `DB_DSN`, `HTTP_MODE`, etc.,
then restart the gateway:

```bash
# /etc/setjoin/config.env
HTTP_MODE=proxy             # serve plain HTTP on :80, TLS terminated upstream
TRUSTED_PROXY_IP=127.0.0.1  # address the proxy connects from
```

`HTTP_MODE=proxy` (instead of the default `redirect`) makes the gateway serve
content on `:80` behind the proxy instead of redirecting to its own `:443`.

## Example: nginx (TLS termination, same host)

```nginx
server {
    listen 443 ssl;
    http2 on;
    server_name mail.example.com;

    ssl_certificate     /etc/letsencrypt/live/mail.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mail.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:80;
        proxy_set_header Host $host;
        # $proxy_add_x_forwarded_for APPENDS the observed client IP to any
        # incoming chain, so the RIGHTMOST entry is the address nginx itself
        # saw — exactly what the gateway's rightmost-hop trust relies on.
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

```bash
TRUSTED_PROXY_IP=127.0.0.1
```

Watch for the IPv6 pitfall: if `proxy_pass` targets a hostname resolving to
`::1` first, the peer is `::1`, not `127.0.0.1` — configure whichever address
actually appears in the logs.

## Example: Caddy (automatic HTTPS)

```
mail.example.com {
    reverse_proxy 127.0.0.1:80
}
```

```bash
TRUSTED_PROXY_IP=127.0.0.1
```

Caddy v2 already emits a correct rightmost value by default: it computes the
client address itself and, for clients that are not in its `trusted_proxies`
list, **replaces** any client-supplied `X-Forwarded-For` with the observed
address, and sets `X-Forwarded-Proto` automatically. If Caddy itself sits
behind another proxy or CDN, add that hop to `trusted_proxies` so Caddy
resolves the real client, and set `TRUSTED_PROXY_IP` to Caddy's address
(last-hop discipline, below).

## Example: HAProxy (TLS termination)

```
frontend fe_mail
    bind *:443 ssl crt /etc/haproxy/mail.pem
    mode http
    default_backend be_setjoin

backend be_setjoin
    mode http
    # set-header REPLACES (removes then sets), so the rightmost entry becomes
    # the client address HAProxy itself observed — never a client-supplied chain.
    http-request set-header X-Forwarded-For %[src]
    http-request set-header X-Forwarded-Proto https
    server setjoin1 127.0.0.1:80
```

```bash
TRUSTED_PROXY_IP=127.0.0.1   # or the HAProxy host address when remote — then firewall :80 to that source
```

**TCP pass-through caveat:** in `mode tcp` no `X-Forwarded-*` headers are
added, so every request is attributed to the HAProxy address — but the scheme
depends on where TLS terminates. With **TLS pass-through** (the client's TLS
session is spliced through to the gateway's `:443`), the gateway terminates
TLS itself and its socket is authoritative (`r.TLS != nil`): the scheme reads
`https` and HSTS plus `Secure` session cookies still apply — only per-client
IP attribution is lost. With **cleartext forwarding** (TLS terminated at the
load balancer, plain HTTP spliced or proxied to the gateway), there is no TLS
on the gateway socket and no trusted `X-Forwarded-Proto`, so the scheme reads
`http` — no `Secure` cookies and, in proxy mode, no gateway HSTS. Do not set
`TRUSTED_PROXY_IP` for TCP pass-through in either flavor: the splicing hop
contributes nothing trustworthy to honor, and a client's tunneled request can
carry its own `X-Forwarded-For`, so trusting the splice would let clients
choose their own identity. Use HTTP mode if per-client IP features matter;
TCP pass-through is only acceptable where threat controls, geo/CA and IP
audit are not needed.

## Cloud load balancers

The trust model anchors to ONE exact peer IP, while cloud L7 balancers terminate
TLS on a fleet whose egress addresses form a range: AWS ALB nodes use addresses
from the ALB subnets, GCP external HTTP(S) LBs use a proxy-only subnet, Azure
Application Gateway similar. Pinning one node IP works until traffic shifts to
another node and everything it carries is attributed to the LB. Two sound
patterns:

**L4 pass-through with source preservation** (AWS NLB with instance targets, GCP
passthrough Network LB): the gateway's socket peer IS the client and no XFF is
involved. Leave `TRUSTED_PROXY_IP` unset and run the gateway in direct TLS mode
(`TLS_AUTOCERT_DOMAINS` or `TLS_CERT`/`TLS_KEY`) — client identity comes from
the socket, which is the strongest possible posture.

**L7 LB → stable-IP last hop:** keep a small nginx/Caddy/HAProxy on the origin
host (or a single-ENI/VIP hop) as the final tier with a fixed address, trust
that address, and have it emit the LB-validated client IP as the rightmost
entry. Example for Cloudflare in front of an origin nginx (any CDN with a
validated client-IP header works the same way):

```nginx
# Origin nginx, final hop before setjoin.
# Accept the client-IP signal ONLY from Cloudflare's published ranges:
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
# ... remaining ranges from https://www.cloudflare.com/ips/ (v4 + v6)
real_ip_header CF-Connecting-IP;

server {
    listen 8080;
    # Lock :8080 to the CDN/tunnel with a firewall; setjoin itself stays on loopback.
    location / {
        proxy_pass http://127.0.0.1:80;
        # After real_ip, $remote_addr is the edge-validated client address.
        # Emit it as the ONLY XFF value so the rightmost entry is genuine.
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto https;  # client-facing TLS ended at the edge
    }
}
```

```bash
TRUSTED_PROXY_IP=127.0.0.1
```

## Multi-tier chains (general rule)

With more than one proxy tier (CDN → LB → proxy → setjoin), each tier should
keep its own trust list; what matters to setjoin is only the **final hop's
emission**: the rightmost `X-Forwarded-For` entry must be the client address
the final hop itself validated, and `TRUSTED_PROXY_IP` must be the final hop's
address. Naively appending along the chain leaves the previous hop's address as
the rightmost entry, and setjoin will (correctly, from its viewpoint) report
the intermediate hop as the client. When you control every tier, rebuild the
header at the last hop (overwrite or emit the validated single value); when you
don't, add the closest trustworthy hop to the last hop's own trust config and
let it normalize the value.

## Multiple ingress replicas

`TRUSTED_PROXY_IP` accepts exactly one address. A pool of ingress pods or nodes
presenting many source addresses means only traffic from the configured address
is honored; the rest is fail-closed to the proxy attribution. Options: dedicate
one last-hop proxy with a fixed IP (recommended), SNAT all ingress egress to a
single address, or leave `TRUSTED_PROXY_IP` unset — acceptable only where
per-client-IP controls are not required.

## Common pitfalls

- **CIDR, hostname, `[bracketed]` or comma-separated values never match** — the
  comparison is exact single-IP string equality, so these silently disable
  header trust (fail closed, same as unset).
- **Non-canonical IPv6 text** (`[::1]`, uppercase, unexpanded forms) can miss
  the string match even when semantically equal. Copy the exact form your logs
  show for the socket peer.
- **Forgetting the restart** — the value is read once at init.
- **A spoofable trusted address** — anything able to connect from that source
  address controls client identity and every IP-derived decision downstream.
- **Pairing with `HTTP_MODE`.** For a TLS-terminating proxy, set
  `HTTP_MODE=proxy` together with `TRUSTED_PROXY_IP`. With the default
  `HTTP_MODE=redirect`, a proxy pointed at `:80` bounces every client to the
  gateway's own `:443` — the TLS listener will still honor trusted headers,
  but you gain nothing from the proxy tier and double-TLS round-trips remain.
- **Health-check/probe traffic** arriving from other source ranges is attributed
  to its socket peer — harmless for probes, but real user traffic must flow
  through the trusted hop.

## Verify the deployment

1. **Spoof rejection (the important one).** Through the full public path:

   ```
   curl -sD- https://mail.example.com/ -H 'X-Forwarded-For: 203.0.113.9' -o /dev/null
   ```

   Check the resolved client IP where you observe it (authserver threat/audit
   logs or gateway access logs): it must be YOUR real address, never
   `203.0.113.9`. The trusted proxy appended your real address after the
   spoofed one, and the rightmost value wins.
2. **Untrusted peer.** From a host that is not the proxy, connect to the
   gateway port directly with an `X-Forwarded-For` header: it must be ignored
   (socket peer wins).
3. **TLS treatment (`Secure` cookies).** With `HTTP_MODE=proxy` behind TLS
   termination, log in through the public endpoint and confirm the session
   cookie carries the `Secure` flag. Then confirm the fail-closed direction
   from the proxy host itself (its address is the trusted peer): request the
   gateway port directly with no `X-Forwarded-Proto` header and the cookie
   must lose `Secure` (verdict falls back to `http`). Remove the temporary
   header change afterwards.
4. **HSTS.** The gateway does **not** emit HSTS in proxy mode — the
   `Strict-Transport-Security` header is wired only into its direct-TLS
   listener chain, so no gateway response on the `:80` proxy path carries it.
   Verify instead that your proxy tier sets it and the browser receives it
   (nginx, one line in the TLS `server` block:
   `add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;`).
   Direct-TLS deployments (no proxy) get the header from the gateway's own
   `:443` listener.
5. **Fail-closed negative test.** Set `TRUSTED_PROXY_IP` to an address that
   never appears as a peer, restart, and confirm behavior is identical to
   unset — every client attributes to the immediate peer and no header is
   honored. Restore the correct value and restart.
