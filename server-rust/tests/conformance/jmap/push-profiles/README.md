# Push legacy-profile corpus (#356a)

`bins/gateway/tests/jmap_push_profiles_recorded.rs` records frozen `mailserverd`
once per `CRYPTO_ALGORITHM_PROFILE` (`standard`, `hybrid`, `smx`), with the
fixture `JWT_SECRET` and the identity-login SM2 PEM mounted read-only.

Accepted cases, as Go:
- HS256 and SM2 on `GET /jmap/ws` (status plus the reply to a `ready` frame),
  `GET /jmap/eventsource?closeafter=state` and `GET /api/chat/presence?userIds=0`.
- An unscoped token under Go's `mailserver-drive-native-1` kid.
- A duplicated header `alg` whose last member is HS256 (last member wins in both).

Refusal cases:
- Claim separation: drive scope, expired, refresh, mfa_pending,
  force_pw_change, password_reset, wrong audience, wrong issuer, missing iat,
  nbf in the future, a guest claim without a satellite row.
- Key confusion: retired `mailserver-hmac-1` kid, wrong secret, `alg: none`,
  HMAC keyed with the SM2 or the ES256 public point, an SM2 token from a
  foreign key (d = 1), and a duplicated `alg` whose last member is ES256.

Native replay builds the legacy key material `main.rs` installs per profile,
has no Go upstream and requires zero Go proxies. Native-only tests cover
jti/family/all revocation and live WS/SSE eviction for HS256 and SM2, and a
mutant without legacy keys that must fail the standard `ws-hs256` golden.
Normalization: the fixture mailbox id in SSE state frames.

    cargo test --locked -p setjoin-gateway --test jmap_push_profiles_recorded -- --test-threads=1
