// Generates a golden DPoP proof vector using Node's WebCrypto (same ES256/P-256
// primitives the browser's crypto.subtle exposes) so the Go VerifyDPoP path can
// be cross-verified against a real, independently-produced proof — not just
// round-tripped against itself. Run once with `node gen_dpop_vector.mjs`.
import { webcrypto } from 'node:crypto';

const { subtle } = webcrypto;

function b64url(buf) {
	return Buffer.from(buf).toString('base64url');
}

const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
const jwk = await subtle.exportKey('jwk', pair.publicKey);
const pubJwk = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };

const header = { typ: 'dpop+jwt', alg: 'ES256', jwk: pubJwk };
const iat = 1751500000; // fixed — the Go test passes this as `now` so skew never applies
const payload = { htm: 'POST', htu: 'https://mail.example.com/jmap', iat, jti: 'golden-vector-jti-1' };

const enc = (o) => b64url(Buffer.from(JSON.stringify(o)));
const signingInput = `${enc(header)}.${enc(payload)}`;
const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(signingInput));
const proof = `${signingInput}.${b64url(sig)}`;

// RFC 7638 thumbprint (must match shared/threat.JKTFromJWK's canonical member order).
const canonical = JSON.stringify({ crv: pubJwk.crv, kty: pubJwk.kty, x: pubJwk.x, y: pubJwk.y });
const jktBuf = await subtle.digest('SHA-256', Buffer.from(canonical));
const jkt = b64url(jktBuf);

console.log(JSON.stringify({ proof, jkt, iat, jwk: pubJwk }, null, 2));
