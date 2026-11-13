#!/usr/bin/env node
// Regression test: the E6 in-process fault proxy forwards upstream responses
// hop-by-hop-clean (RFC 9110 §7.6.1) with the body intact.
//
// Instrument defect (field evidence, retained run e6h-20260921t183646z, 20/20
// pairs, verdict FAIL): every one of 40,000 driver attempts classified
// networkDrop while every proxy recorded `forwarded: 6462, upstreamErrors: 0`
// per member — the proxy completed every upstream exchange, yet the client
// (undici fetch, exactly the driver's `fetch` + `arrayBuffer` shape) failed
// the response body read. Drop latencies tracked the per-stage latency
// additions (min ~0.6 ms, median ~63 ms against a 60 ms stage, max ~241 ms
// against a 200 ms stage), i.e. headers arrived and the failure hit at body
// completion. Two pre-fix `FaultProxy.handle` defects combine to produce
// exactly that, and this test reproduces both through the REAL class:
//
// 1. Body drop for small content-length responses (the gateway's actual shape
//    for the pinned E6 class routes). The metered write path is asynchronous
//    (`await this.takeTokens(...)` yields), but `upstreamResponse` emits
//    'data' and 'end' in the same tick for a single-segment response: 'end'
//    ran `response.end()` before the chunk's queued `response.write()`
//    resumed, the ERR_STREAM_WRITE_AFTER_END failure vanished into
//    `drain().catch(() => {})`, and the client received headers + accurate
//    `content-length` with ZERO body bytes. Pre-fix throw shape (observed):
//    `TypeError: terminated` caused by undici
//    `ResponseContentLengthMismatchError` (code UND_ERR_RES_CONTENT_LENGTH_MISMATCH).
//    With ONLY the hop-by-hop header fix applied the same arm instead hangs
//    until the client timeout — the write-after-end race, not the headers,
//    drops the body. The fix serializes every chunk's metered write through
//    one promise chain per response and runs `response.end()` only after the
//    chain settles (also preserving multi-chunk body order under throttling;
//    a failed metered write now destroys the client socket — an honest drop
//    — instead of emitting a half-response).
//
// 2. Hop-by-hop header forwarding. The pre-fix path passed
//    `upstreamResponse.headers` VERBATIM to `response.writeHead(...)`,
//    re-asserting the upstream connection's framing fields (notably
//    `transfer-encoding`) on the client-facing response. RFC 9110 §7.6.1
//    requires a proxy to strip hop-by-hop fields (plus every field named by
//    the received `connection` header) before forwarding; end-to-end fields
//    stay, including `content-length` — the body is piped verbatim so the
//    declared length remains accurate — and this proxy's own HTTP server
//    applies its single, correct framing when transfer-encoding is stripped.
//
// Arms drive the REAL FaultProxy class against stub upstreams: a chunked
// upstream and a content-length upstream must both resolve client-side with
// the exact body bytes over a correctly single-framed response; the loss and
// outage drop paths must still destroy the client connection.
//
// Wave-1 unit B7 arms (review of commit 71423c07e's follow-up state) add two
// further pre-fix defects, both reproduced through the REAL class:
//
// 3. Terminal drop accounting was not exactly-once. The per-response write
//    chain resolved "successfully" when the client socket died during the
//    asynchronous takeTokens wait (the destroyed-socket early return), so a
//    response that wrote ZERO wire bytes was counted `forwarded` with every
//    error/drop counter at zero; and the upstream response-'error' handler
//    (premature upstream close mid-body) destroyed the client socket WITHOUT
//    incrementing `upstreamErrors`. The fix routes every response chain
//    through exactly-once terminal accounting — each attempt settles as one
//    of forwarded / upstreamError / clientAbort (injected loss/outage drops
//    settle before the exchange) — and a close during takeTokens now routes
//    to the failure arm.
//
// 4. Request-side hop-by-hop leak. The request forwarded upstream copied the
//    client's headers verbatim and only overwrote `connection`, so every
//    field nominated by the request's own `connection` header (e.g. a custom
//    `x-local`) plus `te` / `proxy-authorization` leaked one hop. The fix
//    applies the SAME stripHopByHopHeaders helper to the request headers
//    before asserting the proxy's own `host` and `connection: close`.
//
// Scheme v4 proxy-drain arms (r3 finding 2; the two named refusal tests) add:
//
// 5. Client disconnects BEFORE upstream headers, in both shapes the r3
//    in-memory probe reproduced: during the stage latency window (pre-fix:
//    `handle` returned at the disconnected-client check with
//    requestsReceived:1 and ALL terminal counters zero, no upstream ever
//    created) and while upstream headers were pending (pre-fix: the upstream
//    was registered with NO downstream cancellation — registered and
//    undestroyed). Post-fix, terminal accounting installs AT RECEIPT, the
//    downstream-disconnect cancellation routes the attempt to clientAbort
//    and destroys the upstream; exactly one terminal kind is recorded and
//    the counters reconcile.
// 6. Client disconnects MID-BODY: same invariants — the upstream is
//    destroyed by the cancellation routing, the truncated delivery is a
//    clientAbort (never forwarded/upstreamError), counters reconcile.
// 7. The proxy-owned drain check: stop() drains up to the configured
//    deadline, then snapshots pending/registered-upstreams/terminal-ledger;
//    an undrained proxy records ok:false (the runMember refusal and the
//    consumption E6-PROXY-DRAIN check fail closed on exactly this evidence).
// 8. The §2.3.2 per-basis attribution closure report: requestsReceived
//    breaks down exactly per population basis, and the shared frozen
//    PROXY_CONFIG digests identically in every proxy a run constructs (the
//    digest recorded in both windows' receipts).
//
// Round-2 review arms (terminal settlement order; the P1/P2 findings) add:
//
// 9. Terminal settlement ORDER (P1): the successful path counted `forwarded`
//    when finishAttempt ran — BEFORE response.end() and its flush — so a
//    downstream close during final response completion left the proxy at
//    `forwarded` while the driver's body read still failed as networkDrop
//    (proxy/driver classification disagreement window). The fix settles
//    successful attempts ONLY on the response's 'finish' event (headers and
//    body handed off to the operating system: the client-visible bytes are
//    committed), with every close/error path sharing the same once-only
//    guard — and a close after end() but before 'finish' (the final flush
//    never completed) now settles as clientAbort instead of being skipped.
//    Invariant: proxy `forwarded` implies every declared body byte was
//    committed before settlement, and finishAttempt('forwarded') is
//    reachable only from a cleanly ended, well-framed upstream response, so
//    forwarded can never coexist with a driver networkDrop caused by this
//    proxy. Arm 13 reproduces the close-during-final-completion shape.
// 10. Terminal-ledger reconciliation in EVERY named path (P2): only the
//    disconnect arms reconciled the ledger; the request-side forwarding arm
//    and every successful/drop/error arm now assert
//    terminalSettled === requestsReceived with nothing pending.
//
// Run: node scripts/run-connectivity-e6-harness.proxy.test.mjs (loopback only).

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import http from 'node:http';
import net from 'node:net';
import process from 'node:process';

import { FaultProxy, HOP_BY_HOP_HEADERS, PROXY_CONFIG, stripHopByHopHeaders } from './run-connectivity-e6-harness.mjs';

const sleepMs = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// Deterministic multi-part payload; parts are written in separate upstream
// flushes so the stub exercises genuinely streamed (chunked) responses.
const PAYLOAD_PARTS = [
	'{"part":1,"pad":"0123456789abcdef"}\n',
	'{"part":2,"pad":"fedcba9876543210"}\n',
	'{"part":3,"pad":"abcdefghijklmnopqrstuvwxyz"}\n',
	'{"part":4,"pad":"zyxwvutsrqponmlkjihgfedcba"}\n',
];
const PAYLOAD = Buffer.from(PAYLOAD_PARTS.join(''));

function proxySchedule({ lossPercent = 0, outage = false, bandwidthKbit = 100_000, latencyMs = 0 } = {}) {
	return {
		warmupMs: 0,
		measurementMs: 60_000,
		stageBlocks: [
			{ name: 'proxy-regression-test', startMs: 0, durationMs: 60_000, bandwidthKbit, lossPercent, latencyMs },
		],
		outage: outage
			? { startMs: 0, durationMs: 60_000, reconnectWithinMs: 0 }
			: { startMs: 3_600_000, durationMs: 60_000, reconnectWithinMs: 0 },
	};
}

async function listen(server) {
	await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
	return server.address().port;
}

/** Stub upstream speaking HTTP/1.1 with the given header set and streamed body parts. */
async function startStubUpstream({ headers, streamed, body = PAYLOAD }) {
	const server = http.createServer((request, response) => {
		response.writeHead(200, headers);
		if (streamed) {
			// Flush headers before the body exists: with no content-length this
			// commits Node's server to chunked framing (the harness gateway's
			// streamed-response shape).
			response.flushHeaders();
			response.write(body.subarray(0, 200));
			setTimeout(() => {
				response.write(body.subarray(200, 400));
				response.end(body.subarray(400));
			}, 10);
			return;
		}
		response.end(body);
	});
	const port = await listen(server);
	return { server, port, url: `http://127.0.0.1:${port}` };
}

async function startProxy(targetUrl, { lossPercent, outage, bandwidthKbit, latencyMs, config } = {}) {
	const proxy = new FaultProxy({
		schedule: proxySchedule({ lossPercent, outage, bandwidthKbit, latencyMs }),
		seeds: { run: 'proxy-regression-test' },
		targetUrl,
		windowOriginMonotonicMs: performance.now(),
		config,
	});
	await proxy.start();
	return proxy;
}

async function fetchBody(url, { method = 'GET', timeoutMs = 5_000, headers } = {}) {
	const response = await fetch(url, { method, headers, signal: AbortSignal.timeout(timeoutMs) });
	const body = Buffer.from(await response.arrayBuffer());
	return { response, body };
}

/** Raw-socket read of one client-facing response: framing must be wire-visible. */
function rawWireGet(url, path = '/') {
	return rawWireRequest(url, { path });
}

/**
 * Raw-socket request with caller-controlled headers (the undici fetch used by
 * fetchBody silently drops client-supplied `connection` headers, so the
 * request-side hop-by-hop arm needs wire-level control). Resolves with the
 * raw latin1 wire bytes once the content-length-framed response body has been
 * fully read (or the socket closes); the proxy holds the connection open for
 * keep-alive, so waiting for close alone would hang.
 */
function rawWireRequest(url, { path = '/', headers = ['Connection: close'] } = {}) {
	return new Promise((resolve, reject) => {
		const target = new URL(url);
		const socket = net.connect(Number(target.port), '127.0.0.1', () => {
			const requestLines = [`GET ${path} HTTP/1.1`, `Host: ${target.host}`, ...headers];
			socket.write(requestLines.join('\r\n') + '\r\n\r\n');
		});
		const chunks = [];
		socket.on('data', (chunk) => {
			chunks.push(chunk);
			const raw = Buffer.concat(chunks).toString('latin1');
			const headerEnd = raw.indexOf('\r\n\r\n');
			if (headerEnd !== -1) {
				const match = /content-length:\s*(\d+)/i.exec(raw);
				if (match && raw.length >= headerEnd + 4 + Number(match[1])) {
					socket.destroy();
					resolve(raw);
				}
			}
		});
		socket.on('close', () => resolve(Buffer.concat(chunks).toString('latin1')));
		socket.on('error', reject);
		setTimeout(() => socket.destroy(new Error('raw wire request timed out')), 5_000).unref();
	});
}

/**
 * Wait until the proxy's terminal attempt accounting settles (any of the
 * forwarded / upstreamErrors / clientAborts counters moves), so assertions
 * observe the FINAL classification rather than racing the asynchronous write
 * chain — the close-during-takeTokens arm settles only after the token wait
 * drains (~175 ms at the throttled stage bandwidth).
 */
async function waitForTerminalSettled(proxy, timeoutMs = 5_000) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		const { forwarded, upstreamErrors, clientAborts } = proxy.stats;
		if (forwarded + upstreamErrors + clientAborts > 0) return;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
}

/**
 * Wait until the proxy DRAINS (scheme v4 proxy-drain block): zero unsettled
 * attempts (pending) and zero still-registered upstreams — the state the
 * drain snapshot in stop() requires for `ok: true`. Polls because upstream
 * destroy()/completion removes entries from the registered set on 'close',
 * one tick after the terminal accounting settles.
 */
async function waitForDrained(proxy, timeoutMs = 5_000) {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (proxy.pending === 0 && proxy.upstreams.size === 0) return;
		await new Promise((resolve) => setTimeout(resolve, 10));
	}
	assert.fail(`proxy did not drain within ${timeoutMs}ms (pending ${proxy.pending}, upstreams ${proxy.upstreams.size})`);
}

/**
 * The scheme v4 refusal-test invariants shared by both named disconnect
 * refusals: exactly ONE terminal kind is recorded for the single received
 * request, the terminal ledger reconciles with requestsReceived, nothing
 * injected dropped it, and the proxy drains with no registered upstream
 * left behind (the r3 probe's "registered and undestroyed" refusal).
 */
function assertSingleTerminalReconciled(proxy, kind) {
	const { requestsReceived, forwarded, droppedLoss, droppedOutage, upstreamErrors, clientAborts } = proxy.stats;
	assert.equal(requestsReceived, 1, 'disconnect arms reach the proxy exactly once');
	const terminal = { forwarded, upstreamErrors, clientAborts };
	assert.equal(terminal[kind], 1, `exactly one terminal kind must be recorded: ${kind}`);
	assert.equal(
		Object.entries(terminal).reduce((sum, [name, count]) => sum + count, 0),
		1,
		'no second terminal kind may fire for the same attempt',
	);
	assert.equal(droppedLoss, 0, 'a client disconnect is not an injected loss drop');
	assert.equal(droppedOutage, 0, 'a client disconnect is not an injected outage drop');
	assert.equal(proxy.pending, 0, 'the attempt must not stay pending (unsettled)');
	assert.equal(
		forwarded + upstreamErrors + clientAborts + droppedLoss + droppedOutage,
		requestsReceived,
		'terminal ledger must reconcile with requestsReceived',
	);
}

/**
 * Full terminal-ledger reconciliation for ANY arm (round-2 review P2): every
 * received request settled through exactly one terminal kind — the ledger
 * sums to requestsReceived and nothing stays pending (unsettled). The
 * per-kind expectations pin the arm's specific classification (omit a key to
 * leave that kind unconstrained beyond the reconciliation itself).
 */
function assertTerminalLedgerReconciled(proxy, expectedKinds = {}) {
	const { requestsReceived, forwarded, droppedLoss, droppedOutage, upstreamErrors, clientAborts } = proxy.stats;
	const terminalSettled = forwarded + upstreamErrors + clientAborts + droppedLoss + droppedOutage;
	assert.equal(terminalSettled, requestsReceived, 'terminal ledger must reconcile with requestsReceived');
	assert.equal(proxy.pending, 0, 'no attempt may remain pending (unsettled)');
	for (const [kind, expected] of Object.entries(expectedKinds)) {
		assert.equal(proxy.stats[kind], expected, `terminal kind ${kind} must equal ${expected}`);
	}
}

// ---------------------------------------------------------------------------
// Arm 1 (unit): the hop-by-hop stripper implements RFC 9110 §7.6.1 exactly —
// constant list removed, every `connection`-named field removed, end-to-end
// fields (content-length, content-type, date, set-cookie) preserved.
// ---------------------------------------------------------------------------
{
	const stripped = stripHopByHopHeaders({
		connection: 'keep-alive, x-shadow-field',
		'x-shadow-field': 'named-by-connection',
		'keep-alive': 'timeout=5',
		'transfer-encoding': 'chunked',
		te: 'trailers',
		trailer: 'x-checksum',
		upgrade: 'websocket',
		'proxy-authenticate': 'Basic',
		'proxy-authorization': 'Basic zzz',
		'proxy-connection': 'keep-alive',
		'content-length': String(PAYLOAD.length),
		'content-type': 'application/json',
		date: 'Sun, 21 Sep 2026 18:36:46 GMT',
		'x-request-id': '5363fd68',
	});
	for (const name of HOP_BY_HOP_HEADERS) {
		assert.equal(stripped[name], undefined, `hop-by-hop field must be stripped: ${name}`);
	}
	assert.equal(stripped['x-shadow-field'], undefined, 'field named by `connection` must be stripped');
	assert.equal(stripped['content-length'], String(PAYLOAD.length), 'content-length must be preserved (body piped verbatim)');
	assert.equal(stripped['content-type'], 'application/json', 'end-to-end fields preserved');
	assert.equal(stripped.date, 'Sun, 21 Sep 2026 18:36:46 GMT', 'end-to-end fields preserved');
	assert.equal(stripped['x-request-id'], '5363fd68', 'end-to-end fields preserved');
	for (const required of ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']) {
		assert.ok(HOP_BY_HOP_HEADERS.includes(required), `RFC 9110 §7.6.1 list must contain ${required}`);
	}
	assert.ok(Object.isFrozen(HOP_BY_HOP_HEADERS), 'hop-by-hop list must be frozen');
}

// ---------------------------------------------------------------------------
// Arm 2 (integration, chunked upstream): the stub streams WITHOUT
// content-length (flushHeaders commits Node's chunked framing upstream). The
// proxy must resolve the client fetch with the exact body bytes over a single,
// correctly framed response. Wire check: the payload appears exactly once
// inside one chunked framing layer and one terminating last-chunk.
// ---------------------------------------------------------------------------
{
	const upstream = await startStubUpstream({
		headers: { 'content-type': 'application/octet-stream' },
		streamed: true,
	});
	const proxy = await startProxy(upstream.url);
	try {
		const { response, body } = await fetchBody(`${proxy.endpoint}/attempt?seq=0`);
		assert.equal(response.status, 200, 'chunked upstream: proxied status must be 200');
		assert.ok(body.equals(PAYLOAD), `chunked upstream: body bytes must survive the proxy verbatim (${body.length} vs ${PAYLOAD.length})`);

		const wire = await rawWireGet(proxy.endpoint, '/attempt?seq=1');
		const headerBlock = wire.slice(0, wire.indexOf('\r\n\r\n')).toLowerCase();
		assert.ok(headerBlock.includes('transfer-encoding: chunked'), 'client-facing response must be chunked-framed for a streamed upstream');
		const firstPayloadLine = PAYLOAD_PARTS[0].slice(0, -1);
		assert.equal(wire.split(firstPayloadLine).length - 1, 1, 'payload must appear exactly once (no double framing/re-framing artifacts)');
		assert.equal(wire.split('0\r\n\r\n').length - 1, 1, 'exactly one terminating last-chunk');
		assert.ok(wire.endsWith('0\r\n\r\n'), 'response must end with the chunked terminator');
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 2, forwarded: 2, upstreamErrors: 0, clientAborts: 0, droppedLoss: 0, droppedOutage: 0 });
		await proxy.stop();
		assert.equal(proxy.drain.ok, true, 'chunked-success arm: proxy must drain cleanly at stop');
		assert.equal(proxy.drain.terminalSettled, proxy.drain.requestsReceived, 'chunked-success arm: drain snapshot terminal ledger reconciles');
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 3 (integration, content-length upstream): an end-to-end content-length
// must be preserved and the body must arrive byte-exact (the gateway's actual
// shape for the pinned E6 class routes: small JSON with content-length).
// ---------------------------------------------------------------------------
{
	const upstream = await startStubUpstream({
		headers: {
			'content-type': 'application/json',
			'content-length': String(Buffer.byteLength(PAYLOAD)),
			'x-request-id': 'regression-arm-3',
		},
		streamed: false,
	});
	const proxy = await startProxy(upstream.url);
	try {
		const { response, body } = await fetchBody(`${proxy.endpoint}/attempt?seq=2`);
		assert.equal(response.status, 200);
		assert.equal(response.headers.get('content-length'), String(Buffer.byteLength(PAYLOAD)), 'content-length must be forwarded intact');
		assert.equal(response.headers.get('x-request-id'), 'regression-arm-3', 'end-to-end fields forwarded');
		assert.ok(body.equals(PAYLOAD), 'content-length upstream: body bytes must survive the proxy verbatim');
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, forwarded: 1, upstreamErrors: 0, clientAborts: 0, droppedLoss: 0, droppedOutage: 0 });
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 4 (integration, loss drop): 100% loss must still destroy the client
// connection (the genuine networkDrop path) — fetch rejects.
// ---------------------------------------------------------------------------
{
	const upstream = await startStubUpstream({ headers: { 'content-type': 'application/json' }, streamed: false });
	const proxy = await startProxy(upstream.url, { lossPercent: 100 });
	try {
		await assert.rejects(
			() => fetchBody(`${proxy.endpoint}/attempt?seq=3`),
			(error) => error instanceof Error,
			'loss drop must reject the client fetch',
		);
		assert.equal(proxy.stats.droppedLoss, 1, 'proxy must account the loss drop');
		assert.equal(proxy.stats.forwarded, 0, 'dropped request must not be forwarded');
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, droppedLoss: 1, upstreamErrors: 0, clientAborts: 0, droppedOutage: 0 });
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 5 (integration, outage drop): an active outage must destroy the client
// connection without touching the upstream — fetch rejects.
// ---------------------------------------------------------------------------
{
	const upstream = await startStubUpstream({ headers: { 'content-type': 'application/json' }, streamed: false });
	const proxy = await startProxy(upstream.url, { outage: true });
	try {
		await assert.rejects(
			() => fetchBody(`${proxy.endpoint}/attempt?seq=4`),
			(error) => error instanceof Error,
			'outage drop must reject the client fetch',
		);
		assert.equal(proxy.stats.droppedOutage, 1, 'proxy must account the outage drop');
		assert.equal(proxy.stats.requestsReceived, 1, 'outage drop still arrives at the proxy');
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, droppedOutage: 1, forwarded: 0, upstreamErrors: 0, clientAborts: 0, droppedLoss: 0 });
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 6 (wave-1 B7, client abort during takeTokens): the client vanishes
// while the write chain is parked inside the asynchronous token wait, so the
// response writes ZERO wire bytes. The chain must route this to the failure
// arm — `forwarded` must stay 0 and the abort must be accounted (pre-fix
// probe: `forwarded: 1` with every error/drop counter at zero). The stage is
// throttled to 64 kbit (8 bytes/ms) so the first 1400-byte slice needs ~175 ms
// of token wait: the 40 ms abort lands deterministically INSIDE takeTokens.
// ---------------------------------------------------------------------------
{
	const body = Buffer.alloc(4096, 0x78);
	const upstream = await startStubUpstream({
		headers: { 'content-type': 'application/json', 'content-length': String(body.length) },
		streamed: false,
		body,
	});
	const proxy = await startProxy(upstream.url, { bandwidthKbit: 64 });
	try {
		const abort = new AbortController();
		const response = await fetch(`${proxy.endpoint}/attempt?seq=5`, { signal: abort.signal });
		setTimeout(() => abort.abort(), 40).unref();
		await assert.rejects(
			() => response.arrayBuffer(),
			(error) => error instanceof Error,
			'aborted client must not receive the body',
		);
		await waitForTerminalSettled(proxy);
		assert.equal(proxy.stats.forwarded, 0, 'zero-wire-byte response must NOT be counted forwarded');
		assert.equal(proxy.stats.clientAborts, 1, 'client abort during takeTokens must be accounted as clientAborts');
		assert.equal(proxy.stats.upstreamErrors, 0, 'a client abort is not an upstream error');
		assert.equal(proxy.stats.droppedLoss, 0, 'a client abort is not an injected loss drop');
		assert.equal(proxy.stats.droppedOutage, 0, 'a client abort is not an injected outage drop');
		assert.equal(proxy.stats.requestsReceived, 1, 'abort arm reaches the proxy exactly once');
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, clientAborts: 1, forwarded: 0, upstreamErrors: 0, droppedLoss: 0, droppedOutage: 0 });
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 7 (wave-1 B7, upstream response-error accounting): the upstream
// truncates mid-body (destroy() without end against a declared
// content-length). The upstream response-'error' handler must destroy the
// client connection AND increment `upstreamErrors` — pre-fix it destroyed the
// socket with every counter at zero.
// ---------------------------------------------------------------------------
{
	const upstream = http.createServer((request, response) => {
		response.writeHead(200, { 'content-type': 'application/json', 'content-length': '4000' });
		response.flushHeaders();
		response.write('y'.repeat(200));
		setTimeout(() => response.destroy(), 15);
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`);
	try {
		await assert.rejects(
			() => fetchBody(`${proxy.endpoint}/attempt?seq=6`),
			(error) => error instanceof Error,
			'truncated upstream body must reject the client fetch',
		);
		await waitForTerminalSettled(proxy);
		assert.equal(proxy.stats.upstreamErrors, 1, 'upstream response error must increment upstreamErrors');
		assert.equal(proxy.stats.forwarded, 0, 'truncated response must not be counted forwarded');
		assert.equal(proxy.stats.clientAborts, 0, 'an upstream truncation is not a client abort');
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, upstreamErrors: 1, forwarded: 0, clientAborts: 0, droppedLoss: 0, droppedOutage: 0 });
	} finally {
		await proxy.stop();
		upstream.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 8 (wave-1 B7, request-side hop-by-hop stripping): a request carrying
// `connection: x-local, te, keep-alive` plus `x-local` and `te` must not leak
// the nominated fields (nor the constant hop-by-hop set,
// proxy-authorization included) upstream. End-to-end fields (x-request-id)
// must survive, and the proxy must assert its own `connection: close` +
// upstream `host`. Raw-socket client: fetch/undici silently drops
// client-supplied `connection` headers, so wire-level control is required.
// ---------------------------------------------------------------------------
{
	const seenRequestHeaders = [];
	const upstream = http.createServer((request, response) => {
		seenRequestHeaders.push({ ...request.headers });
		response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' });
		response.end('ok');
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`);
	try {
		const wire = await rawWireRequest(proxy.endpoint, {
			path: '/attempt?seq=7',
			headers: [
				'Connection: x-local, te, keep-alive',
				'X-Local: leak-me',
				'Te: trailers',
				'Proxy-Authorization: Basic zzz',
				'X-Request-Id: request-side-strip',
			],
		});
		assert.ok(wire.startsWith('HTTP/1.1 200'), 'proxied exchange over the stripped request must succeed');
		assert.ok(wire.endsWith('ok'), 'proxied body must survive the stripped request');

		assert.equal(seenRequestHeaders.length, 1, 'upstream must see exactly one forwarded request');
		const seen = seenRequestHeaders[0];
		assert.equal(seen.connection, 'close', 'upstream connection must be the proxy-asserted single hop');
		assert.equal(seen['x-request-id'], 'request-side-strip', 'end-to-end request fields must be forwarded');
		for (const leaked of ['x-local', 'te', 'proxy-authorization', 'proxy-authenticate', 'proxy-connection', 'keep-alive', 'trailer', 'transfer-encoding', 'upgrade']) {
			assert.equal(seen[leaked], undefined, `hop-by-hop request field must not leak upstream: ${leaked}`);
		}
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 1, forwarded: 1, upstreamErrors: 0, clientAborts: 0, droppedLoss: 0, droppedOutage: 0 });
	} finally {
		await proxy.stop();
		upstream.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 9 (scheme v4 refusal test (a), client disconnects BEFORE upstream
// headers). Two sub-cases reproduce the r3 in-memory probe exactly:
//
//   (a1) disconnect during the stage latency window (the pre-fix
//        `harness:662 return`): the client is gone by the time the latency
//        timer fires, so the pre-fix path returned with requestsReceived:1
//        and ALL terminal counters zero, and no upstream was ever created.
//        Post-fix the terminal accounting installed AT RECEIPT settles the
//        attempt as clientAbort during the latency wait, and the timer must
//        not start an upstream exchange for the dead client.
//   (a2) disconnect while upstream headers are PENDING: the stub upstream
//        holds its response; the pre-fix proxy registered the upstream with
//        no downstream cancellation — registered and undestroyed. Post-fix
//        the downstream-disconnect cancellation routes the attempt to
//        clientAbort AND destroys the upstream (the stub must see its
//        connection die without ever answering).
//
// Both sub-cases assert the shared invariants: upstream destroyed/never
// created, exactly one terminal kind, counters reconcile, proxy drains.
// ---------------------------------------------------------------------------
{
	const upstream = http.createServer((request, response) => {
		assert.fail('arm 9a1: no upstream exchange may start for a client that disconnected during latency');
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`, { latencyMs: 250 });
	try {
		const abort = new AbortController();
		// The fetch promise itself rejects (headers never arrive before the
		// abort); capture the outcome to attach the rejection handler before
		// the abort timer fires.
		const settled = fetch(`${proxy.endpoint}/attempt?seq=9`, { signal: abort.signal }).then(
			() => ({ error: null }),
			(error) => ({ error }),
		);
		setTimeout(() => abort.abort(), 50).unref();
		const { error } = await settled;
		assert.ok(error instanceof Error, 'arm 9a1: disconnect during latency must reject the client fetch');
		await waitForTerminalSettled(proxy);
		await waitForDrained(proxy);
		assertSingleTerminalReconciled(proxy, 'clientAborts');
		await proxy.stop();
		assert.equal(proxy.drain.ok, true, 'arm 9a1: proxy must drain cleanly at stop');
		assert.equal(proxy.drain.requestsReceived, 1, 'arm 9a1: drain snapshot records the single request');
	} finally {
		upstream.close();
	}
}
{
	let sawRequest = 0;
	let sawConnectionDie = null;
	const upstream = http.createServer((request, response) => {
		sawRequest += 1;
		sawConnectionDie = new Promise((resolve) => response.socket.once('close', resolve));
		// Hold the headers: the upstream exchange is IN FLIGHT but has not
		// answered when the client disconnects (the r3 registered-and-
		// undestroyed shape).
		setTimeout(() => {
			if (!response.socket.destroyed) {
				response.writeHead(200, { 'content-type': 'text/plain', 'content-length': '2' });
				response.end('ok');
			}
		}, 300).unref();
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`);
	try {
		const abort = new AbortController();
		const settled = fetch(`${proxy.endpoint}/attempt?seq=10`, { signal: abort.signal }).then(
			() => ({ error: null }),
			(error) => ({ error }),
		);
		setTimeout(() => abort.abort(), 50).unref();
		const { error } = await settled;
		assert.ok(error instanceof Error, 'arm 9a2: disconnect before upstream headers must reject the client fetch');
		await waitForTerminalSettled(proxy);
		await waitForDrained(proxy);
		assertSingleTerminalReconciled(proxy, 'clientAborts');
		assert.equal(sawRequest, 1, 'arm 9a2: the upstream exchange was in flight');
		const died = await Promise.race([
			sawConnectionDie,
			sleepMs(2_000).then(() => 'timeout'),
		]);
		assert.notEqual(died, 'timeout', 'arm 9a2: the registered upstream must be DESTROYED by the downstream cancellation (stub connection dies unanswered)');
		await proxy.stop();
		assert.equal(proxy.drain.ok, true, 'arm 9a2: proxy must drain cleanly at stop');
		assert.equal(proxy.drain.upstreamsRegistered, 0, 'arm 9a2: no upstream may survive at teardown');
	} finally {
		upstream.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 10 (scheme v4 refusal test (b), client disconnects MID-BODY): the
// upstream answers with headers + a partial content-length body and holds
// the rest; the client aborts with part of the body already delivered. Same
// invariants as refusal (a): upstream destroyed, exactly one terminal kind
// (clientAbort — never `forwarded` for a truncated delivery, never
// `upstreamError` — the upstream only dies BECAUSE the cancellation routed),
// counters reconcile, proxy drains cleanly.
// ---------------------------------------------------------------------------
{
	let sawConnectionDie = null;
	// A body LARGER than the pre-abort partial write, so the delivery is
	// genuinely truncated mid-body when the client disconnects (a body that
	// fits in the first flush would arrive whole before the abort).
	const body = Buffer.alloc(4096, 0x62);
	const upstream = http.createServer((request, response) => {
		sawConnectionDie = new Promise((resolve) => response.socket.once('close', resolve));
		response.writeHead(200, {
			'content-type': 'application/json',
			'content-length': String(body.length),
		});
		response.write(body.subarray(0, 200));
		setTimeout(() => {
			if (!response.socket.destroyed) response.end(body.subarray(200));
		}, 500).unref();
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`);
	try {
		const abort = new AbortController();
		const response = await fetch(`${proxy.endpoint}/attempt?seq=11`, { signal: abort.signal });
		setTimeout(() => abort.abort(), 50).unref();
		await assert.rejects(
			() => response.arrayBuffer(),
			(error) => error instanceof Error,
			'arm 10: mid-body disconnect must reject the client body read',
		);
		await waitForTerminalSettled(proxy);
		await waitForDrained(proxy);
		assertSingleTerminalReconciled(proxy, 'clientAborts');
		const died = await Promise.race([
			sawConnectionDie,
			sleepMs(2_000).then(() => 'timeout'),
		]);
		assert.notEqual(died, 'timeout', 'arm 10: the mid-body upstream must be destroyed by the cancellation routing');
		await proxy.stop();
		assert.equal(proxy.drain.ok, true, 'arm 10: proxy must drain cleanly at stop');
		assert.equal(proxy.drain.terminalSettled, proxy.drain.requestsReceived, 'arm 10: drain snapshot terminal ledger reconciles');
	} finally {
		upstream.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 11 (proxy-owned drain check refuses an undrained proxy): the upstream
// never answers and the client stays connected, so the attempt is still
// unsettled with its upstream registered when stop() runs. After the (short,
// arm-configured) drain deadline the snapshot must record the breach —
// pending: 1, upstreamsRegistered: 1, ok: false — the exact evidence the
// runMember refusal and the consumption E6-PROXY-DRAIN check fail closed on.
// ---------------------------------------------------------------------------
{
	const upstream = http.createServer(() => {
		// Never responds.
	});
	const upstreamPort = await listen(upstream);
	const proxy = await startProxy(`http://127.0.0.1:${upstreamPort}`, {
		config: { ...PROXY_CONFIG, drainSettleDeadlineMs: 150 },
	});
	try {
		const stalled = fetch(`${proxy.endpoint}/attempt?seq=12`, { signal: AbortSignal.timeout(10_000) }).then(
			() => ({ error: null }),
			(error) => ({ error }),
		);
		await sleepMs(50);
		assert.equal(proxy.pending, 1, 'arm 11: the unsettled attempt must be pending before stop');
		await proxy.stop();
		assert.equal(proxy.drain.ok, false, 'arm 11: the drain check must refuse the undrained proxy');
		assert.equal(proxy.drain.pending, 1, 'arm 11: the snapshot records the unsettled attempt');
		assert.equal(proxy.drain.upstreamsRegistered, 1, 'arm 11: the snapshot records the registered upstream');
		assert.equal(proxy.drain.terminalSettled, 0, 'arm 11: nothing settled before the breach');
		const { error } = await stalled;
		assert.ok(error instanceof Error, 'arm 11: the forced teardown must release the stalled client');
	} finally {
		upstream.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 12 (scheme v4 §2.3.2 per-basis attribution closure report): each
// proxied request names its population on PROXY_CONFIG.attributionHeader and
// the report breaks requestsReceived down per basis EXACTLY — driver
// attempts, instrument requests, candidate optional work, and (failing
// closed at consumption) unattributed traffic. The shared proxy config is
// one frozen object whose digest is stable across every proxy instance a
// run constructs (the value recorded in BOTH windows' receipts and asserted
// equal at consumption).
// ---------------------------------------------------------------------------
{
	const upstream = await startStubUpstream({
		headers: { 'content-type': 'text/plain', 'content-length': '2' },
		streamed: false,
		body: Buffer.from('ok'),
	});
	const proxy = await startProxy(upstream.url);
	try {
		const mark = (header) => (header ? { [PROXY_CONFIG.attributionHeader]: header } : {});
		await fetchBody(`${proxy.endpoint}/attempt?seq=13`, { headers: mark('driver-attempt') });
		await fetchBody(`${proxy.endpoint}/attempt?seq=14`, { headers: mark('driver-attempt') });
		await fetchBody(`${proxy.endpoint}/attempt?seq=15`, { headers: mark('candidate-optional') });
		await fetchBody(`${proxy.endpoint}/attempt?seq=16`, {});
		assert.deepEqual(proxy.requestsByBasis, {
			driverAttempts: 2,
			instrumentRequests: 0,
			candidateOptional: 1,
			unattributed: 1,
		}, 'per-basis breakdown must classify every received request exactly');
		const basisSum = Object.values(proxy.requestsByBasis).reduce((sum, count) => sum + count, 0);
		assert.equal(basisSum, proxy.stats.requestsReceived, 'breakdown must reconcile with requestsReceived');
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, { requestsReceived: 4, forwarded: 4, upstreamErrors: 0, clientAborts: 0, droppedLoss: 0, droppedOutage: 0 });
		assert.ok(Object.isFrozen(PROXY_CONFIG), 'the shared proxy config must be frozen');
		const first = await startProxy(upstream.url);
		try {
			assert.equal(first.configDigest, proxy.configDigest, 'every proxy constructed from the shared config carries the SAME digest');
			assert.match(proxy.configDigest, /^[0-9a-f]{64}$/, 'the digest is a sha-256 hex string (receipt-ready)');
			assert.equal(proxy.configDigest, createHash('sha256').update(JSON.stringify(PROXY_CONFIG)).digest('hex'), 'digest binds the canonical shared config bytes');
		} finally {
			await first.stop();
		}
	} finally {
		await proxy.stop();
		upstream.server.close();
	}
}

// ---------------------------------------------------------------------------
// Arm 13 (round-2 review P1 regression, close during FINAL response
// completion): the upstream answers honestly and completely (accurate
// content-length, full body), the proxy's write chain delivers every byte and
// calls response.end() — and the client socket dies DURING the final
// completion, before the response has finished. Pre-fix the terminal counter
// had already been incremented at finishAttempt time, so the proxy recorded
// `forwarded` while the driver's body read still failed as networkDrop (the
// classification disagreement window). Post-fix, successful attempts settle
// ONLY on the response's 'finish' event; a close that lands before 'finish'
// settles through the same once-only guard as clientAbort, never forwarded.
//
// The close is injected at the one seam a black-box client cannot time
// deterministically — between the proxy's end() and the flush completing —
// by wrapping the instance's handle (the real class logic is untouched) and
// destroying the socket BEFORE the original end() runs: that ordering
// provably suppresses 'finish' on Node's HTTP server (the close fires with
// writableEnded=true and the flush unfinished — exactly the premature
// sub-case the fix routes to clientAbort).
// ---------------------------------------------------------------------------
{
	const body = Buffer.alloc(2048, 0x79);
	const upstream = await startStubUpstream({
		headers: { 'content-type': 'application/json', 'content-length': String(body.length) },
		streamed: false,
		body,
	});
	const proxy = await startProxy(upstream.url);
	try {
		const finishSpy = { count: 0 };
		const originalHandle = proxy.handle.bind(proxy);
		proxy.handle = (request, response) => {
			response.once('finish', () => {
				finishSpy.count += 1;
			});
			const end = response.end.bind(response);
			response.end = (...args) => {
				if (!response.socket.destroyed) response.socket.destroy();
				return end(...args);
			};
			originalHandle(request, response);
		};
		await assert.rejects(
			() => fetchBody(`${proxy.endpoint}/attempt?seq=17`),
			(error) => error instanceof Error,
			'arm 13: a close during final response completion must reject the client body read (the driver networkDrop shape)',
		);
		assert.equal(finishSpy.count, 0, 'arm 13: the response must never have finished (the flush did not complete)');
		await waitForTerminalSettled(proxy);
		await waitForDrained(proxy);
		assertTerminalLedgerReconciled(proxy, {
			requestsReceived: 1,
			forwarded: 0,
			upstreamErrors: 0,
			clientAborts: 1,
			droppedLoss: 0,
			droppedOutage: 0,
		});
		await proxy.stop();
		assert.equal(proxy.drain.ok, true, 'arm 13: proxy must drain cleanly at stop');
		assert.equal(proxy.drain.terminalSettled, proxy.drain.requestsReceived, 'arm 13: drain snapshot terminal ledger reconciles');
		assert.equal(proxy.drain.pending, 0, 'arm 13: no attempt may stay pending in the drain snapshot');
	} finally {
		upstream.server.close();
	}
}

process.stdout.write(
	'e6 fault-proxy hop-by-hop regression: PASS (RFC 9110 §7.6.1 stripping unit arm; chunked-upstream, content-length-upstream, loss-drop, outage-drop integration arms; close-during-takeTokens, upstream-response-error, request-side-strip wave-1 B7 arms; scheme v4 pre-headers-disconnect [latency + pending-headers], mid-body-disconnect, undrained-proxy-refusal, per-basis-attribution arms; round-2 close-during-final-completion + full-ledger-reconciliation arms)\n',
);
