"""Author the listener oracle's stimuli (v2-requests.json). It never produces or
overwrites Go's recorded responses: those come only from the frozen Go listener
via mailserver/internal/federation/listener_oracle_record_test.go."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SEED = [
    "INSERT INTO domains(id,name,is_local) VALUES(9346001,'zulu.test',true)",
    "INSERT INTO users(id,username,email,display_name,domain_id,password_hash) VALUES(9346011,'carol','carol@zulu.test','Carol',9346001,'x')",
    "INSERT INTO mailboxes(id,user_id,domain_id,email,display_name,type,is_primary) VALUES(9346021,9346011,9346001,'carol@zulu.test','Carol','personal',true)",
]
ALLOW = [
    {"domain": "alpha.test", "ca": "alpha", "scope": "dm", "enabled": True},
    {"domain": "bravo.test", "ca": "bravo", "scope": "room", "enabled": True},
    {"domain": "charlie.test", "ca": "charlie", "scope": "dm", "enabled": True},
]
CHAT = "application/x-setjoin-chat"
ROOM = "application/x-setjoin-room"
ADV = "application/x-setjoin-advisory"


def js(o):
    return json.dumps(o, separators=(",", ":"), ensure_ascii=False)


def frame(kind, stanza=None, payload=None):
    f = {"kind": kind}
    if stanza is not None:
        f["stanzaId"] = stanza
    if payload is not None:
        f["payload"] = payload
    return js(f)


def hello(domain="alpha.test", **extra):
    p = {"fromDomain": domain, "ver": 1}
    p.update(extra)
    return {"op": "send", "body": frame("hello", payload=p)}


def send(body):
    return {"op": "send", "body": body}


def msg(seq, stanza, ct, payload):
    return send(
        frame("msg", stanza, {"peerSeq": seq, "contentType": ct, "payload": payload})
    )


def chat(
    seq,
    body="hi carol",
    cid=None,
    frm="alice@alpha.test",
    to="carol@zulu.test",
    stanza=None,
    **extra,
):
    cid = cid or f"c{seq}"
    p = {"fromAddr": frm, "toAddr": to, "body": body, "clientMsgId": cid}
    p.update(extra)
    return msg(seq, stanza or cid, CHAT, p)


def read(n, timeout_ms=3000, conn=0):
    return {"op": "read", "n": n, "timeout_ms": timeout_ms, "conn": conn}


def quiet(ms=400, conn=0):
    return {"op": "quiet", "ms": ms, "conn": conn}


def sql(s):
    return {"op": "sql", "sql": s}


def enqueue(peer, stanza, ct, payload):
    return sql(
        f"SELECT federation_enqueue('{peer}','{stanza}','{ct}','{json.dumps(payload).replace(chr(39), chr(39) * 2)}'::jsonb)"
    )


CASES = []


def case(name, steps, identity="alpha", allow=None, seed=None, **kw):
    c = {
        "name": name,
        "identity": identity,
        "allow": ALLOW if allow is None else allow,
        "sql": SEED if seed is None else seed,
        "steps": steps,
    }
    c.update(kw)
    CASES.append(c)


def ok(name, identity, domain):
    case(name, [hello(domain), read(1), quiet(300)], identity=identity)


# ---- handshake outcomes
ok("hs_ok_ed25519_no_eku", "alpha", "alpha.test")
ok("hs_ok_p256_server_client_eku", "bravo", "bravo.test")
ok("hs_ok_rsa_email_eku_only", "charlie", "charlie.test")
case(
    "hs_ok_case_insensitive_keys",
    [
        send(
            '{"KIND":"hello","Payload":{"FromDomain":"alpha.test","VER":1,"caps":["x"],"resumeFromSeq":5}}'
        ),
        read(1),
        quiet(300),
    ],
)
case(
    "hs_ok_unicode_fold_keys",
    [send('{"KIND":"hello","Payload":{"fromDomain":"alpha.test","ver":1}}'), read(1)],
)
case(
    "hs_ok_extra_fields",
    [
        send(
            '{"kind":"hello","stanzaId":"zz","extra":[1,{"a":null}],"payload":{"fromDomain":"alpha.test","ver":9,"unknown":true}}'
        ),
        read(1),
    ],
)
case(
    "hs_ok_whitespace_frame",
    [
        send(' {\n "kind" : "hello" , "payload" : { "fromDomain" : "alpha.test" } } '),
        read(1),
    ],
)
case("hs_unknown_domain_no_row", [hello("unknown.test"), read(1)], identity="unknown")
case("hs_impostor_cert_wrong_ca", [hello("alpha.test"), read(1)], identity="impostor")
case("hs_expired_cert", [hello("alpha.test"), read(1)], identity="expired")
case("hs_not_yet_valid_cert", [hello("alpha.test"), read(1)], identity="notyet")
case("hs_cert_san_mismatch", [hello("alpha.test"), read(1)], identity="wrongsan")
case("hs_hello_claims_other_domain", [hello("bravo.test"), read(1)], identity="alpha")
case(
    "hs_row_disabled",
    [hello("alpha.test"), read(1)],
    allow=[{"domain": "alpha.test", "ca": "alpha", "scope": "dm", "enabled": False}],
)
case(
    "hs_row_room_scope_ok",
    [hello("alpha.test"), read(1)],
    allow=[{"domain": "alpha.test", "ca": "alpha", "scope": "room", "enabled": True}],
)
case("hs_first_frame_not_hello", [chat(1), read(1)])
case("hs_hello_malformed_json", [send("{"), read(1)])
case("hs_hello_array_frame", [send("[1,2]"), read(1)])
case("hs_hello_null_frame", [send("null"), read(1)])
case(
    "hs_hello_null_payload",
    [send(frame("hello", payload=None).replace("}", ',"payload":null}', 1)), read(1)],
)
case("hs_hello_missing_payload", [send('{"kind":"hello"}'), read(1)])
case("hs_hello_payload_not_object", [send('{"kind":"hello","payload":"x"}'), read(1)])
case("hs_hello_kind_wrong_type", [send('{"kind":1}'), read(1)])
case("hs_oversize_length_prefix", [{"op": "raw_hex", "hex": "01000001"}, read(1)])
case("hs_zero_length_frame", [{"op": "raw_hex", "hex": "00000000"}, read(1)])
case(
    "hs_lone_surrogate_domain",
    [send('{"kind":"hello","payload":{"fromDomain":"alpha.test\\ud800"}}'), read(1)],
)
case(
    "hs_hello_then_hello_again",
    [
        hello(),
        read(1),
        hello(),
        quiet(300),
        send(frame("ack", payload={"peerSeq": 0})),
        quiet(300),
    ],
)

# ---- inbound chat
case("chat_applied", [hello(), read(1), chat(1), read(1), quiet(300)])
case(
    "chat_duplicate_acked",
    [hello(), read(1), chat(1), read(1), chat(1), read(1), chat(2), read(1)],
)
case(
    "chat_sequence_run",
    [hello(), read(1)] + [step for i in range(1, 6) for step in [chat(i), read(1)]],
)
case(
    "chat_gap_requests_replay",
    [
        hello(),
        read(1),
        chat(3),
        read(1),
        chat(1),
        read(1),
        chat(2),
        read(1),
        chat(3),
        read(1),
    ],
)
case(
    "chat_gap_after_progress",
    [hello(), read(1), chat(1), read(1), chat(5), read(1), chat(2), read(1)],
)
case(
    "chat_stale_seq_below_cursor",
    [
        hello(),
        read(1),
        chat(1),
        read(1),
        chat(2),
        read(1),
        chat(1, cid="again"),
        read(1),
    ],
)
case(
    "chat_poison_spoofed_from",
    [hello(), read(1), chat(1, frm="mallory@bravo.test"), read(1), chat(2), read(1)],
)
case(
    "chat_poison_unknown_recipient",
    [hello(), read(1), chat(1, to="nobody@zulu.test"), read(1)],
)
case(
    "chat_poison_missing_body",
    [
        hello(),
        read(1),
        msg(
            1,
            "m1",
            CHAT,
            {
                "fromAddr": "alice@alpha.test",
                "toAddr": "carol@zulu.test",
                "clientMsgId": "x",
            },
        ),
        read(1),
    ],
)
case(
    "chat_poison_long_client_msg_id",
    [hello(), read(1), chat(1, cid="c" * 600), read(1)],
)
case(
    "chat_poison_long_from",
    [hello(), read(1), chat(1, frm="a" * 330 + "@alpha.test"), read(1)],
)
case(
    "chat_poison_body_over_64k",
    [hello(), read(1), chat(1, body="x" * 65537), read(1, 5000)],
)
case(
    "chat_body_64k_exact", [hello(), read(1), chat(1, body="y" * 65536), read(1, 5000)]
)
case(
    "chat_quarantine_mixed_charset",
    [hello(), read(1), chat(1, body="hello мир привет friends"), read(1)],
)
case(
    "chat_quarantine_fake_html",
    [hello(), read(1), chat(1, body='<span style="display:none">x</span> hi'), read(1)],
)
case(
    "chat_html_and_unicode_body",
    [hello(), read(1), chat(1, body='a<b>&"c"   é 😀', cid="x<y>&z"), read(1)],
)
case(
    "chat_nul_escape_in_body",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"n1","payload":{{"peerSeq":1,"contentType":"{CHAT}","payload":{{"fromAddr":"alice@alpha.test","toAddr":"carol@zulu.test","body":"a\\u0000b","clientMsgId":"n1"}}}}}}'
        ),
        read(1),
        chat(2),
        read(1),
    ],
)
case(
    "chat_lone_surrogate_in_body",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"n1","payload":{{"peerSeq":1,"contentType":"{CHAT}","payload":{{"fromAddr":"alice@alpha.test","toAddr":"carol@zulu.test","body":"a\\ud800b","clientMsgId":"n1"}}}}}}'
        ),
        read(1),
        chat(2),
        read(1),
    ],
)
case(
    "chat_valid_surrogate_pair_body",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"n1","payload":{{"peerSeq":1,"contentType":"{CHAT}","payload":{{"fromAddr":"alice@alpha.test","toAddr":"carol@zulu.test","body":"a\\ud83d\\ude00b","clientMsgId":"n1"}}}}}}'
        ),
        read(1),
    ],
)
case(
    "chat_nul_in_stanza_id",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"a\\u0000b","payload":{{"peerSeq":1,"contentType":"{CHAT}","payload":{{"x":1}}}}}}'
        ),
        read(1),
        chat(2),
        read(1),
    ],
)
case(
    "chat_nul_in_content_type",
    [
        hello(),
        read(1),
        send(
            '{"kind":"msg","stanzaId":"s","payload":{"peerSeq":1,"contentType":"a\\u0000b","payload":{"x":1}}}'
        ),
        read(1),
    ],
)
case(
    "chat_ack_echoes_stanza_special",
    [hello(), read(1), chat(1, stanza='s<1>&é"\\'), read(1)],
)
case(
    "chat_ack_stanza_invalid_utf8",
    [
        hello(),
        read(1),
        {
            "op": "raw_hex",
            "hex": "{:08x}".format(
                len(
                    b'{"kind":"msg","stanzaId":"\xff\xfe","payload":{"peerSeq":1,"contentType":"x","payload":{}}}'
                )
            )
            + b'{"kind":"msg","stanzaId":"\xff\xfe","payload":{"peerSeq":1,"contentType":"x","payload":{}}}'.hex(),
        },
        read(1),
    ],
)
case(
    "chat_payload_null",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"s","payload":{{"peerSeq":1,"contentType":"{CHAT}","payload":null}}}}'
        ),
        read(1),
    ],
)
case(
    "chat_payload_missing",
    [
        hello(),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"s","payload":{{"peerSeq":1,"contentType":"{CHAT}"}}}}'
        ),
        read(1),
    ],
)
case("chat_peerseq_zero", [hello(), read(1), chat(0), read(1)])
case(
    "chat_two_peers_independent_cursors",
    [hello(), read(1), chat(1), read(1)],
    identity="alpha",
)
case("chat_big_peerseq_gap", [hello(), read(1), chat(9007199254740993), read(1)])

# ---- other content types
case(
    "unknown_content_type_redacted",
    [
        hello(),
        read(1),
        msg(1, "u1", "text/plain", {"secret": "do not store"}),
        read(1),
        msg(2, "u2", "application/json", [1, 2, 3]),
        read(1),
    ],
)
case(
    "unknown_content_type_dup",
    [
        hello(),
        read(1),
        msg(1, "u1", "text/plain", {"a": 1}),
        read(1),
        msg(1, "u1", "text/plain", {"a": 1}),
        read(1),
    ],
)
case(
    "unknown_content_type_gap",
    [hello(), read(1), msg(4, "u1", "text/plain", {"a": 1}), read(1)],
)
case(
    "unknown_content_type_nul_payload",
    [
        hello(),
        read(1),
        send(
            '{"kind":"msg","stanzaId":"s","payload":{"peerSeq":1,"contentType":"text/plain","payload":{"a":"\\u0000"}}}'
        ),
        read(1),
    ],
)
case(
    "unknown_content_type_empty",
    [hello(), read(1), msg(1, "u1", "", {"a": 1}), read(1)],
)
case(
    "unknown_content_type_big",
    [hello(), read(1), msg(1, "u1", "text/plain", {"a": "z" * 70000}), read(1, 5000)],
)
case(
    "room_message_unknown_room",
    [
        hello("bravo.test"),
        read(1),
        msg(
            1,
            "r1",
            ROOM,
            {
                "op": "message",
                "roomId": "nope@zulu.test",
                "fromAddr": "bob@bravo.test",
                "body": "hi",
                "clientMsgId": "r1",
            },
        ),
        read(1),
    ],
    identity="bravo",
)
case(
    "room_invite_unknown_room",
    [
        hello("bravo.test"),
        read(1),
        msg(
            1,
            "r1",
            ROOM,
            {"op": "invite", "roomId": "nope@bravo.test", "originDomain": "bravo.test"},
        ),
        read(1),
    ],
    identity="bravo",
)
case(
    "room_advisory_frame",
    [
        hello("bravo.test"),
        read(1),
        msg(1, "a1", ADV, {"op": "room_revoked", "roomId": "nope@zulu.test"}),
        read(1),
    ],
    identity="bravo",
)
case(
    "room_spam_scan_body",
    [
        hello("bravo.test"),
        read(1),
        msg(
            1,
            "r1",
            ROOM,
            {
                "op": "message",
                "roomId": "nope@zulu.test",
                "body": "hello мир привет friends",
            },
        ),
        read(1),
    ],
    identity="bravo",
)
case(
    "room_gap",
    [hello("bravo.test"), read(1), msg(3, "r1", ROOM, {"op": "message"}), read(1)],
    identity="bravo",
)
case(
    "room_nul_payload",
    [
        hello("bravo.test"),
        read(1),
        send(
            f'{{"kind":"msg","stanzaId":"s","payload":{{"peerSeq":1,"contentType":"{ROOM}","payload":{{"op":"message","body":"\\u0000"}}}}}}'
        ),
        read(1),
    ],
    identity="bravo",
)

# ---- ephemeral, unknown kinds, bad frames mid-stream
typing = lambda **k: send(frame("ephemeral", payload=dict({"op": "typing"}, **k)))
case(
    "eph_typing_dm",
    [
        hello(),
        read(1),
        typing(fromAddr="alice@alpha.test", toAddr="carol@zulu.test"),
        quiet(400),
        chat(1),
        read(1),
    ],
)
case(
    "eph_non_typing_dropped",
    [
        hello(),
        read(1),
        send(frame("ephemeral", payload={"op": "presence"})),
        quiet(300),
        chat(1),
        read(1),
    ],
)
case(
    "eph_malformed_dropped",
    [
        hello(),
        read(1),
        send('{"kind":"ephemeral","payload":"x"}'),
        send('{"kind":"ephemeral"}'),
        quiet(300),
        chat(1),
        read(1),
    ],
)
case(
    "eph_storm_throttled",
    [hello(), read(1)]
    + [typing(fromAddr="alice@alpha.test", toAddr="carol@zulu.test")] * 12
    + [quiet(400), chat(1), read(1)],
)
case(
    "unknown_kind_ignored",
    [
        hello(),
        read(1),
        send(frame("bogus", payload={"a": 1})),
        quiet(300),
        chat(1),
        read(1),
    ],
)
case(
    "empty_kind_ignored",
    [hello(), read(1), send("null"), send("{}"), quiet(300), chat(1), read(1)],
)
case(
    "hello_midstream_ignored",
    [hello(), read(1), hello("bravo.test"), quiet(300), chat(1), read(1)],
)
case(
    "bad_envelope_array_halts",
    [hello(), read(1), send('{"kind":"msg","payload":[]}'), read(1)],
)
case(
    "bad_envelope_no_payload_halts", [hello(), read(1), send('{"kind":"msg"}'), read(1)]
)
case(
    "bad_envelope_float_seq_halts",
    [hello(), read(1), send('{"kind":"msg","payload":{"peerSeq":1.5}}'), read(1)],
)
case(
    "bad_ack_payload_halts",
    [hello(), read(1), send('{"kind":"ack","payload":"x"}'), read(1)],
)
case(
    "bad_ack_missing_payload_halts", [hello(), read(1), send('{"kind":"ack"}'), read(1)]
)
case("bad_json_midstream_halts", [hello(), read(1), send("{not json"), read(1)])
case(
    "ack_empty_object_is_zero",
    [hello(), read(1), send(frame("ack", payload={})), quiet(300), chat(1), read(1)],
)

# ---- server-initiated sends (outbox)
P = lambda i: {
    "fromAddr": "carol@zulu.test",
    "toAddr": "alice@alpha.test",
    "body": f"out {i} <b>&",
    "n": 1.50,
    "big": 12345678901234567890,
    "k": [1, {"z": None}],
}
OUT3 = [enqueue("alpha.test", f"o{i}", CHAT, P(i)) for i in (1, 2, 3)]
case("out_drain_in_order", OUT3 + [hello(), read(1), read(3), quiet(300)])
case(
    "out_ack_advances",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("ack", payload={"peerSeq": 2})),
        quiet(300),
    ],
)
case(
    "out_ack_then_new_rows",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("ack", payload={"peerSeq": 3})),
        enqueue("alpha.test", "o4", CHAT, P(4)),
        read(1),
    ],
)
case(
    "out_new_row_wakes_sender",
    [
        hello(),
        read(1),
        enqueue("alpha.test", "o1", CHAT, P(1)),
        read(1),
        enqueue("alpha.test", "o2", ROOM, {"op": "message"}),
        read(1),
    ],
)
case(
    "out_ack_forged_future_halts",
    OUT3
    + [hello(), read(1), read(3), send(frame("ack", payload={"peerSeq": 99})), read(1)],
)
case(
    "out_ack_negative_halts",
    OUT3
    + [hello(), read(1), read(3), send(frame("ack", payload={"peerSeq": -1})), read(1)],
)
case(
    "out_ack_before_send_halts",
    [hello(), read(1), send(frame("ack", payload={"peerSeq": 1})), read(1)],
)
case(
    "out_receipt_acts_as_ack",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("receipt", payload={"peerSeq": 3})),
        quiet(300),
    ],
)
case(
    "out_replay_req_rewinds",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("replay_req", payload={"peerSeq": 2})),
        read(2),
        quiet(300),
    ],
)
case(
    "out_replay_req_from_one",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("replay_req", payload={"peerSeq": 1})),
        read(3),
    ],
)
case(
    "out_replay_req_future_halts",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("replay_req", payload={"peerSeq": 10})),
        read(1),
    ],
)
case(
    "out_replay_req_at_next_ok",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("replay_req", payload={"peerSeq": 4})),
        quiet(300),
    ],
)
case(
    "out_replay_clamped_to_ack",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("ack", payload={"peerSeq": 2})),
        send(frame("replay_req", payload={"peerSeq": 1})),
        read(1),
        quiet(300),
    ],
)
case(
    "out_replay_negative_halts",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("replay_req", payload={"peerSeq": -3})),
        read(1),
    ],
)
case(
    "out_reconnect_resumes_after_ack",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        send(frame("ack", payload={"peerSeq": 1})),
        quiet(300),
        {"op": "reconnect"},
        hello(),
        read(1),
        read(2),
        quiet(300),
    ],
)
case(
    "out_reconnect_unacked_resends_all",
    OUT3 + [hello(), read(1), read(3), {"op": "reconnect"}, hello(), read(1), read(3)],
)
case(
    "out_window_256",
    [
        sql(
            f"SELECT count(federation_enqueue('alpha.test','w'||g,'{CHAT}','{{\"i\":1}}'::jsonb)) FROM generate_series(1,300) g"
        ),
        hello(),
        read(1),
        read(256, 20000),
        quiet(500),
        send(frame("ack", payload={"peerSeq": 100})),
        read(44, 10000),
        quiet(300),
    ],
)
case(
    "out_and_in_interleaved",
    OUT3
    + [
        hello(),
        read(1),
        read(3),
        chat(1),
        read(1),
        send(frame("ack", payload={"peerSeq": 3})),
        chat(2),
        read(1),
    ],
)
case(
    "out_payload_shapes",
    [
        sql(
            "SELECT federation_enqueue('alpha.test','sh1','x/y','[1, 2.0, \"<&>\", null, true, {\"a\": {}}]'::jsonb)"
        ),
        sql(
            "SELECT federation_enqueue('alpha.test','sh2','x/y','\"plain \\u2028 string\"'::jsonb)"
        ),
        sql("SELECT federation_enqueue('alpha.test','sh3','x/y','null'::jsonb)"),
        sql(
            "SELECT federation_enqueue('alpha.test','st<h>&4','x/y','123456789012345678901234567890.5e3'::jsonb)"
        ),
        hello(),
        read(1),
        read(4),
    ],
)
case(
    "out_other_peer_rows_not_sent",
    [enqueue("bravo.test", "b1", CHAT, P(1))]
    + OUT3
    + [hello(), read(1), read(3), quiet(300)],
)

# ---- dynamic gates and stream registry
case(
    "dyn_evict_on_disable",
    [
        hello(),
        read(1),
        sql(
            "UPDATE federation_allowlist SET enabled=false WHERE peer_domain='alpha.test'"
        ),
        sql("SELECT app_notify('federation_allowlist_changed','{}')"),
        read(1, 5000),
    ],
)
case(
    "dyn_evict_on_delete",
    [
        hello(),
        read(1),
        sql("DELETE FROM federation_allowlist WHERE peer_domain='alpha.test'"),
        sql("SELECT app_notify('federation_allowlist_changed','{}')"),
        read(1, 5000),
    ],
)
case(
    "dyn_flag_off_evicts",
    [hello(), read(1), {"op": "flag", "value": False}, read(1, 5000)],
)
case(
    "dyn_flag_off_then_on_reaccepts",
    [
        hello(),
        read(1),
        {"op": "flag", "value": False},
        read(1, 5000),
        {"op": "flag", "value": True},
        {"op": "reconnect"},
        hello(),
        read(1),
        chat(1),
        read(1),
    ],
)
case(
    "dyn_supersede_old_stream_closed",
    [
        hello(),
        read(1),
        {"op": "open", "conn": 1},
        {**hello(), "conn": 1},
        read(1, 3000, 1),
        read(1, 3000, 0),
        {**chat(1), "conn": 1},
        read(1, 3000, 1),
    ],
)
case(
    "dyn_flag_off_at_boot_never_accepts",
    [{"op": "connect_timeout", "ms": 1500}],
    flag_initial=False,
)
case(
    "dyn_reconnect_continues_inbox",
    [
        hello(),
        read(1),
        chat(1),
        read(1),
        {"op": "reconnect"},
        hello(),
        read(1),
        chat(1),
        read(1),
        chat(2),
        read(1),
    ],
)

# A peer may receive Go's last write before Go updates its sentCursor. A
# zero-latency receipt then spuriously trips its forged-ack guard. Model the
# receiving peer's apply/ack latency explicitly; retain the original recording
# unchanged as evidence of this Go race. No response bytes are normalized.
for c in CASES:
    if c["name"].startswith("out_"):
        settled = []
        for step in c["steps"]:
            settled.append(step)
            if step["op"] == "read" and step["n"] > 1:
                settled.append({"op": "sleep", "ms": 100})
        c["steps"] = settled

(ROOT / "v2-requests.json").write_text(
    json.dumps({"cases": CASES}, indent=1, ensure_ascii=False) + "\n"
)
print(len(CASES), "cases")
