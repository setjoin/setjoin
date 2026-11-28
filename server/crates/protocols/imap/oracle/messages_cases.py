#!/usr/bin/env python3
"""Author IMAP FETCH/SEARCH/STORE stimuli (#344). Stimuli only: the Go recorder
(listener_oracle_messages_record_test.go) fills `response` and `effects`.
Same step grammar as cases.py; extra action kind `sql` runs owner SQL on both sides."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ALICE = "imap2-app-token-alice"
BOB = "imap2-app-token-bob"


def step(request, until, **extra):
    return dict(request=request, until=until, **extra)


def cmd(tag, text):
    return step(f"{tag} {text}\r\n", tag)


def login(tag="l1", user="alice@imap2.test", token=ALICE):
    return cmd(tag, f'LOGIN "{user}" "{token}"')


def select(folder="Inbox", tag="s1"):
    return cmd(tag, f"SELECT {folder}")


def run(name, steps, **extra):
    return dict(name=name, transport="plain", steps=steps, **extra)


def build():
    s = []
    s.append(run("fetch-before-select", [
        cmd("a1", "FETCH 1 (FLAGS)"), cmd("a2", "UID FETCH 1 (FLAGS)"), cmd("a3", "SEARCH ALL"),
        cmd("a4", "STORE 1 +FLAGS (\\Seen)"), cmd("a5", "UID SEARCH ALL"), cmd("a6", "UID"),
        login(), cmd("b1", "FETCH 1:* (FLAGS)"), cmd("b2", "SEARCH ALL"), cmd("b3", "STORE 1 FLAGS ()"),
        cmd("b4", "UID STORE 1 FLAGS ()"), cmd("b5", "UID"), cmd("b6", "UID FETCH 1"),
        select("Nope", "c1"), cmd("c2", "FETCH 1:*"), cmd("c3", "SEARCH ALL"),
        select(tag="c4"), cmd("c5", "UNSELECT"), cmd("c6", "FETCH 1:*"), cmd("c7", "UID SEARCH ALL"),
    ]))
    s.append(run("fetch-sequence-forms", [
        login(), select(),
        cmd("f01", "FETCH 1 (FLAGS)"), cmd("f02", "FETCH 1:* (FLAGS UID)"), cmd("f03", "FETCH * (FLAGS)"),
        cmd("f04", "FETCH 2:3 (FLAGS)"), cmd("f05", "FETCH 1,3,5 (UID)"), cmd("f06", "FETCH 3:1 (UID)"),
        cmd("f07", "FETCH 99 (UID)"), cmd("f08", "FETCH 0 (UID)"), cmd("f09", "FETCH abc (UID)"),
        cmd("f10", "FETCH"), cmd("f11", "FETCH 1:2(FLAGS)"), cmd("f12", "FETCH (FLAGS)"),
        cmd("f13", "FETCH 1:2,*:6 (UID)"), cmd("f14", "FETCH 2,2,1:3 (UID)"), cmd("f15", "FETCH 4:* BODY[]"),
        cmd("f16", "fetch 1 (ENVELOPE)"), cmd("f17", "FETCH 1:1,x,2 (UID)"), cmd("f18", "FETCH +2 (UID)"),
        cmd("f19", "FETCH -1 (UID)"), cmd("f20", "FETCH 1:*:3 (UID)"), cmd("f21", "FETCH 1: (UID)"),
        cmd("f22", "FETCH :2 (UID)"), cmd("f23", "FETCH *:* (UID)"), step("f24\tFETCH\t1\t(UID)\r\n", "f24"),
    ]))
    s.append(run("fetch-uid-forms", [
        login(), select(),
        cmd("u01", "UID FETCH 5 (FLAGS)"), cmd("u02", "UID FETCH 3:* (UID)"), cmd("u03", "UID FETCH 4 (UID)"),
        cmd("u04", "UID FETCH * (UID)"), cmd("u05", "UID FETCH 12:20 (UID)"), cmd("u06", "UID FETCH 20:3 (UID)"),
        cmd("u07", "UID FETCH 1,3,99 (UID)"), cmd("u08", "UID FETCH"), cmd("u09", "UID FETCH abc"),
        cmd("u10", "UID FOO 1"), cmd("u11", "uid fetch 11 (UID)"), cmd("u12", "UID EXPUNGE 1"),
        cmd("u13", "UID FETCH 8:9 (UID)"), cmd("u14", "UID SEARCH ALL"),
    ]))
    s.append(run("fetch-other-tag", [
        login(), select("Project"), cmd("p1", "FETCH 1:* (FLAGS)"), cmd("p2", "UID FETCH 2 (UID)"),
        cmd("p3", "SEARCH ALL"), cmd("p4", "UID SEARCH UNSEEN"), select("Label", "p5"),
        cmd("p6", "FETCH 1:*"), cmd("p7", "SEARCH ALL"),
    ]))
    s.append(run("search-flags-and-text", [
        login(), select(),
        cmd("s01", "SEARCH"), cmd("s02", "SEARCH ALL"), cmd("s03", "SEARCH SEEN"), cmd("s04", "SEARCH UNSEEN"),
        cmd("s05", "SEARCH DELETED"), cmd("s06", "SEARCH UNDELETED"), cmd("s07", "SEARCH ANSWERED"),
        cmd("s08", "SEARCH UNANSWERED"), cmd("s09", "SEARCH FLAGGED"), cmd("s10", "SEARCH UNFLAGGED"),
        cmd("s11", "SEARCH DRAFT"), cmd("s12", "SEARCH UNDRAFT"), cmd("s13", "SEARCH NEW"),
        cmd("s14", "SEARCH RECENT"), cmd("s15", "SEARCH seen flagged"), cmd("s16", "SEARCH UNSEEN UNFLAGGED"),
        cmd("s17", "SEARCH FROM bob"), cmd("s18", 'SEARCH FROM "EXAMPLE.ORG"'), cmd("s19", "SEARCH SUBJECT hello"),
        cmd("s20", 'SEARCH SUBJECT "needle"'), cmd("s21", "SEARCH TEXT needle"), cmd("s22", "SEARCH BODY needle"),
        cmd("s23", "SEARCH BODY 50%"), cmd("s24", "SEARCH BODY off_and"), cmd("s25", "SEARCH FROM"),
        cmd("s26", "SEARCH SUBJECT"), cmd("s27", 'SEARCH SUBJECT "Quote \\"me\\""'), cmd("s28", "SEARCH SUBJECT Quote"),
        cmd("s29", 'SEARCH SUBJECT """hello"""'), cmd("s30", "SEARCH FROM x SUBJECT"),
        cmd("s31", "SEARCH TEXT ''"), cmd("s32", 'SEARCH SUBJECT ""'), cmd("s33", "search all"),
        cmd("s34", "SEARCH FROM e%"), cmd("s35", "SEARCH FROM _ob"),
    ]))
    s.append(run("search-header-keyword-unknown", [
        login(), select(),
        cmd("h01", "SEARCH HEADER Message-ID <mid-5@imap2.test>"), cmd("h02", 'SEARCH HEADER "message-id" "<mid-3@imap2.test>"'),
        cmd("h03", "SEARCH HEADER Subject Hello"), cmd("h04", "SEARCH HEADER Message-ID"), cmd("h05", "SEARCH HEADER"),
        cmd("h06", "SEARCH KEYWORD Label"), cmd("h07", "SEARCH KEYWORD label"), cmd("h08", "SEARCH KEYWORD Project"),
        cmd("h09", 'SEARCH KEYWORD "Label"'), cmd("h10", "SEARCH KEYWORD"), cmd("h11", "SEARCH KEYWORD Nope"),
        cmd("h12", "SEARCH SINCE 1-Jan-2020"), cmd("h13", "SEARCH OR SEEN FLAGGED"), cmd("h14", "SEARCH NOT SEEN"),
        cmd("h15", "SEARCH 1:3"), cmd("h16", "SEARCH CHARSET UTF-8 SUBJECT hello"), cmd("h17", "SEARCH UID 3:5"),
        cmd("h18", "SEARCH KEYWORD Label UNSEEN"), cmd("h19", "SEARCH LARGER 1000"), cmd("h20", "SEARCH RETURN (ALL) SEEN"),
        cmd("h21", "SEARCH (SEEN)"), cmd("h22", "SEARCH HEADER Message-ID x y z"),
    ]))
    s.append(run("uid-search-forms", [
        login(), select(),
        cmd("q1", "UID SEARCH ALL"), cmd("q2", "UID SEARCH UNSEEN"), cmd("q3", "UID SEARCH FROM example"),
        cmd("q4", "UID SEARCH SUBJECT nothingmatches"), cmd("q5", "UID SEARCH"), cmd("q6", "uid search deleted"),
        cmd("q7", "UID SEARCH KEYWORD Label"), cmd("q8", "SEARCH DELETED UNSEEN"),
        step("q9\tUID\tSEARCH\tSEEN\r\n", "q9"), cmd("q10", "UID  SEARCH   FLAGGED"),
    ]))
    s.append(run("store-relative-flags", [
        login(), select(),
        cmd("t01", "STORE 1 +FLAGS (\\Seen)"), cmd("t02", "STORE 1 +FLAGS (\\Seen)"), cmd("t03", "STORE 2 -FLAGS (\\Flagged)"),
        cmd("t04", "STORE 3 +FLAGS (\\Answered \\Draft)"), cmd("t05", "STORE 1:2 -FLAGS (\\Seen \\Answered)"),
        cmd("t06", "STORE 1 +FLAGS \\Seen"), cmd("t07", "STORE 1 +FLAGS (\\seen \\FLAGGED)"),
        cmd("t08", "STORE 1 +FLAGS (\\Unknown $custom)"), cmd("t09", "STORE 1 +FLAGS ()"),
        cmd("t10", "STORE 2 +flags (\\Seen)"), cmd("t11", "STORE * -FLAGS (\\Seen)"), cmd("t12", "STORE 99 +FLAGS (\\Seen)"),
        cmd("t13", "STORE 1 +FLAGS (\\Seen"), cmd("t14", "STORE 1 +FLAGS \\Seen \\Flagged"),
        cmd("t15", "FETCH 1:* (FLAGS)"), cmd("t16", "SEARCH UNSEEN"),
    ]))
    s.append(run("store-replace-and-silent", [
        login(), select(),
        cmd("r01", "STORE 1 FLAGS (\\Flagged)"), cmd("r02", "STORE 2 FLAGS ()"), cmd("r03", "STORE 1:3 FLAGS (\\Seen \\Draft)"),
        cmd("r04", "STORE 1 FLAGS.SILENT (\\Answered)"), cmd("r05", "STORE 2 +FLAGS.SILENT (\\Seen)"),
        cmd("r06", "STORE 2 -FLAGS.SILENT (\\Seen)"), cmd("r07", "STORE 1 flags.silent (\\Seen)"),
        cmd("r08", "STORE 1 BOGUS (\\Seen)"), cmd("r09", "STORE 1 FLAGS.SILENT"), cmd("r10", "STORE 1 +FLAGS"),
        cmd("r11", "STORE 1"), cmd("r12", "STORE"), cmd("r13", "STORE x +FLAGS (\\Seen)"), cmd("r14", "STORE 0 +FLAGS (\\Seen)"),
        cmd("r15", "STORE 1:* FLAGS.SILENT (\\Seen \\Flagged)"), cmd("r16", "FETCH 1:* (FLAGS)"),
    ]))
    s.append(run("store-deleted-flag", [
        login(), select(),
        cmd("d01", "STORE 1 +FLAGS (\\Deleted)"), cmd("d02", "SEARCH ALL"), cmd("d03", "FETCH 1:* (FLAGS)"),
        cmd("d04", "STORE 1 -FLAGS (\\Deleted)"), cmd("d05", "SEARCH DELETED"), cmd("d06", "STORE 4 -FLAGS (\\Deleted)"),
        cmd("d07", "STORE 2 FLAGS (\\Deleted \\Seen)"), cmd("d08", "STORE 1:* +FLAGS.SILENT (\\Deleted)"),
        cmd("d09", "FETCH 1:*"), cmd("d10", "SEARCH ALL"), cmd("d11", "UID SEARCH DELETED"),
        cmd("d12", "STORE 1:* -FLAGS.SILENT (\\Deleted)"), cmd("d13", "SEARCH DELETED"),
    ]))
    s.append(run("uid-store-forms", [
        login(), select(),
        cmd("w01", "UID STORE 5 +FLAGS (\\Seen)"), cmd("w02", "UID STORE 3:5 -FLAGS (\\Seen)"), cmd("w03", "UID STORE 4 +FLAGS (\\Seen)"),
        cmd("w04", "UID STORE 14:* FLAGS (\\Answered)"), cmd("w05", "UID STORE * +FLAGS.SILENT (\\Flagged)"),
        cmd("w06", "UID STORE 1 +FLAGS (\\Seen)"), cmd("w07", "UID STORE 5"), cmd("w08", "UID STORE"),
        cmd("w09", "UID STORE x +FLAGS (\\Seen)"), cmd("w10", "UID STORE 20:3 +FLAGS (\\Draft)"),
        cmd("w11", "FETCH 1:* (FLAGS)"),
    ]))
    s.append(run("store-read-only-and-project", [
        login(), cmd("e0", "EXAMINE Inbox"), cmd("e1", "STORE 1 +FLAGS (\\Seen)"), cmd("e2", "UID STORE 3 +FLAGS (\\Seen)"),
        cmd("e3", "STORE"), cmd("e4", "STORE 1 BOGUS"), cmd("e5", "FETCH 1:2 (FLAGS)"), cmd("e6", "SEARCH ALL"),
        select("Project", "e7"), cmd("e8", "STORE 1 +FLAGS (\\Seen)"), cmd("e9", "STORE 2 -FLAGS (\\Seen)"),
        cmd("e10", "UID STORE 1:2 FLAGS (\\Flagged)"), cmd("e11", "FETCH 1:* (FLAGS)"),
    ]))
    s.append(run("cross-mailbox-isolation", [
        login("l1", "bob@imap2.test", BOB), select(),
        cmd("b1", "FETCH 1:* (FLAGS)"), cmd("b2", "UID FETCH 1:* (UID)"), cmd("b3", "SEARCH ALL"),
        cmd("b4", "SEARCH FROM example"), cmd("b5", "UID SEARCH KEYWORD Label"), cmd("b6", "STORE 1:* +FLAGS (\\Seen \\Deleted)"),
        cmd("b7", "UID STORE 3:20 +FLAGS (\\Seen)"), cmd("b8", "SEARCH DELETED"), cmd("b9", "SELECT Project"),
        cmd("c1", "FETCH 1:* (FLAGS)"),
    ]))
    s.append(run("pipelined-and-mixed", [
        login(), step("p0 SELECT Inbox\r\np1 FETCH 1 (FLAGS)\r\np2 STORE 1 +FLAGS (\\Seen)\r\np3 SEARCH SEEN\r\np4 UID FETCH 5 (UID)\r\np5 NOOP\r\n", "p5"),
        cmd("p6", "STORE 2 +FLAGS (\\Seen)"), cmd("p7", "SEARCH SEEN UNFLAGGED"), cmd("p8", "LOGOUT"),
    ]))
    null_subject = ("INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,to_addrs,cc_addrs,body_text,size_bytes,thread_id,imap_uid,raw_ref,received_at) "
                    "VALUES (9344103,9344021,0,'<mid-8@imap2.test>',NULL,'dave@example.com','[\"alice@imap2.test\"]','[]','null subject row',300,'t3',8,'blob/3','2025-03-06 12:22:32+00');"
                    "INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid) SELECT m.id,m.received_at,t.id,TRUE,m.imap_uid FROM messages m JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Inbox' WHERE m.id=9344103")
    null_uid = ("INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,to_addrs,cc_addrs,body_text,size_bytes,thread_id,imap_uid,raw_ref,received_at) "
                "VALUES (9344104,9344021,0,'<mid-9@imap2.test>','null uid row','erin@example.com','[\"alice@imap2.test\"]','[]','null uid row',300,'t4',NULL,'blob/4','2025-03-07 13:23:33+00');"
                "INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid) SELECT m.id,m.received_at,t.id,TRUE,m.imap_uid FROM messages m JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Inbox' WHERE m.id=9344104")
    s.append(run("null-columns-fail-whole-command", [
        login(), select(), cmd("n0", "FETCH 1:* (UID)"),
        dict(action=dict(kind="sql", sql=null_subject)),
        cmd("n1", "FETCH 1:* (UID)"), cmd("n2", "SEARCH ALL"), cmd("n3", "UID FETCH 8 (UID)"), cmd("n4", "STORE 1 +FLAGS (\\Seen)"),
        dict(action=dict(kind="sql", sql=null_uid)),
        cmd("n5", "SEARCH ALL"), cmd("n6", "UID SEARCH SEEN"), cmd("n7", "STORE 1 +FLAGS (\\Flagged)"), cmd("n8", "FETCH 1 (UID)"),
        cmd("n9", "SEARCH SUBJECT Hello"),
    ]))
    s.append(run("membership-uid-mode", [
        dict(action=dict(kind="sql", sql="INSERT INTO feature_toggles(key,enabled) VALUES ('feature.imap_membership_uid',true) ON CONFLICT (key) DO UPDATE SET enabled=true")),
        login(), select(),
        cmd("m1", "FETCH 1:* (UID)"), cmd("m2", "UID FETCH 8:11 (UID)"), cmd("m3", "SEARCH ALL"), cmd("m4", "UID SEARCH UNSEEN"),
        cmd("m5", "UID STORE 9 +FLAGS (\\Seen)"), cmd("m6", "STORE 5 +FLAGS (\\Flagged)"), select("Label", "m7"),
        cmd("m8", "FETCH 1:*"), cmd("m9", "UID SEARCH ALL"),
    ]))
    return s


if __name__ == "__main__":
    (ROOT / "messages-requests.json").write_text(json.dumps(build(), indent=1) + "\n")
