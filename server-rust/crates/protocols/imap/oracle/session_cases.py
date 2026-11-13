#!/usr/bin/env python3
"""Author IMAP LIST/STATUS/EXPUNGE/CLOSE/CREATE/DELETE/RENAME/COPY/MOVE/APPEND/IDLE
stimuli (#345). Stimuli only: the Go recorder (listener_oracle_session_record_test.go)
fills `response` and `effects`. Same step grammar as messages_cases.py."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
TOKENS = {u: f"imap3-app-token-{u}" for u in ("alice", "bob", "dave", "erin")}


def step(request, until, **extra):
    return dict(request=request, until=until, **extra)


def cmd(tag, text):
    return step(f"{tag} {text}\r\n", tag)


def login(tag="l1", user="alice"):
    return cmd(tag, f'LOGIN "{user}@imap3.test" "{TOKENS[user]}"')


def select(folder="Inbox", tag="s1"):
    return cmd(tag, f"SELECT {folder}")


def sql(text):
    return dict(action=dict(kind="sql", sql=text))


def append(tag, head, data):
    """APPEND with a synchronising literal: wait for the continuation, send the data."""
    size = len(data.encode())
    return [step(f"{tag} APPEND {head} {{{size}}}\r\n", "+"), step(data + "\r\n", tag)]


def on(conn, steps):
    return [dict(s, conn=conn) for s in steps]


def run(name, steps, **extra):
    return dict(name=name, transport="plain", steps=steps, **extra)


MEMBERSHIP = sql("INSERT INTO feature_toggles(key,enabled) VALUES ('feature.imap_membership_uid',true) "
                 "ON CONFLICT (key) DO UPDATE SET enabled=true")


def build():
    s = []
    s.append(run("pre-auth-commands", [
        cmd("a01", "LIST"), cmd("a02", 'LIST "" "*"'), cmd("a03", "STATUS Inbox (MESSAGES)"), cmd("a04", "EXPUNGE"),
        cmd("a05", "IDLE"), cmd("a06", "APPEND Inbox {3}"), cmd("a07", "CREATE Foo"), cmd("a08", "DELETE Foo"),
        cmd("a09", "RENAME Foo Bar"), cmd("a10", "MOVE 1 Project"), cmd("a11", "COPY 1 Project"), cmd("a12", "CLOSE"),
        cmd("a13", "UID COPY 1 Project"), cmd("a14", "UID MOVE 1 Project"), cmd("a15", "UID"), cmd("a16", "list"),
        cmd("a17", "close"), cmd("a18", "LSUB"), cmd("a19", "UNSELECT"), cmd("a20", "UID FOO 1"),
        login(), cmd("b01", "MOVE 1 Project"), cmd("b02", "COPY 1 Project"), cmd("b03", "EXPUNGE"), cmd("b04", "CLOSE"),
        cmd("b05", "UID COPY 1 Project"), cmd("b06", "UID MOVE 1 Project"), cmd("b07", "UID COPY"), cmd("b08", "MOVE"),
        cmd("b09", "IDLE"),
    ]))
    s.append(run("list-forms", [
        login(), cmd("c01", "LIST"), cmd("c02", 'LIST "" "*"'), cmd("c03", "LIST   x   y"), cmd("c04", "lIsT"),
        cmd("c05", "LSUB"), cmd("c06", 'LSUB "" "*"'), select(), cmd("c07", "LIST"), cmd("c08", "NOOP"),
    ]))
    s.append(run("list-settings-subscribed-only", [
        login("l1", "dave"), cmd("d01", "LIST"), cmd("d02", "STATUS Sub (MESSAGES)"), cmd("d03", "STATUS Project (MESSAGES)"),
    ]))
    s.append(run("list-settings-expose-all-empty-separator", [
        login("l1", "erin"), cmd("e01", "LIST"),
        cmd("e02", "CREATE Fresh"), cmd("e03", "LIST"),
    ]))
    s.append(run("list-null-counts-and-parents", [
        login(), cmd("n01", "LIST"),
        sql("UPDATE tags SET parent_id=NULL WHERE mailbox_id=9345021 AND name='Sub'"),
        cmd("n02", "LIST"),
        sql("UPDATE tags SET imap_name='' WHERE mailbox_id=9345021 AND name='Empty'"),
        cmd("n03", "LIST"), cmd("n04", "STATUS Empty (MESSAGES)"), cmd("n05", 'STATUS "" (MESSAGES)'),
        select("", "n06"), cmd("n07", "FETCH 1:*"),
    ]))
    s.append(run("status-forms", [
        login(),
        cmd("t01", "STATUS Inbox (MESSAGES UNSEEN)"), cmd("t02", 'STATUS "Inbox" (MESSAGES)'), cmd("t03", "STATUS INBOX (UIDNEXT)"),
        cmd("t04", "STATUS iNbOx"), cmd("t05", "STATUS Nope (MESSAGES)"), cmd("t06", "STATUS"), cmd("t07", "STATUS Project"),
        cmd("t08", "STATUS Work (MESSAGES)"), cmd("t09", "STATUS Reports (MESSAGES)"), cmd("t10", "STATUS Hidden (MESSAGES)"),
        cmd("t11", "STATUS [Gmail]/Trash (MESSAGES)"), cmd("t12", "STATUS Trash (MESSAGES)"), cmd("t13", "STATUS Empty (MESSAGES)"),
        cmd("t14", 'STATUS "Project/Sub" (MESSAGES)'), cmd("t15", "STATUS Sub (MESSAGES)"), cmd("t16", "STATUS  Label  (MESSAGES)"),
        cmd("t17", 'STATUS "Quoted \\"x\\"" (MESSAGES)'), cmd("t18", "status inbox (messages)"),
        sql("UPDATE tags SET imap_uid_validity=0, imap_uid_next=0 WHERE mailbox_id=9345021 AND name='Empty'"),
        cmd("t19", "STATUS Empty (MESSAGES)"), cmd("t20", "STATUS Scheduled (MESSAGES)"),
        cmd("t21", "STATUS [Gmail]/Scheduled (MESSAGES)"), cmd("t22", "STATUS Snoozed (MESSAGES)"),
        select("Project", "t23"), cmd("t24", "STATUS Inbox (MESSAGES)"), cmd("t25", "FETCH 1:*"),
    ]))
    s.append(run("expunge-and-close", [
        login(),
        cmd("x01", "EXPUNGE"), cmd("x02", "CLOSE"), cmd("x03", "EXAMINE Inbox"), cmd("x04", "EXPUNGE"), cmd("x05", "CLOSE"),
        cmd("x06", "EXPUNGE"),
        select(tag="x07"), cmd("x08", "EXPUNGE"), cmd("x09", "SEARCH DELETED"), cmd("x10", "FETCH 1:*"),
        cmd("x11", "STORE 1,3 +FLAGS (\\Deleted)"), cmd("x12", "EXPUNGE"), cmd("x13", "FETCH 1:* (UID)"),
        cmd("x14", "EXPUNGE"), cmd("x15", "STATUS Inbox (MESSAGES UNSEEN)"),
        cmd("x16", "UID STORE 20 +FLAGS (\\Deleted)"), cmd("x17", "CLOSE"), cmd("x18", "FETCH 1:*"), cmd("x19", "CLOSE"),
        cmd("x20", "EXPUNGE"), select(tag="x21"), cmd("x22", "FETCH 1:* (UID)"), cmd("x23", "STORE 1:* +FLAGS (\\Deleted)"),
        cmd("x24", "UNSELECT"), cmd("x25", "EXPUNGE"), select(tag="x26"), cmd("x27", "SEARCH ALL"),
    ]))
    s.append(run("expunge-other-folder-and-project", [
        login(), select("Project", "p0"), cmd("p1", "FETCH 1:* (UID)"), cmd("p2", "EXPUNGE"), cmd("p3", "CLOSE"),
        select(tag="p4"), cmd("p5", "FETCH 1:* (UID)"),
        sql("UPDATE messages SET is_deleted=TRUE WHERE id=9345101"),
        cmd("p6", "EXPUNGE"), cmd("p7", "STATUS Inbox (MESSAGES)"), cmd("p8", "UID FETCH 1:* (UID)"),
    ]))
    s.append(run("expunge-membership-uid", [
        MEMBERSHIP, login(), select(),
        cmd("m1", "STORE 2,4 +FLAGS (\\Deleted)"), cmd("m2", "EXPUNGE"), cmd("m3", "FETCH 1:* (UID)"),
        cmd("m4", "STORE 1 +FLAGS (\\Deleted)"), cmd("m5", "CLOSE"),
    ]))
    s.append(run("create-delete-rename", [
        login(),
        cmd("k01", "CREATE Newbox"), cmd("k02", "CREATE Newbox"), cmd("k03", 'CREATE "My Folder"'), cmd("k04", "CREATE A/B"),
        cmd("k05", "CREATE"), cmd("k06", 'CREATE ""'), cmd("k07", "CREATE INBOX"), cmd("k08", "CREATE inbox"),
        cmd("k09", "CREATE Sent"), cmd("k10", "CREATE drafts"), cmd("k11", "CREATE TRASH"), cmd("k12", "CREATE Spam"),
        cmd("k13", "CREATE Junk"), cmd("k14", "CREATE Starred"), cmd("k15", "CREATE Project"), cmd("k16", "CREATE Work"),
        cmd("k17", 'CREATE "Quoted'), cmd("k18", "CREATE a b c"), cmd("k19", "CREATE 'single'"), cmd("k20", "create lower"),
        sql("UPDATE tags SET imap_uid_validity=5000 WHERE mailbox_id=9345021 AND imap_uid_validity > 100000"),
        cmd("k21", "LIST"), cmd("k22", "STATUS Newbox (MESSAGES)"), cmd("k23", "STATUS \"My Folder\" (MESSAGES)"),
        cmd("r01", "RENAME Newbox Renamed"), cmd("r02", "RENAME Renamed Renamed"), cmd("r03", 'RENAME "My Folder" "Other Folder"'),
        cmd("r04", "RENAME Nope Else"), cmd("r05", "RENAME Inbox Foo"), cmd("r06", "RENAME inbox Foo"), cmd("r07", "RENAME Sent Foo"),
        cmd("r08", "RENAME Project Dup"), cmd("r09", "RENAME Renamed"), cmd("r10", "RENAME"), cmd("r11", 'RENAME "" X'),
        cmd("r12", 'RENAME X ""'), cmd("r13", "RENAME Starred Foo"), cmd("r14", "RENAME Trash Foo"),
        cmd("r15", "RENAME lower Renamed"), cmd("r16", "RENAME Label Dup"), cmd("r17", "RENAME Empty Hidden"),
        cmd("r18", "RENAME Work Moved"), cmd("r19", "RENAME Reports Moved"),
        cmd("r20", "LIST"), cmd("r21", "STATUS Dup (MESSAGES)"),
        cmd("d01", "DELETE Renamed"), cmd("d02", "DELETE Renamed"), cmd("d03", 'DELETE "Other Folder"'), cmd("d04", "DELETE Inbox"),
        cmd("d05", "DELETE INBOX"), cmd("d06", "DELETE Sent"), cmd("d07", "DELETE"), cmd("d08", 'DELETE ""'), cmd("d09", "DELETE Nope"),
        cmd("d10", "DELETE Starred"), cmd("d11", "DELETE Work"), cmd("d12", "DELETE Hidden"), cmd("d13", "DELETE [Gmail]/Trash"),
        cmd("d14", "DELETE Trash"), cmd("d15", "DELETE Project"), cmd("d16", "LIST"), cmd("d17", "DELETE Sub"),
        cmd("d18", "LIST"),
    ]))
    s.append(run("delete-and-rename-selected-folder", [
        login(), cmd("c0", "CREATE Scratch"),
        sql("UPDATE tags SET imap_uid_validity=5000 WHERE mailbox_id=9345021 AND name='Scratch'"), select("Scratch", "c1"), cmd("c2", "RENAME Scratch Scratch2"), cmd("c3", "FETCH 1:*"),
        cmd("c4", "STATUS Scratch2 (MESSAGES)"), cmd("c5", "STATUS Scratch (MESSAGES)"), cmd("c6", "DELETE Scratch"),
        cmd("c7", "FETCH 1:*"), cmd("c8", "DELETE Scratch2"), cmd("c9", "FETCH 1:*"), cmd("ca", "NOOP"),
        select("Project", "d0"), cmd("d1", "DELETE project"), cmd("d2", "DELETE Project"), cmd("d3", "FETCH 1:*"),
        cmd("d4", "LIST"),
    ]))
    s.append(run("copy-forms", [
        login(), select(),
        cmd("y01", "COPY 1 Project"), cmd("y02", "COPY 1 Project"), cmd("y03", "COPY 2:3 Dup"), cmd("y04", "COPY 99 Dup"),
        cmd("y05", "COPY 1 Nope"), cmd("y06", "COPY x Dup"), cmd("y07", "COPY 1"), cmd("y08", "COPY"), cmd("y09", "COPY 1 Work"),
        cmd("y10", "COPY 1 Hidden"), cmd("y11", "COPY * Label"), cmd("y12", 'COPY 1 "Dup"'), cmd("y13", "COPY 4 Empty"),
        cmd("y14", "copy 1 Sub"), cmd("y15", "COPY 1 Inbox"), cmd("y16", "COPY 1 INBOX"), cmd("y17", "COPY 1,1,1 Reports"),
        cmd("y18", "COPY 1:* Starred"), cmd("y19", "COPY 1 Trash"), cmd("y20", "COPY 1 [Gmail]/Spam"),
        cmd("y21", "STATUS Project (MESSAGES)"), cmd("y22", "STATUS Dup (MESSAGES UIDNEXT)"), cmd("y23", "STATUS Inbox (MESSAGES)"),
        select("Dup", "y24"), cmd("y25", "FETCH 1:* (UID)"), cmd("y26", "UID SEARCH ALL"),
    ]))
    s.append(run("uid-copy-forms", [
        login(), select(),
        cmd("u01", "UID COPY 5 Dup"), cmd("u02", "UID COPY 3:14 Project"), cmd("u03", "UID COPY 4 Empty"), cmd("u04", "UID COPY 20:3 Label"),
        cmd("u05", "UID COPY 12 Dup"), cmd("u06", "UID COPY * Reports"), cmd("u07", "UID COPY 5 Dup"), cmd("u08", "uid copy 99 Dup"),
        cmd("u09", "UID COPY"), cmd("u10", "UID COPY 5"), cmd("u11", "UID COPY x Dup"),
        cmd("u12", "EXAMINE Project"), cmd("u13", "UID COPY 1 Dup"), cmd("u14", "COPY 1 Dup"), cmd("u15", "UID MOVE 1 Dup"),
        select("Dup", "u16"), cmd("u17", "UID FETCH 1:* (UID)"), cmd("u18", "FETCH 1:* (UID)"),
    ]))
    s.append(run("move-forms", [
        login(), select(),
        cmd("v01", "MOVE 1 Project"), cmd("v02", "FETCH 1:* (UID)"), cmd("v03", "MOVE 1 Dup"), cmd("v04", "MOVE 1 Trash"),
        cmd("v05", "MOVE 1:2 Empty"), cmd("v06", "MOVE 99 Dup"), cmd("v07", "MOVE 1 Nope"), cmd("v08", "MOVE x Dup"), cmd("v09", "MOVE 1"),
        cmd("v10", "MOVE"), cmd("v11", "MOVE 1 Work"), cmd("v12", "MOVE 1 Hidden"), cmd("v13", 'MOVE 1 "Label"'),
        cmd("v14", "MOVE 1 [Gmail]/Spam"), cmd("v15", "MOVE 1 Sent"), cmd("v16", "MOVE 1 Inbox"), cmd("v17", "MOVE 1 Starred"),
        cmd("v18", "MOVE 1 Snoozed"), cmd("v19", "MOVE 1 Scheduled"), cmd("v20", "MOVE * Drafts"), cmd("v21", "move 1 Reports"),
        cmd("v22", "STATUS Inbox (MESSAGES UNSEEN)"), cmd("v23", "STATUS Trash (MESSAGES)"), cmd("v24", "STATUS Project (MESSAGES)"),
        cmd("v25", "FETCH 1:* (UID)"), select("Trash", "v26"), cmd("v27", "FETCH 1:* (UID)"), cmd("v28", "MOVE 1:* Inbox"),
        cmd("v29", "FETCH 1:* (UID)"), select(tag="v30"), cmd("v31", "FETCH 1:* (UID)"),
    ]))
    s.append(run("uid-move-forms", [
        login(), select(),
        cmd("w01", "UID MOVE 5 Dup"), cmd("w02", "UID MOVE 3:14 Project"), cmd("w03", "UID MOVE 4 Empty"), cmd("w04", "UID MOVE 20:3 Trash"),
        cmd("w05", "UID MOVE 12 Dup"), cmd("w06", "UID MOVE * Reports"), cmd("w07", "uid move 99 Dup"), cmd("w08", "UID MOVE"),
        cmd("w09", "UID MOVE 5"), cmd("w10", "UID MOVE x Dup"), cmd("w11", "UID FETCH 1:* (UID)"), cmd("w12", "STATUS Project (MESSAGES)"),
        select("Project", "w13"), cmd("w14", "UID MOVE 1:* Inbox"), cmd("w15", "UID FETCH 1:* (UID)"),
    ]))
    s.append(run("copy-move-read-only-and-isolation", [
        login(), cmd("z0", "EXAMINE Inbox"), cmd("z1", "COPY 1 Dup"), cmd("z2", "MOVE 1 Dup"), cmd("z3", "EXPUNGE"), cmd("z4", "CLOSE"),
        *on(1, [login("l2", "bob"), select(tag="z5"),
        cmd("b1", "COPY 1:* Project"), cmd("b2", "MOVE 1:* Project"), cmd("b3", "UID COPY 1 Dup"), cmd("b4", "STATUS Project (MESSAGES)"),
        cmd("b5", "CREATE Project"), cmd("b6", "RENAME Project Mine"), cmd("b7", "DELETE Project"), cmd("b8", "LIST"),
        cmd("b9", "STORE 1 +FLAGS (\\Deleted)"), cmd("c1", "EXPUNGE"), cmd("c2", "FETCH 1:* (UID)"), cmd("c3", "COPY 1 Trash"),
        cmd("c4", "MOVE 1 Trash"), cmd("c5", "STATUS Trash (MESSAGES)")]),
        cmd("c6", "STATUS Inbox (MESSAGES)"), cmd("c7", "STATUS Project (MESSAGES)"), cmd("c8", "COPY 1 Trash"),
    ]))
    s.append(run("copy-move-membership-uid", [
        MEMBERSHIP, login(), select(),
        cmd("g01", "COPY 1 Project"), cmd("g02", "COPY 1 Project"), cmd("g03", "UID COPY 8 Dup"), cmd("g04", "MOVE 2 Dup"),
        cmd("g05", "UID MOVE 9:* Empty"), cmd("g06", "MOVE 1 Trash"), cmd("g07", "FETCH 1:* (UID)"), select("Dup", "g08"),
        cmd("g09", "FETCH 1:* (UID)"), cmd("g10", "COPY 1 Label"), select("Project", "g11"), cmd("g12", "FETCH 1:* (UID)"),
        cmd("g13", "UID COPY 1:* Dup"), cmd("g14", "UID MOVE 1:* Reports"), select("Reports", "g15"), cmd("g16", "UID FETCH 1:* (UID)"),
    ]))
    s.append(run("copy-move-null-uid-fails-command", [
        login(), select(),
        sql("INSERT INTO messages(id,mailbox_id,folder_id,message_id,subject,from_addr,to_addrs,cc_addrs,body_text,size_bytes,thread_id,imap_uid,raw_ref,received_at) "
            "VALUES (9345199,9345021,0,'<mid-null@imap3.test>','null uid','x@example.com','[]','[]','b',1,'t99',NULL,'imap3/99','2025-03-07 13:23:33+00');"
            "INSERT INTO message_tags(message_id,received_at,tag_id,is_primary,imap_uid) SELECT m.id,m.received_at,t.id,TRUE,m.imap_uid FROM messages m JOIN tags t ON t.mailbox_id=m.mailbox_id AND t.name='Inbox' WHERE m.id=9345199"),
        cmd("h1", "COPY 1 Dup"), cmd("h2", "MOVE 1 Dup"), cmd("h3", "UID COPY 3 Dup"), cmd("h4", "EXPUNGE"), cmd("h5", "STATUS Inbox (MESSAGES)"),
        cmd("h6", "STORE 1 +FLAGS (\\Deleted)"), cmd("h7", "CLOSE"),
    ]))
    s.append(run("append-forms", [
        login(),
        *append("p01", "Inbox", "Subject: one\r\n\r\nhello"),
        *append("p02", "Inbox (\\Seen \\Flagged)", "second"),
        *append("p03", 'Inbox (\\Answered \\Draft \\Deleted \\Unknown) "04-Mar-2025 10:20:30 +0000"', "third"),
        *append("p04", '"Project"', "to project"), *append("p05", "INBOX", "upper inbox"), *append("p06", "Work", "to alias name"),
        *append("p07", "Hidden", "hidden folder"), *append("p08", "Nope", "nowhere"), *append("p09", "[Gmail]/Trash", "to trash"),
        *append("p10", "Empty ()", "empty flags"), *append("p11", "Dup (\\seen)", "lower flag"), *append("p12", "Inbox (\\Seen", "open paren"),
        *append("p13", "Inbox \\Seen)", "close paren"), *append("p14", "Inbox", "with\u0000nul"),
        *append("p15", "Inbox", "multi\r\nline\r\nbody\r\n"), *append("p16", "Inbox", "café 中"),
        cmd("q01", "APPEND Inbox {0}"), cmd("q02", "APPEND Inbox {-1}"), cmd("q03", "APPEND Inbox {x}"), cmd("q04", "APPEND Inbox {50000001}"),
        cmd("q05", "APPEND Inbox {5+}"), cmd("q06", "APPEND Inbox"), cmd("q07", "APPEND"), cmd("q08", "APPEND {5}"),
        *append("q09", "( )", "12345"), cmd("q10", "APPEND Inbox 5}"), cmd("q11", "APPEND Inbox {}"),
        step("q12 APPEND Inbox {1}{2}\r\n", "+"), step("hi\r\n", "q12"),
        step("q13 APPEND Inbox {+5}\r\n", "+"), step("hello\r\n", "q13"),
        step("q14 APPEND Inbox {05}\r\n", "+"), step("hello\r\n", "q14"),
        cmd("r01", "STATUS Inbox (MESSAGES UNSEEN UIDNEXT)"), cmd("r02", "STATUS Project (MESSAGES)"), cmd("r03", "STATUS Dup (MESSAGES)"),
        cmd("r04", "SELECT Inbox"), cmd("r05", "FETCH 1:6"), cmd("r06", "SEARCH ALL"),
        cmd("r07", "EXAMINE Inbox"), *[cmd("r08", "APPEND Inbox {3}")],
    ]))
    s.append(run("append-before-select-and-selected-elsewhere", [
        login(), *append("a1", "Inbox", "unselected"), select("Project", "a2"), *append("a3", "Inbox", "other folder"),
        cmd("a4", "STATUS Inbox (MESSAGES)"), cmd("a5", "STATUS Project (MESSAGES)"), cmd("a6", "FETCH 1:* (UID)"),
        cmd("a7", "UNSELECT"), *append("a8", "Empty", "after unselect"), cmd("a9", "STATUS Empty (MESSAGES UIDNEXT)"),
    ]))
    s.append(run("append-quota-and-isolation", [
        login("l1", "erin"), *append("e1", "Inbox", "x" * 200), *append("e2", "Inbox", "y" * 100), *append("e3", "Inbox", "z"),
        cmd("e4", "STATUS Inbox (MESSAGES)"),
        *on(1, [login("l2", "bob"), *append("b1", "Project", "no such folder for bob"), *append("b2", "Inbox", "bob mail"),
        cmd("b3", "STATUS Inbox (MESSAGES)")]),
    ]))
    s.append(run("append-membership-uid", [
        MEMBERSHIP, login(), *append("m1", "Inbox", "first"), *append("m2", "Dup", "second"), *append("m3", "Project", "third"),
        select(tag="m4"), cmd("m5", "FETCH 1:6 (UID)"), cmd("m6", "UID SEARCH ALL"), cmd("m7", "STATUS Inbox (UIDNEXT MESSAGES)"),
    ]))
    s.append(run("idle-forms", [
        cmd("i00", "IDLE"), login(), cmd("i01", "IDLE"), step("DONE\r\n", "i01"), cmd("i02", "NOOP"),
        select(), cmd("i03", "IDLE"), step("NOOP\r\n", "none"), step("done\r\n", "none"), step("  DONE  \r\n", "i03"),
        cmd("i04", "IDLE"), step("DONE extra\r\n", "none"), step("\r\n", "none"), step("DONE\r\n", "i04"),
        step("i05 IDLE\r\nDONE\r\ni06 NOOP\r\n", "i06"), step("i07 IDLE\r\nDONE\r\nDONE\r\ni08 NOOP\r\n", "i08"),
        cmd("i09", "idle"), step("DONE\r\n", "i09"), cmd("i10", "UNSELECT"), cmd("i11", "IDLE"), step("DONE\r\n", "i11"),
        cmd("i12", "IDLE extra args"), step("DONE\r\n", "i12"), cmd("i13", "EXAMINE Inbox"), cmd("i14", "IDLE"), step("DONE\r\n", "i14"),
        cmd("i15", "STORE 1 +FLAGS (\\Seen)"),
        cmd("i16", "IDLE"), step("a" * 65536 + "\r\n", "none"), step("i17 NOOP\r\n", "i17"),
    ]))
    s.append(run("idle-eof-ends-session", [
        login(), select(), cmd("j1", "IDLE"), step("DONE\r\nj2 LOGOUT\r\n", "j2"), step("", "eof"),
    ]))
    s.append(run("idle-line-limit", [
        login(), cmd("k1", "IDLE"), step("a" * 70000 + "\r\n", "none"), step("k3 NOOP\r\n", "k3"),
    ]))
    for user, mb in (("alice", 9345021), ("dave", 9345023), ("erin", 9345024)):
        s.append(run(f"list-all-parented-{user}", [
            login("l1", user), sql("UPDATE tags SET parent_id=(SELECT id FROM tags p WHERE p.mailbox_id=tags.mailbox_id AND p.name='Project') "
                                   f"WHERE mailbox_id={mb} AND parent_id IS NULL"),
            cmd("o01", "LIST"), cmd("o02", 'LIST "" "*"'),
            sql(f"UPDATE tags SET imap_expose=FALSE WHERE mailbox_id={mb} AND name='Sub'"), cmd("o03", "LIST"),
        ]))
    s.append(run("list-first-row-parented-then-null", [
        login(), sql("UPDATE tags SET parent_id=(SELECT id FROM tags p WHERE p.mailbox_id=tags.mailbox_id AND p.name='Project') "
                     "WHERE mailbox_id=9345021 AND name IN ('Inbox','Sent')"),
        cmd("o01", "LIST"),
        sql("UPDATE tags SET parent_id=(SELECT id FROM tags p WHERE p.mailbox_id=tags.mailbox_id AND p.name='Project') "
            "WHERE mailbox_id=9345021 AND parent_id IS NULL"),
        cmd("o02", "LIST"),
    ]))
    s.append(run("list-no-exposed-tags", [
        login(), sql("UPDATE tags SET imap_expose=FALSE WHERE mailbox_id=9345021"), cmd("o01", "LIST"), cmd("o02", "STATUS Inbox (MESSAGES)"),
        cmd("o03", "SELECT Inbox"), cmd("o04", "CREATE Back"), cmd("o05", "LIST"),
    ]))
    # Go panics (recovered by handleConn, which closes the socket without a reply).
    s.append(run("append-panic-shapes-close-connection", [
        login(), step("p1 APPEND 5}\r\n", "eof"),
    ]))
    s.append(run("append-paren-order-panic-after-literal", [
        login(), step("p1 APPEND Inbox ) ( {3}\r\n", "+"), step("abc\r\n", "eof"),
    ]))
    s.append(run("append-short-literal-then-eof", [
        login(), step("p1 APPEND Inbox {10}\r\n", "+"), step("abc", "eof", shutdown=True),
    ]))
    s.append(run("serverbug-gone-and-unknown", [
        login(), cmd("u1", "FOO"), cmd("u2", "XYZZY a b"), cmd("u3", "UID FOO 1"), cmd("u4", "UID"), cmd("u5", "CHECK"),
        cmd("u6", "GETQUOTA Inbox"), cmd("u7", "SORT (DATE) UTF-8 ALL"), cmd("u8", "THREAD REFERENCES UTF-8 ALL"),
        cmd("u9", "EXPUNGE"), cmd("ua", "CLOSE"), cmd("ub", "UNSELECT"), cmd("uc", "UID EXPUNGE 1"), cmd("ud", "COMPRESS DEFLATE"),
        cmd("ue", "ENABLE UTF8=ACCEPT"), cmd("uf", "NAMESPACE"), cmd("ug", "LOGOUT"),
    ]))
    return s


if __name__ == "__main__":
    (ROOT / "session-requests.json").write_text(json.dumps(build(), indent=1) + "\n")
