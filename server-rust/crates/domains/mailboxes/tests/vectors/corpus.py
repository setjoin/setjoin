#!/usr/bin/env python3
"""Corpus for the mimeutil differential vectors: raw messages, address and
media-type strings. `dump_go.txt` (copied to a Go main package inside the
mailserver module) records frozen Go's answers into vectors.json."""
import base64, json

M = []
def msg(name, raw):
    if isinstance(raw, str):
        raw = raw.encode('utf-8', 'surrogateescape')
    M.append({"name": name, "raw": base64.b64encode(raw).decode()})

H = "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: Hi\r\nMessage-ID: <m1@example.com>\r\nDate: Mon, 02 Jan 2006 15:04:05 GMT\r\n"
msg("plain-crlf", H + "\r\nHello body\r\n\r\nsecond para\r\n")
msg("plain-lf", H.replace("\r\n", "\n") + "\nHello body\n\nsecond para\n")
msg("no-body", H.rstrip("\r\n"))
msg("headers-only-blank", H + "\r\n")
msg("lf-headers-crlf-body", H.replace("\r\n", "\n") + "\nx\r\n\r\ny\r\n")
msg("folded", "Subject: part one\r\n\tpart two\r\n  part three\r\nFrom: a@b.co\r\n\r\nbody")
msg("folded-first", " Subject: lead\r\nFrom: a@b.co\r\n\r\nbody")
msg("subject-encoded-b", "Subject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=\r\nFrom: a@b.co\r\n\r\nx")
msg("subject-encoded-q", "Subject: =?utf-8?q?caf=C3=A9_au_lait?=\r\n\r\nx")
msg("subject-latin1", "Subject: =?ISO-8859-1?Q?caf=E9?=\r\n\r\nx")
msg("subject-ascii-word", "Subject: =?us-ascii?q?abc=FFdef?=\r\n\r\nx")
msg("subject-sjis", "Subject: =?shift_jis?B?k/qWe4zq?=\r\n\r\nx")
msg("subject-mixed", "Subject: Re: =?UTF-8?Q?caf=C3=A9?= and more\r\n\r\nx")
msg("subject-two-words", "Subject: =?UTF-8?Q?a?= =?UTF-8?Q?b?=\r\n\r\nx")
msg("subject-bad-b64", "Subject: =?UTF-8?B?!!!?=\r\n\r\nx")
msg("subject-short-q", "Subject: =?UTF-8?Q?=4?=\r\n\r\nx")
msg("subject-nonutf8", b"Subject: caf\xe9\r\n\r\nx")
msg("subject-empty-word", "Subject: =?UTF-8?Q??=\r\n\r\nx")
msg("subject-upper-header", "SUBJECT: shouting\r\nsubject: second\r\n\r\nx")
msg("subject-kelvin-fold", "Subjecſt: sharp s\r\n\r\nx")
msg("colon-leading", ": nothing\r\nSubject: real\r\n\r\nx")
msg("from-name-quoted", 'From: "Doe, John" <john@example.com>\r\n\r\nx')
msg("from-name-comment", "From: john@example.com (John Doe)\r\n\r\nx")
msg("from-group", "From: team: a@b.co;\r\n\r\nx")
msg("from-group-two", "From: team: a@b.co, c@d.co;\r\n\r\nx")
msg("from-encoded-name", "From: =?UTF-8?Q?J=C3=BCrgen?= <j@example.de>\r\n\r\nx")
msg("from-encoded-latin", "From: =?ISO-8859-1?Q?J=FCrgen?= <j@example.de>\r\n\r\nx")
msg("from-encoded-1252", "From: =?windows-1252?Q?J=FCrgen?= <j@example.de>\r\n\r\nx")
msg("from-whole-encoded", "From: =?UTF-8?B?QWxpY2UgPGFsaWNlQGV4YW1wbGUuY29tPg==?=\r\n\r\nx")
msg("from-bare", "From: alice@example.com\r\n\r\nx")
msg("from-angle-only", "From: <alice@example.com>\r\n\r\nx")
msg("from-garbage", "From: not an address\r\n\r\nx")
msg("from-garbage-angle", "From: Name <broken\r\n\r\nx")
msg("from-quoted-local", 'From: "a b"@example.com\r\n\r\nx')
msg("from-ip-literal", "From: a@[192.168.0.1]\r\n\r\nx")
msg("from-bad-literal", "From: a@[999.1.1.1]\r\n\r\nx")
msg("from-unicode", "From: Zoë <zoë@exämple.com>\r\n\r\nx")
msg("from-obs", "From: a..b@example.com\r\n\r\nx")
msg("from-html-chars", 'From: "A <b> & c" <a@example.com>\r\n\r\nx')
msg("from-nul-name", 'From: "a\x00b" <a@example.com>\r\n\r\nx')
msg("to-list", "To: a@b.co, \"C, D\" <c@d.co>, e@f.co (Eve)\r\n\r\nx")
msg("to-list-bad", "To: a@b.co, ???, c@d.co\r\n\r\nx")
msg("to-empty-group", "To: undisclosed-recipients:;\r\n\r\nx")
msg("to-trailing-comma", "To: a@b.co,, ,\r\n\r\nx")
msg("cc-bcc", "Cc: c@d.co\r\nBcc: Hidden <h@d.co>\r\n\r\nx")
msg("refs", "In-Reply-To: <a@b>\r\nReferences: <a@b>\r\n <c@d>\r\n\r\nx")
msg("date-rfc850", "Date: Sunday, 06-Nov-94 08:49:37 GMT\r\n\r\nx")
msg("date-rfc850-est", "Date: Sunday, 06-Nov-94 08:49:37 EST\r\n\r\nx")
msg("date-rfc850-gmt-offset", "Date: Sunday, 06-Nov-94 08:49:37 GMT+3\r\n\r\nx")
msg("date-ansic", "Date: Sun Nov  6 08:49:37 1994\r\n\r\nx")
msg("date-ansic-frac", "Date: Sun Nov  6 08:49:37.123456789 1994\r\n\r\nx")
msg("date-http-frac", "Date: Sun, 06 Nov 1994 08:49:37.5 GMT\r\n\r\nx")
msg("date-rfc2822", "Date: Mon, 02 Jan 2006 15:04:05 -0700\r\n\r\nx")
msg("date-bad-day", "Date: Mon, 31 Feb 2006 15:04:05 GMT\r\n\r\nx")
msg("date-one-digit-hour", "Date: Mon, 02 Jan 2006 5:04:05 GMT\r\n\r\nx")
msg("date-wrong-weekday", "Date: Fri, 02 Jan 2006 15:04:05 GMT\r\n\r\nx")
msg("date-lower", "Date: mon, 02 jan 2006 15:04:05 GMT\r\n\r\nx")
msg("date-one-digit-day", "Date: Mon, 2 Jan 2006 15:04:05 GMT\r\n\r\nx")
msg("date-extra", "Date: Mon, 02 Jan 2006 15:04:05 GMT x\r\n\r\nx")
msg("date-leap", "Date: Thu, 29 Feb 2024 23:59:59 GMT\r\n\r\nx")
msg("date-year-0000", "Date: Sat, 01 Jan 0000 00:00:00 GMT\r\n\r\nx")
msg("date-hour-24", "Date: Mon, 02 Jan 2006 24:04:05 GMT\r\n\r\nx")
msg("ct-plain-utf8", "Content-Type: text/plain; charset=utf-8\r\n\r\nhéllo")
msg("ct-plain-latin1", b"Content-Type: text/plain; charset=iso-8859-1\r\n\r\nh\xe9llo")
msg("ct-plain-1252-euro", b"Content-Type: text/plain; charset=windows-1252\r\n\r\nprice \x80 5")
msg("ct-plain-latin2", b"Content-Type: text/plain; charset=ISO-8859-2\r\n\r\n\xb1\xe6\xea")
msg("ct-plain-sjis", b"Content-Type: text/plain; charset=shift_jis\r\n\r\n\x93\xfa\x96\x7b")
msg("ct-plain-gbk", b"Content-Type: text/plain; charset=gbk\r\n\r\n\xc4\xe3\xba\xc3")
msg("ct-plain-gb2312", b"Content-Type: text/plain; charset=gb2312\r\n\r\n\xc4\xe3\xba\xc3")
msg("ct-plain-big5", b"Content-Type: text/plain; charset=big5\r\n\r\n\xa7A\xa6n")
msg("ct-plain-euckr", b"Content-Type: text/plain; charset=euc-kr\r\n\r\n\xbe\xc8\xb3\xe7")
msg("ct-plain-eucjp", b"Content-Type: text/plain; charset=euc-jp\r\n\r\n\xc6\xfc\xcb\xdc")
msg("ct-plain-koi8r", b"Content-Type: text/plain; charset=koi8-r\r\n\r\n\xf0\xd2\xc9\xd7\xc5\xd4")
msg("ct-plain-cp1251", b"Content-Type: text/plain; charset=windows-1251\r\n\r\n\xcf\xf0\xe8\xe2\xe5\xf2")
msg("ct-plain-utf16le", b"Content-Type: text/plain; charset=utf-16le\r\n\r\nh\x00i\x00")
msg("ct-plain-utf16le-odd", b"Content-Type: text/plain; charset=utf-16le\r\n\r\nh\x00i")
msg("ct-plain-utf16be-bom", b"Content-Type: text/plain; charset=utf-16be\r\n\r\n\xfe\xff\x00h\x00i")
msg("ct-plain-utf16-bom", b"Content-Type: text/plain; charset=utf-16\r\n\r\n\xff\xfeh\x00i\x00")
msg("ct-plain-utf8-label", b"Content-Type: text/plain; charset=utf8\r\n\r\nok \xe9 \xf0\x9f\x98")
msg("ct-plain-utf8-bom", b"Content-Type: text/plain; charset=UTF8\r\n\r\n\xef\xbb\xbfhello")
msg("ct-plain-bogus", b"Content-Type: text/plain; charset=nonsense\r\n\r\nh\xe9llo")
msg("ct-plain-replacement", b"Content-Type: text/plain; charset=iso-2022-kr\r\n\r\nhello")
msg("ct-plain-hz", b"Content-Type: text/plain; charset=hz-gb-2312\r\n\r\nhello")
msg("ct-plain-xuser", b"Content-Type: text/plain; charset=x-user-defined\r\n\r\nh\xe9llo")
msg("ct-plain-quoted-charset", b'Content-Type: text/plain; charset="ISO-8859-1"\r\n\r\nh\xe9llo')
msg("ct-plain-iso2022jp", b"Content-Type: text/plain; charset=iso-2022-jp\r\n\r\n\x1b$B$3$s$K$A$O\x1b(B")
msg("ct-plain-gb18030", b"Content-Type: text/plain; charset=gb18030\r\n\r\n\x81\x30\x81\x30\xc4\xe3")
msg("ct-plain-macintosh", b"Content-Type: text/plain; charset=macintosh\r\n\r\n\x8e\x8f")
msg("ct-plain-latin1-bad", b"Content-Type: text/plain; charset=latin1; \r\n\r\nh\xe9llo")
msg("ct-plain-invalid-mt", b"Content-Type: text/plain; charset\r\n\r\nh\xe9llo")
msg("ct-plain-ws-charset", b"Content-Type: text/plain; charset=\" utf-8\"\r\n\r\nh\xe9llo")
msg("ct-plain-rfc2231", b"Content-Type: text/plain; charset*=utf-8''iso-8859-1\r\n\r\nh\xe9llo")
msg("ct-html", "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hi</p>\r\n\r\n<p>2</p>")
msg("ct-html-latin1", b"Content-Type: text/html; charset=iso-8859-1\r\n\r\n<p>h\xe9</p>")
msg("ct-html-upper", "Content-Type: TEXT/HTML\r\n\r\n<b>x</b>")
msg("ct-other", "Content-Type: application/pdf\r\n\r\n%PDF-")
msg("ct-whole-encoded", "Content-Type: =?UTF-8?Q?text/plain?=\r\n\r\nbody")
msg("body-trim", "\r\n\r\n   \r\n  padded body \r\n\r\n")

B = "XYZ"
def mp(parts, boundary=B, ct="multipart/mixed", preamble="", epilogue="", eol="\r\n", close=True, head=None):
    out = (head if head is not None else f"Content-Type: {ct}; boundary={boundary}{eol}{eol}")
    out += preamble
    for p in parts:
        out += f"--{boundary}{eol}" + p
        if not p.endswith(eol): out += eol
    if close: out += f"--{boundary}--{eol}"
    out += epilogue
    return out

def part(ct, body, extra=""):
    return f"Content-Type: {ct}\r\n{extra}\r\n{body}"

msg("mp-alt", mp([part("text/plain; charset=utf-8", "plain text"), part("text/html; charset=utf-8", "<p>html</p>")], ct="multipart/alternative"))
msg("mp-alt-lf", mp([part("text/plain", "plain text").replace("\r\n", "\n"), part("text/html", "<p>html</p>").replace("\r\n", "\n")], eol="\n").replace("\r\n", "\n"))
msg("mp-mixed-attach", mp([part("text/plain", "see attached"), part("application/pdf", "JVBERi0=", "Content-Transfer-Encoding: base64\r\n")]))
msg("mp-nested", mp([mp([part("text/plain", "inner plain"), part("text/html", "<i>inner html</i>")], boundary="IN", ct="multipart/alternative", head="Content-Type: multipart/alternative; boundary=IN\r\n\r\n"), part("image/png", "PNG")]))
msg("mp-nested-bad", mp([part("multipart/alternative", "no boundary here"), part("text/plain", "after")]))
msg("mp-nested-unparseable", mp([part("multipart/alternative; boundary", "x"), part("text/plain", "after")]))
msg("mp-first-empty-plain", mp([part("text/plain", ""), part("text/plain", "second plain")]))
msg("mp-latin1-part", b"Content-Type: multipart/alternative; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain; charset=iso-8859-1\r\n\r\nh\xe9llo\r\n--XYZ\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n<p>\x80</p>\r\n--XYZ--\r\n")
msg("mp-sjis-part", b"Content-Type: multipart/alternative; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain; charset=shift_jis\r\n\r\n\x93\xfa\x96\x7b\r\n--XYZ--\r\n")
msg("mp-bogus-charset-part", mp([part("text/plain; charset=bogus", "kept as is")]))
msg("mp-preamble-epilogue", mp([part("text/plain", "p")], preamble="This is a preamble\r\n", epilogue="epilogue text\r\n"))
msg("mp-no-close", mp([part("text/plain", "unclosed")], close=False))
msg("mp-no-delims", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\njust text no delimiters\r\n")
msg("mp-no-boundary-param", "Content-Type: multipart/mixed\r\n\r\n--XYZ\r\n\r\nx\r\n--XYZ--\r\n")
msg("mp-quoted-boundary", mp([part("text/plain", "quoted")], boundary="a b'c", head='Content-Type: multipart/mixed; boundary="a b\'c"\r\n\r\n'))
msg("mp-boundary-prefix-lookalike", mp([part("text/plain", "line\r\n--XYZZ not a delimiter\r\nmore")]))
msg("mp-mixed-eol-switch", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\na\r\n--XYZ\n\nContent-Type: text/plain\n\nb\n--XYZ--\n")
msg("mp-decoy-close", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\na\r\n--XYZ--junk\r\nmore\r\n--XYZ--\r\n")
msg("mp-decoy-preamble", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ--junk\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\nafter\r\n--XYZ--\r\n")
msg("mp-part-no-blank", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n--XYZ--\r\n")
msg("mp-second-part-bad-after-first", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\nfirst ok\r\n--XYZ\r\nContent-Type: text/html\r\n--XYZ--\r\n")
msg("mp-transport-padding", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ  \r\nContent-Type: text/plain\r\n\r\npadded\r\n--XYZ--  \r\n")
msg("mp-close-at-eof", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\natend\r\n--XYZ--")
msg("mp-lf-boundary-in-crlf-body", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\r\n\r\nsafe\n--XYZ--\r\nstill part\r\n--XYZ--\r\n")
msg("mp-mixed-case-ct", "Content-Type: Multipart/Alternative; Boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: TEXT/PLAIN\r\n\r\nupper\r\n--XYZ--\r\n")
msg("mp-part-ct-spacing", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type:text/plain\r\n\r\nnospace\r\n--XYZ\r\nContent-Type: text/plain;charset=x\r\n\r\n2\r\n--XYZ--\r\n")
msg("mp-part-ct-folded", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain;\r\n charset=iso-8859-1\r\n\r\nfold\r\n--XYZ--\r\n")
msg("mp-text-first-decl-html", mp([part("text/html", "<p>h</p>"), part("text/plain", "p")]))
def nest(n):
    inner = "Content-Type: text/plain\r\n\r\ndeepest"
    for i in range(n, 0, -1):
        inner = f"Content-Type: multipart/mixed; boundary=B{i}\r\n\r\n--B{i}\r\n{inner}\r\n--B{i}--\r\n"
    return inner
msg("mp-depth-19", nest(19))
msg("mp-depth-20", nest(20))
msg("mp-depth-21", nest(21))
msg("mp-missing-ct-part", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\n\r\nno part headers\r\n--XYZ--\r\n")
msg("mp-crlf-part-lf-body", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plain\n\nbody\r\n\r\ninner\r\n--XYZ--\r\n")
msg("mp-ct-kelvin", "Content-Type: multipart/mixed; boundary=XYZ\r\n\r\n--XYZ\r\nContent-Type: text/plaİn\r\n\r\nodd\r\n--XYZ--\r\n")
msg("big-header-values", "Subject: " + "x" * 5000 + "\r\n\r\nbody")
msg("nul-in-body", b"Subject: nul\r\n\r\nab\x00cd")
msg("nul-in-subject", b"Subject: ab\x00cd\r\n\r\nbody")
msg("invalid-utf8-body", b"Content-Type: text/plain; charset=utf-8\r\n\r\nbad \xff\xfe bytes")
msg("invalid-utf8-html", b"Content-Type: text/html\r\n\r\n<p>bad \xc3</p>")
msg("empty", "")
msg("just-newlines", "\n\n\n")

A = ["", "a@b.co", " a@b.co ", "<a@b.co>", "Name <a@b.co>", '"Quoted Name" <a@b.co>', "a@b.co (comment)", "a@b.co (nested (comment))",
 "(lead) a@b.co", "a@b.co, c@d.co", "a@b.co,c@d.co", "A <a@b.co>, B <c@d.co>", "group: a@b.co, c@d.co;", "group:;", "group: a@b.co", "a@b",
 "@b.co", "a@", "a", "a b", "a b <c@d.co>", "a.b@c.d", ".a@b.co", "a.@b.co", "a..b@c.d", '"a..b"@c.d', "a@b..co", "a@[1.2.3.4]", "a@[::1]", "a@[1.2.3]",
 "a@[1.2.3.4", "=?UTF-8?Q?A?= <a@b.co>", "=?UTF-8?Q?A?= =?UTF-8?Q?B?= <a@b.co>", "=?UTF-8?Q?A?= B <a@b.co>", "A =?UTF-8?Q?B?= <a@b.co>",
 "=?bogus?Q?A?= <a@b.co>", "=?bogus?Q?A?= B <a@b.co>", "a@b.co (=?UTF-8?Q?Name?=)", "a@b.co (=?bogus?Q?Name?=)", "a@b.co (unclosed",
 "Name <a@b.co", "Name a@b.co>", "<>", "<a@b.co> trailing", "a@b.co a@b.co", "a@b.co;", "\"unclosed <a@b.co>", '"a\\"b" <a@b.co>', '"a\\\\b" <a@b.co>',
 "Zoë <zoe@exämple.com>", "名前 <a@b.co>", "a@b.co,", ",a@b.co", ",,", " , ", "a@b.co , , c@d.co", "Hello World <a@b.co>", "Hello  World  <a@b.co>",
 "Hello, World <a@b.co>", "x@y.z (a) (b)", "x@y.z ()", "<a@b.co>(c)", "a@b.co(c)d", "\\a@b.co", "a\tb <c@d.co>", "a@b.co\t", "<@route:a@b.co>",
 "<@a,@b:c@d.co>", "a;b@c.d", "'a'@b.co", "a+tag@b.co", "a%b@c.d", "a@b.c-d", "a@-b.co", "john@example.com, \"Smith, Anna\" <anna@example.org>, bob@x.y (Bob)",
 "a@b.co, group: c@d.co;, e@f.co", "g1: a@b.co; g2: c@d.co;", "Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>",
 "=?UTF-8?B?4pyT?= <a@b.co>", "=?UTF-8?Q?=?= <a@b.co>", "=?ISO-8859-1?Q?=E9?= <a@b.co>", "=?us-ascii?Q?=E9?= <a@b.co>"]
A += ["\xff@b.co", "a@\xffb.co", "\"\xff\" <a@b.co>", "N\xffe <a@b.co>"]
A += ['a@b.co' + ' ' * 3, '"" <a@b.co>', '"" a@b.co', '""@b.co', "<a@b.co>, ", "A <a@b.co>,\r\n B <c@d.co>"]

MT = ["text/plain", "text/plain; charset=utf-8", "TEXT/PLAIN; CHARSET=UTF-8", "text/plain;charset=utf-8;", "text/plain; ;", "text/plain; charset", "text/plain; charset=", 
 'text/plain; charset=""', "text/plain; charset=a; charset=b", "text/plain; charset=a; charset=a", 'text/plain; charset="a\\"b"', 'text/plain; charset="a\\b"', 'multipart/mixed; boundary="a;b"', 
 "multipart/mixed; boundary=a:b", "multipart/mixed; boundary=a/b", "text", "text/", "/plain", "text/plain/x", "text/pla in", " text/plain ", "text/plain ; a=b", "text/plain; a = b",
 "text/plain; a*=utf-8''%C3%A9", "text/plain; a*=iso-8859-1''%E9", "text/plain; a*0=x; a*1=y", "text/plain; a*0*=utf-8''%C3; a*1*=%A9", "text/plain; a*0=x; a*2=z", "text/plain; a*=utf-8''%C3%", 
 "text/plain; a=é", "text/plainK; a=b", "Kext/plain", "", ";", "text/plain; ; charset=utf-8", "text/plain;\tcharset=utf-8", "text/plain; charset=utf-8", 
 'text/plain; charset="utf-8', "text/plain; a=\"b\r\nc\"", "multipart/mixed; boundary=", "multipart/mixed; boundary=\"\"", "multipart/ mixed; boundary=x", "multipart/mixed;boundary=x;"]

json.dump({"messages": M, "addresses": [base64.b64encode(a.encode('utf-8','surrogateescape')).decode() for a in A],
           "media_types": [base64.b64encode(a.encode('utf-8','surrogateescape')).decode() for a in MT]}, open("corpus.json", "w"))
print(len(M), len(A), len(MT))
