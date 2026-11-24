#!/usr/bin/env python3
"""Pure-stdlib YAML 1.2 scalar/mapping reader and systemd EnvironmentFile helper.

Used by mailserver/deploy/scripts/lib-livekit.sh so install/upgrade and CI deploy
guards require only Python 3 stdlib (no external PyYAML dependency).
"""

import os
import re
import sys

_YAML_ESCAPES = {
    "0": "\0",
    "a": "\a",
    "b": "\b",
    "t": "\t",
    "\t": "\t",
    "n": "\n",
    "v": "\v",
    "f": "\f",
    "r": "\r",
    "e": "\x1b",
    " ": " ",
    '"': '"',
    "/": "/",
    "\\": "\\",
    "N": "\x85",
    "_": "\xa0",
    "L": "\u2028",
    "P": "\u2029",
}


class YamlError(ValueError):
    pass


class _Parser:
    def __init__(self, src: str) -> None:
        self.s = src.replace("\r\n", "\n").replace("\r", "\n")
        if self.s.startswith("\ufeff"):
            self.s = self.s[1:]
        self.n = len(self.s)
        self.i = 0
        self.anchors: dict = {}

    def eof(self) -> bool:
        return self.i >= self.n

    def peek(self, offset: int = 0) -> str:
        idx = self.i + offset
        return self.s[idx] if idx < self.n else ""

    def skip_hws(self) -> None:
        while self.i < self.n and self.s[self.i] in " \t":
            self.i += 1

    def skip_comment_eol(self) -> None:
        self.skip_hws()
        if self.i < self.n and self.s[self.i] == "#":
            while self.i < self.n and self.s[self.i] != "\n":
                self.i += 1
        if self.i < self.n:
            if self.s[self.i] != "\n":
                raise YamlError(f"unexpected trailing content at offset {self.i}")
            self.i += 1

    def skip_blank_and_comments(self) -> None:
        while self.i < self.n:
            save = self.i
            while self.i < self.n and self.s[self.i] in " \t":
                self.i += 1
            if self.i < self.n and self.s[self.i] == "\n":
                self.i += 1
                continue
            if self.i < self.n and self.s[self.i] == "#":
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
                if self.i < self.n and self.s[self.i] == "\n":
                    self.i += 1
                continue
            self.i = save
            break

    def current_line_indent(self) -> int:
        # Must be called at start of a non-blank, non-comment line.
        k = self.i
        while k < self.n and self.s[k] == " ":
            k += 1
        if k < self.n and self.s[k] == "\t":
            raise YamlError("tabs cannot be used for YAML indentation")
        return k - self.i

    def at_doc_marker(self) -> bool:
        for mark in ("---", "..."):
            if self.s.startswith(mark, self.i):
                nxt = self.peek(3)
                if nxt in ("", " ", "\t", "\n", "#"):
                    return True
        return False

    def _fold_newline(self, out: list[str]) -> None:
        # Fold one or more YAML line breaks inside quoted scalars.
        while out and out[-1] in (" ", "\t"):
            out.pop()
        self.i += 1  # consume first \n
        newlines = 1
        while self.i < self.n:
            while self.i < self.n and self.s[self.i] in " \t":
                self.i += 1
            if self.i < self.n and self.s[self.i] == "\n":
                newlines += 1
                self.i += 1
            else:
                break
        out.append(" " if newlines == 1 else "\n" * (newlines - 1))

    def parse_dquote(self) -> str:
        assert self.s[self.i] == '"'
        self.i += 1
        out: list[str] = []
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == '"':
                self.i += 1
                return "".join(out)
            if ch == "\\":
                self.i += 1
                if self.i >= self.n:
                    raise YamlError("unterminated escape in double-quoted string")
                esc = self.s[self.i]
                if esc == "\n":
                    self.i += 1
                    while self.i < self.n and self.s[self.i] in " \t":
                        self.i += 1
                    continue
                if esc in _YAML_ESCAPES:
                    out.append(_YAML_ESCAPES[esc])
                    self.i += 1
                elif esc in ("x", "u", "U"):
                    width = {"x": 2, "u": 4, "U": 8}[esc]
                    self.i += 1
                    hex_str = self.s[self.i : self.i + width]
                    if len(hex_str) != width or not re.fullmatch(r"[0-9a-fA-F]+", hex_str):
                        raise YamlError(f"invalid \\{esc} escape in double-quoted string")
                    out.append(chr(int(hex_str, 16)))
                    self.i += width
                else:
                    raise YamlError(f"unknown escape \\{esc} in double-quoted string")
            elif ch == "\n":
                self._fold_newline(out)
            else:
                out.append(ch)
                self.i += 1
        raise YamlError("unterminated double-quoted string")

    def parse_squote(self) -> str:
        assert self.s[self.i] == "'"
        self.i += 1
        out: list[str] = []
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "'":
                if self.peek(1) == "'":
                    out.append("'")
                    self.i += 2
                    continue
                self.i += 1
                return "".join(out)
            if ch == "\n":
                self._fold_newline(out)
            else:
                out.append(ch)
                self.i += 1
        raise YamlError("unterminated single-quoted string")

    def coerce_plain(self, raw: str):
        if raw in ("null", "Null", "NULL", "~", ""):
            return None
        if raw in ("true", "True", "TRUE"):
            return True
        if raw in ("false", "False", "FALSE"):
            return False
        return raw

    def read_indicator_name(self, sigil: str, in_flow: bool = False) -> str:
        assert self.s[self.i] == sigil
        self.i += 1
        start = self.i
        stops = " \t\n" + (",{}[]" if in_flow else "")
        while self.i < self.n and self.s[self.i] not in stops:
            self.i += 1
        name = self.s[start : self.i]
        if not name:
            raise YamlError(f"empty {sigil!r} name at offset {start}")
        return name

    def parse_plain(self, in_flow: bool = False):
        start = self.i
        stops = ",}]" if in_flow else ""
        last_non_ws = self.i
        while self.i < self.n:
            ch = self.s[self.i]
            if ch == "\n":
                break
            if in_flow and ch in stops:
                break
            if ch == "#" and self.i > start and self.s[self.i - 1] in " \t":
                break
            if ch == ":" and (
                self.peek(1) in ("", " ", "\t", "\n")
                or (in_flow and self.peek(1) in (",", "}", "]"))
            ):
                raise YamlError(f"unexpected ':' in plain scalar at offset {self.i}")
            if ch not in " \t":
                last_non_ws = self.i + 1
            self.i += 1
        text = self.s[start:last_non_ws]
        if not in_flow:
            self.skip_comment_eol()
        return self.coerce_plain(text)

    def parse_key(self, in_flow: bool = False) -> str:
        if self.eof():
            raise YamlError("unexpected EOF reading key")
        ch = self.peek()
        if ch == "!":
            raise YamlError(f"unsupported YAML tag at offset {self.i}")
        if ch == "*":
            alias = self.read_indicator_name("*", in_flow=in_flow)
            if alias not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{alias}'")
            val = self.anchors[alias]
            if not isinstance(val, str):
                raise YamlError(f"YAML alias '*{alias}' is not a scalar key")
            return val
        if ch == "&":
            name = self.read_indicator_name("&", in_flow=in_flow)
            self.skip_hws()
            key = self.parse_key(in_flow=in_flow)
            self.anchors[name] = key
            return key
        if ch == '"':
            return self.parse_dquote()
        if ch == "'":
            return self.parse_squote()
        start = self.i
        while self.i < self.n:
            c = self.s[self.i]
            if c == "\n":
                raise YamlError(f"unexpected newline in mapping key at offset {self.i}")
            if c == ":" and (
                self.peek(1) in ("", " ", "\t", "\n") or (in_flow and self.peek(1) in ",}]")
            ):
                break
            if in_flow and c in ",{}[]":
                raise YamlError(f"invalid character {c!r} in flow key at offset {self.i}")
            self.i += 1
        key = self.s[start : self.i].strip()
        if not key:
            raise YamlError(f"empty mapping key at offset {start}")
        return key

    def skip_flow_ws_comments(self) -> None:
        while self.i < self.n:
            while self.i < self.n and self.s[self.i] in " \t\n":
                self.i += 1
            if self.i < self.n and self.s[self.i] == "#":
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
                continue
            break

    def parse_flow_mapping(self) -> dict:
        assert self.s[self.i] == "{"
        self.i += 1
        res: dict = {}
        while True:
            self.skip_flow_ws_comments()
            if self.eof():
                raise YamlError("unterminated flow mapping '{'")
            if self.peek() == "}":
                self.i += 1
                return res
            k = self.parse_key(in_flow=True)
            self.skip_flow_ws_comments()
            if self.peek() != ":":
                raise YamlError(f"expected ':' after flow key {k!r}")
            self.i += 1
            self.skip_flow_ws_comments()
            if self.peek() in (",", "}"):
                val = None
            else:
                val = self.parse_flow_value()
            res[k] = val
            self.skip_flow_ws_comments()
            if self.peek() == ",":
                self.i += 1
                continue
            if self.peek() == "}":
                self.i += 1
                return res
            raise YamlError(f"expected ',' or '}}' in flow mapping at offset {self.i}")

    def parse_flow_seq(self) -> list:
        assert self.s[self.i] == "["
        self.i += 1
        res: list = []
        while True:
            self.skip_flow_ws_comments()
            if self.eof():
                raise YamlError("unterminated flow sequence '['")
            if self.peek() == "]":
                self.i += 1
                return res
            res.append(self.parse_flow_value())
            self.skip_flow_ws_comments()
            if self.peek() == ",":
                self.i += 1
                continue
            if self.peek() == "]":
                self.i += 1
                return res
            raise YamlError(f"expected ',' or ']' in flow sequence at offset {self.i}")

    def parse_flow_value(self):
        self.skip_flow_ws_comments()
        ch = self.peek()
        if ch == "!":
            raise YamlError(f"unsupported YAML tag at offset {self.i}")
        if ch == "*":
            name = self.read_indicator_name("*", in_flow=True)
            if name not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{name}'")
            return self.anchors[name]
        if ch == "&":
            name = self.read_indicator_name("&", in_flow=True)
            self.skip_flow_ws_comments()
            if self.peek() in ("", ",", "}", "]"):
                val = None
            else:
                val = self.parse_flow_value()
            self.anchors[name] = val
            return val
        if ch == "{":
            return self.parse_flow_mapping()
        if ch == "[":
            return self.parse_flow_seq()
        if ch == '"':
            return self.parse_dquote()
        if ch == "'":
            return self.parse_squote()
        return self.parse_plain(in_flow=True)

    def parse_block_scalar(self, parent_indent: int) -> str:
        style = self.s[self.i]
        self.i += 1
        chomp = ""
        if self.peek() in ("+", "-"):
            chomp = self.peek()
            self.i += 1
        self.skip_comment_eol()
        lines: list[str] = []
        ind: int | None = None
        while self.i < self.n:
            line_start = self.i
            nl = self.s.find("\n", self.i)
            line_end = self.n if nl == -1 else nl
            line = self.s[line_start:line_end]
            if line.strip(" ") == "":
                lines.append("")
                self.i = self.n if nl == -1 else nl + 1
                continue
            cur = len(line) - len(line.lstrip(" "))
            if cur <= parent_indent:
                break
            if ind is None:
                ind = cur
            elif cur < ind:
                raise YamlError("inconsistent block scalar indentation")
            lines.append(line[ind:])
            self.i = self.n if nl == -1 else nl + 1
        while lines and lines[-1] == "":
            lines.pop()
        if not lines:
            return ""
        body = "\n".join(lines) if style == "|" else " ".join(l if l else "\n" for l in lines)
        if chomp == "-":
            return body
        return body + "\n"

    def skip_block_seq(self, seq_indent: int) -> list:
        items: list = []
        while True:
            self.skip_blank_and_comments()
            if self.eof() or self.at_doc_marker():
                break
            ind = self.current_line_indent()
            if ind != seq_indent:
                break
            if not (self.s[self.i + ind :].startswith("- ") or self.s[self.i + ind :] == "-" or self.s[self.i + ind :].startswith("-\n")):
                break
            self.i += ind + 1
            self.skip_hws()
            if self.peek() in ("\n", "#", ""):
                self.skip_comment_eol()
                self.skip_blank_and_comments()
                if not self.eof() and self.current_line_indent() > seq_indent:
                    items.append(self.parse_block_value_node(seq_indent))
                else:
                    items.append(None)
            elif self.peek() in ("!", "&", "*"):
                items.append(self.parse_block_value(seq_indent))
            elif self.peek() == "{":
                items.append(self.parse_flow_mapping())
                self.skip_comment_eol()
            elif self.peek() == "[":
                items.append(self.parse_flow_seq())
                self.skip_comment_eol()
            elif self.peek() == '"':
                items.append(self.parse_dquote())
                self.skip_comment_eol()
            elif self.peek() == "'":
                items.append(self.parse_squote())
                self.skip_comment_eol()
            else:
                # Could be `- key: val` compact mapping; skip item lines > seq_indent cleanly.
                nl = self.s.find("\n", self.i)
                self.i = self.n if nl == -1 else nl + 1
                self.skip_indented_rest(seq_indent)
                items.append(object())
        return items

    def skip_indented_rest(self, min_indent: int) -> None:
        while True:
            self.skip_blank_and_comments()
            if self.eof() or self.at_doc_marker():
                break
            if self.current_line_indent() <= min_indent:
                break
            nl = self.s.find("\n", self.i)
            self.i = self.n if nl == -1 else nl + 1

    def parse_block_value(self, parent_indent: int):
        anchor_name: str | None = None
        if self.peek() == "!":
            raise YamlError(f"unsupported YAML tag at offset {self.i}")
        if self.peek() == "&":
            anchor_name = self.read_indicator_name("&", in_flow=False)
            self.skip_hws()
            if self.peek() == "!":
                raise YamlError(f"unsupported YAML tag at offset {self.i}")
            if self.peek() == "&":
                raise YamlError(f"duplicate YAML anchor at offset {self.i}")
        ch = self.peek()
        if ch == "*":
            if anchor_name is not None:
                raise YamlError("YAML alias cannot carry an anchor")
            alias = self.read_indicator_name("*", in_flow=False)
            self.skip_comment_eol()
            if alias not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{alias}'")
            return self.anchors[alias]
        if ch in ("", "\n", "#"):
            self.skip_comment_eol()
            val = self.parse_block_value_node(parent_indent)
        elif ch == "{":
            val = self.parse_flow_mapping()
            self.skip_comment_eol()
        elif ch == "[":
            val = self.parse_flow_seq()
            self.skip_comment_eol()
        elif ch == '"':
            val = self.parse_dquote()
            self.skip_comment_eol()
        elif ch == "'":
            val = self.parse_squote()
            self.skip_comment_eol()
        elif ch in ("|", ">"):
            val = self.parse_block_scalar(parent_indent)
        else:
            val = self.parse_plain(in_flow=False)
        if anchor_name is not None:
            self.anchors[anchor_name] = val
        return val

    def parse_block_value_node(self, parent_indent: int):
        self.skip_blank_and_comments()
        if self.eof() or self.at_doc_marker():
            return None
        ind = self.current_line_indent()
        if ind == parent_indent and self.s[self.i + ind :].startswith(("- ", "-\n")):
            return self.skip_block_seq(ind)
        if ind <= parent_indent:
            return None
        ch = self.s[self.i + ind]
        if ch in ("!", "&", "*"):
            self.i += ind
            return self.parse_block_value(parent_indent)
        if ch == "{":
            self.i += ind
            v = self.parse_flow_mapping()
            self.skip_comment_eol()
            return v
        if ch == "[":
            self.i += ind
            v = self.parse_flow_seq()
            self.skip_comment_eol()
            return v
        if self.s[self.i + ind :].startswith(("- ", "-\n")) or self.s[self.i + ind :] == "-":
            return self.skip_block_seq(ind)
        return self.parse_block_mapping(ind)

    def parse_block_mapping(self, min_indent: int) -> dict:
        res: dict = {}
        block_indent: int | None = None
        while True:
            self.skip_blank_and_comments()
            if self.eof() or self.at_doc_marker():
                break
            ind = self.current_line_indent()
            if ind < min_indent:
                break
            if block_indent is None:
                block_indent = ind
            elif ind < block_indent:
                break
            elif ind > block_indent:
                raise YamlError(f"unexpected indentation ({ind} > {block_indent})")
            if self.s[self.i + ind :].startswith(("- ", "-\n")) or self.s[self.i + ind :] == "-":
                break
            self.i += ind
            k = self.parse_key(in_flow=False)
            self.skip_hws()
            if self.peek() != ":":
                raise YamlError(f"expected ':' after key {k!r}")
            self.i += 1
            if self.peek() not in ("", " ", "\t", "\n"):
                raise YamlError(f"expected whitespace after ':' for key {k!r}")
            self.skip_hws()
            res[k] = self.parse_block_value(block_indent)
        return res


def parse_yaml_mapping(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        raise YamlError(f"unreadable YAML file {path}: {exc}") from exc
    p = _Parser(text)
    p.skip_blank_and_comments()
    if p.eof():
        return {}
    if p.s.startswith("---", p.i) and p.peek(3) in ("", " ", "\t", "\n", "#"):
        p.i += 3
        p.skip_comment_eol()
        p.skip_blank_and_comments()
    if p.eof() or p.at_doc_marker():
        return {}
    ind = p.current_line_indent()
    first = p.s[p.i + ind]
    if first == "{":
        p.i += ind
        doc = p.parse_flow_mapping()
        p.skip_comment_eol()
    elif first in ("[", "-", "|", ">", "!", "*"):
        raise YamlError(f"{path}: root must be a YAML mapping")
    else:
        doc = p.parse_block_mapping(ind)
    p.skip_blank_and_comments()
    if not p.eof() and p.s.startswith("...", p.i) and p.peek(3) in ("", " ", "\t", "\n", "#"):
        return doc
    if not p.eof():
        raise YamlError(f"{path}: unexpected trailing YAML content at offset {p.i}")
    return doc


def parse_systemd_env_file(path: str) -> dict[str, str]:
    """Parse EnvironmentFile= entries as a character stream per systemd.exec(5)."""
    out: dict[str, str] = {}
    if not path or not os.path.isfile(path):
        return out
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        src = fh.read()
    n = len(src)
    i = 0

    def skip_line_rest() -> None:
        nonlocal i
        while i < n and src[i] != "\n":
            i += 1
        if i < n and src[i] == "\n":
            i += 1

    while i < n:
        while i < n and src[i] in " \t\r\n":
            i += 1
        if i >= n:
            break
        if src[i] in ("#", ";"):
            skip_line_rest()
            continue
        k_start = i
        while i < n and src[i] not in ("=", "\n"):
            i += 1
        if i >= n or src[i] != "=":
            if i < n and src[i] == "\n":
                i += 1
            continue
        key = src[k_start:i].strip(" \t\r")
        i += 1  # consume '='
        while i < n and src[i] in " \t":
            i += 1
        if i >= n or src[i] == "\n":
            val = ""
            if i < n:
                i += 1
        elif src[i] == '"':
            i += 1
            buf: list[str] = []
            while i < n:
                ch = src[i]
                if ch == '"':
                    i += 1
                    break
                if ch == "\\" and i + 1 < n:
                    nxt = src[i + 1]
                    # systemd EnvironmentFile double quotes interpret \, ", $, `
                    # and preserve unrecognized backslashes literally.
                    if nxt in ("\\", '"', "$", "`"):
                        buf.append(nxt)
                        i += 2
                        continue
                    if nxt == "\n":
                        i += 2
                        continue
                    if nxt == "\r" and i + 2 < n and src[i + 2] == "\n":
                        i += 3
                        continue
                buf.append(ch)
                i += 1
            skip_line_rest()
            val = "".join(buf)
        elif src[i] == "'":
            i += 1
            buf = []
            while i < n:
                ch = src[i]
                if ch == "'":
                    i += 1
                    break
                buf.append(ch)
                i += 1
            skip_line_rest()
            val = "".join(buf)
        else:
            buf = []
            while i < n:
                ch = src[i]
                if ch == "\n":
                    i += 1
                    break
                if ch == "\\" and i + 1 < n and src[i + 1] == "\n":
                    i += 2
                    continue
                if ch == "\\" and i + 2 < n and src[i + 1] == "\r" and src[i + 2] == "\n":
                    i += 3
                    continue
                buf.append(ch)
                i += 1
            val = "".join(buf).strip(" \t\r")
        if key:
            out[key] = val
    return out


def fmt_systemd_env_line(key: str, val: str) -> str:
    if "\r" in val or "\x00" in val:
        raise YamlError(f"systemd EnvironmentFile: {key} must not contain CR or NUL")
    if val == "" or re.fullmatch(r"[A-Za-z0-9._:/@-]+", val):
        return f"{key}={val}\n"
    esc = (
        val.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("$", "\\$")
        .replace("`", "\\`")
    )
    return f'{key}="{esc}"\n'


def cmd_get(args: list[str]) -> int:
    if len(args) != 3:
        sys.stderr.write("usage: yaml-config.py get FILE SECTION KEY\n")
        return 2
    path, sec, key = args
    try:
        doc = parse_yaml_mapping(path)
    except YamlError as exc:
        sys.stderr.write(f"yaml-config: {exc}\n")
        return 2
    container = doc if sec == "" else doc.get(sec)
    if not isinstance(container, dict) or key not in container:
        return 1
    val = container[key]
    if val is None or isinstance(val, (dict, list)):
        return 1
    if isinstance(val, bool):
        sys.stdout.write("true" if val else "false")
    else:
        sys.stdout.write(str(val))
    return 0


def cmd_env_line(args: list[str]) -> int:
    if len(args) != 2:
        sys.stderr.write("usage: yaml-config.py env-line KEY VALUE\n")
        return 2
    try:
        sys.stdout.write(fmt_systemd_env_line(args[0], args[1]))
    except YamlError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


def _koanf_bool(val) -> bool:
    # Matches koanf v2.3.6 Bool() / strconv.ParseBool returning false on invalid.
    if isinstance(val, bool):
        return val
    return str(val) in ("1", "t", "T", "true", "TRUE", "True")


def _strict_go_bool(raw: str, key: str) -> bool:
    if raw in ("1", "t", "T", "true", "TRUE", "True"):
        return True
    if raw in ("0", "f", "F", "false", "FALSE", "False"):
        return False
    raise YamlError(f"storage.env: invalid boolean for {key}: {raw!r}")


def cmd_render_storage(args: list[str]) -> int:
    if len(args) not in (1, 2):
        sys.stderr.write("usage: yaml-config.py render-storage CONFIG_ENV [YAML_FILE]\n")
        return 2
    config_path = args[0]
    yaml_path = args[1] if len(args) == 2 else ""
    env_map = parse_systemd_env_file(config_path)
    s3_yaml: dict = {}
    if yaml_path:
        try:
            doc = parse_yaml_mapping(yaml_path)
        except YamlError as exc:
            sys.stderr.write(f"render_storage_env: {exc}\n")
            return 2
        if isinstance(doc.get("s3"), dict):
            s3_yaml = doc["s3"]

    yaml_keys = ("endpoint", "access_key", "secret_key", "bucket", "secure")
    env_keys = (
        "S3_ENDPOINT",
        "S3_ACCESS_KEY",
        "S3_SECRET_KEY",
        "S3_BUCKET",
        "S3_SECURE",
        "MINIO_ENDPOINT",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
        "MINIO_BUCKET",
        "MINIO_SECURE",
    )
    if not any(k in s3_yaml for k in yaml_keys) and not any(k in env_map for k in env_keys):
        return 0

    endpoint = (
        str(s3_yaml["endpoint"]) if s3_yaml.get("endpoint") is not None else "127.0.0.1:9000"
    )
    if "S3_ENDPOINT" in env_map:
        endpoint = env_map["S3_ENDPOINT"]
    if endpoint == "127.0.0.1:9000" and env_map.get("MINIO_ENDPOINT"):
        endpoint = env_map["MINIO_ENDPOINT"]

    access_key = str(s3_yaml["access_key"]) if s3_yaml.get("access_key") is not None else ""
    if "S3_ACCESS_KEY" in env_map:
        access_key = env_map["S3_ACCESS_KEY"]
    if access_key == "" and env_map.get("MINIO_ACCESS_KEY"):
        access_key = env_map["MINIO_ACCESS_KEY"]

    secret_key = str(s3_yaml["secret_key"]) if s3_yaml.get("secret_key") is not None else ""
    if "S3_SECRET_KEY" in env_map:
        secret_key = env_map["S3_SECRET_KEY"]
    if secret_key == "" and env_map.get("MINIO_SECRET_KEY"):
        secret_key = env_map["MINIO_SECRET_KEY"]

    bucket = str(s3_yaml["bucket"]) if s3_yaml.get("bucket") is not None else "mailblobs"
    if "S3_BUCKET" in env_map:
        bucket = env_map["S3_BUCKET"]
    if bucket == "mailblobs" and env_map.get("MINIO_BUCKET"):
        bucket = env_map["MINIO_BUCKET"]

    try:
        if env_map.get("MINIO_SECURE"):
            secure = _strict_go_bool(env_map["MINIO_SECURE"], "MINIO_SECURE")
        elif "S3_SECURE" in env_map:
            secure = _koanf_bool(env_map["S3_SECURE"])
        elif s3_yaml.get("secure") is not None:
            secure = _koanf_bool(s3_yaml["secure"])
        else:
            secure = False

        for k, v in (
            ("S3_ENDPOINT", endpoint),
            ("S3_SECURE", "true" if secure else "false"),
            ("S3_BUCKET", bucket),
            ("S3_ACCESS_KEY", access_key),
            ("S3_SECRET_KEY", secret_key),
        ):
            sys.stdout.write(fmt_systemd_env_line(k, v))
    except YamlError as exc:
        sys.stderr.write(f"{exc}\n")
        return 1
    return 0


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        sys.stderr.write("usage: yaml-config.py <get|env-line|render-storage> ...\n")
        return 2
    cmd = argv[1]
    if cmd == "get":
        return cmd_get(argv[2:])
    if cmd == "env-line":
        return cmd_env_line(argv[2:])
    if cmd == "render-storage":
        return cmd_render_storage(argv[2:])
    sys.stderr.write(f"unknown subcommand: {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
