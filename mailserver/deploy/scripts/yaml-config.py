#!/usr/bin/env python3
"""Pure-stdlib YAML 1.2 scalar/mapping reader and systemd EnvironmentFile helper.

Used by mailserver/deploy/scripts/lib-livekit.sh so install/upgrade and CI deploy
guards require only Python 3 stdlib (no external PyYAML dependency).
"""

from __future__ import annotations

import math
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
        if re.fullmatch(r"[+-]?(?:0|[1-9][0-9]*)", raw):
            return int(raw)
        if re.fullmatch(
            r"[+-]?(?:(?:0|[1-9][0-9]*)\.[0-9]*(?:[eE][+-]?[0-9]+)?|\.[0-9]+(?:[eE][+-]?[0-9]+)?|(?:0|[1-9][0-9]*)[eE][+-]?[0-9]+)",
            raw,
        ):
            return float(raw)
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

    def read_tag(self, in_flow: bool = False) -> str:
        assert self.s[self.i] == "!"
        start = self.i
        if self.peek(1) == "<":
            self.i += 2
            inner_start = self.i
            while self.i < self.n and self.s[self.i] not in (">", "\n"):
                self.i += 1
            if self.peek() != ">":
                raise YamlError(f"unterminated verbatim YAML tag at offset {start}")
            uri = self.s[inner_start : self.i]
            self.i += 1
            if uri.startswith("tag:yaml.org,2002:"):
                short = uri[len("tag:yaml.org,2002:") :]
            else:
                raise YamlError(f"unsupported YAML tag <{uri}> at offset {start}")
        else:
            self.i += 1
            tok_start = self.i
            stops = " \t\n" + (",{}[]" if in_flow else "")
            while self.i < self.n and self.s[self.i] not in stops:
                self.i += 1
            tok = self.s[tok_start : self.i]
            if not tok.startswith("!") or len(tok) < 2:
                raise YamlError(f"unsupported YAML tag '!{tok}' at offset {start}")
            short = tok[1:]
        if short not in ("str", "bool", "int", "float", "null", "map", "seq"):
            raise YamlError(f"unsupported YAML tag '{short}' at offset {start}")
        return short

    def parse_node_props(self, in_flow: bool = False) -> tuple[str | None, str | None]:
        tag: str | None = None
        anchor: str | None = None
        while self.peek() in ("!", "&"):
            if self.peek() == "!":
                if tag is not None:
                    raise YamlError(f"duplicate YAML tag at offset {self.i}")
                tag = self.read_tag(in_flow=in_flow)
            else:
                if anchor is not None:
                    raise YamlError(f"duplicate YAML anchor at offset {self.i}")
                anchor = self.read_indicator_name("&", in_flow=in_flow)
            if in_flow:
                self.skip_flow_ws_comments()
            else:
                self.skip_hws()
        return tag, anchor

    def apply_tag(self, tag: str | None, val, raw_plain: str | None = None):
        if tag is None:
            return val
        if tag == "str":
            if isinstance(val, (dict, list)):
                raise YamlError("cannot tag collection with !!str")
            if raw_plain is not None:
                return raw_plain
            if val is None:
                return ""
            if isinstance(val, bool):
                return "true" if val else "false"
            return str(val)
        if tag == "null":
            if val is None or val in ("", "null", "Null", "NULL", "~"):
                return None
            raise YamlError(f"invalid !!null value {val!r}")
        if tag == "bool":
            if isinstance(val, bool):
                return val
            s = raw_plain if raw_plain is not None else str(val)
            if s in ("true", "True", "TRUE"):
                return True
            if s in ("false", "False", "FALSE"):
                return False
            raise YamlError(f"invalid !!bool value {s!r}")
        if tag == "int":
            if isinstance(val, bool):
                raise YamlError("cannot coerce bool to !!int")
            if isinstance(val, int):
                return val
            s = raw_plain if raw_plain is not None else str(val)
            try:
                return int(s, 0)
            except ValueError as exc:
                raise YamlError(f"invalid !!int value {s!r}") from exc
        if tag == "float":
            if isinstance(val, bool):
                raise YamlError("cannot coerce bool to !!float")
            if isinstance(val, (int, float)):
                return float(val)
            s = raw_plain if raw_plain is not None else str(val)
            try:
                return float(s)
            except ValueError as exc:
                raise YamlError(f"invalid !!float value {s!r}") from exc
        if tag == "map":
            if val is None:
                return {}
            if not isinstance(val, dict):
                raise YamlError("!!map requires a mapping")
            return val
        if tag == "seq":
            if val is None:
                return []
            if not isinstance(val, list):
                raise YamlError("!!seq requires a sequence")
            return val
        raise YamlError(f"unsupported YAML tag {tag!r}")

    def parse_plain(self, in_flow: bool = False, coerce: bool = True):
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
        return self.coerce_plain(text) if coerce else text

    def parse_key(self, in_flow: bool = False) -> tuple[str, bool]:
        if self.eof():
            raise YamlError("unexpected EOF reading key")
        tag, anchor = self.parse_node_props(in_flow=in_flow)
        ch = self.peek()
        raw_plain: str | None = None
        is_plain_untagged = tag is None
        if ch == "*":
            if tag is not None or anchor is not None:
                raise YamlError("YAML alias cannot carry an anchor or tag")
            alias = self.read_indicator_name("*", in_flow=in_flow)
            if alias not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{alias}'")
            val = self.anchors[alias]
            is_plain_untagged = False
        elif ch == '"':
            val = self.parse_dquote()
            is_plain_untagged = False
        elif ch == "'":
            val = self.parse_squote()
            is_plain_untagged = False
        elif ch in ("{", "["):
            raise YamlError(f"flow collection cannot be a block/plain mapping key at offset {self.i}")
        else:
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
            raw_plain = self.s[start : self.i].strip()
            if not raw_plain and tag is None:
                raise YamlError(f"empty mapping key at offset {start}")
            val = raw_plain if tag == "str" else self.coerce_plain(raw_plain)
        val = self.apply_tag(tag, val, raw_plain=raw_plain)
        if isinstance(val, (dict, list)):
            raise YamlError("collection mapping keys are unsupported")
        if val is None:
            key = ""
        elif isinstance(val, bool):
            key = "true" if val else "false"
        else:
            key = str(val)
        if anchor is not None:
            self.anchors[anchor] = key
        return key, is_plain_untagged

    def skip_flow_ws_comments(self) -> None:
        while self.i < self.n:
            while self.i < self.n and self.s[self.i] in " \t\n":
                self.i += 1
            if self.i < self.n and self.s[self.i] == "#":
                while self.i < self.n and self.s[self.i] != "\n":
                    self.i += 1
                continue
            break

    def apply_merge_or_set(
        self,
        seen_keys: set[tuple[str, bool]],
        merged: dict,
        explicit: dict,
        key: str,
        val,
        allow_merge: bool = True,
    ) -> None:
        is_merge = key == "<<" and allow_merge
        token = (key, is_merge)
        if token in seen_keys:
            raise YamlError(f"duplicate YAML key {key!r}")
        seen_keys.add(token)
        if is_merge:
            if isinstance(val, dict):
                sources = [val]
            elif isinstance(val, list) and all(isinstance(x, dict) for x in val):
                sources = val
            else:
                raise YamlError("YAML merge key '<<' requires a mapping or list of mappings")
            for src in sources:
                for mk, mv in src.items():
                    merged.setdefault(mk, mv)
        else:
            explicit[key] = val

    def parse_flow_mapping(self) -> dict:
        assert self.s[self.i] == "{"
        self.i += 1
        seen_keys: set[str] = set()
        merged: dict = {}
        explicit: dict = {}
        while True:
            self.skip_flow_ws_comments()
            if self.eof():
                raise YamlError("unterminated flow mapping '{'")
            if self.peek() == "}":
                self.i += 1
                return {**merged, **explicit}
            k, allow_merge = self.parse_key(in_flow=True)
            self.skip_flow_ws_comments()
            if self.peek() != ":":
                raise YamlError(f"expected ':' after flow key {k!r}")
            self.i += 1
            self.skip_flow_ws_comments()
            if self.peek() in (",", "}"):
                val = None
            else:
                val = self.parse_flow_value()
            self.apply_merge_or_set(seen_keys, merged, explicit, k, val, allow_merge=allow_merge)
            self.skip_flow_ws_comments()
            if self.peek() == ",":
                self.i += 1
                continue
            if self.peek() == "}":
                self.i += 1
                return {**merged, **explicit}
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
        tag, anchor = self.parse_node_props(in_flow=True)
        ch = self.peek()
        if ch == "*":
            if tag is not None or anchor is not None:
                raise YamlError("YAML alias cannot carry an anchor or tag")
            name = self.read_indicator_name("*", in_flow=True)
            if name not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{name}'")
            return self.anchors[name]
        raw_plain: str | None = None
        if ch in ("", ",", "}", "]"):
            val = None
        elif ch == "{":
            val = self.parse_flow_mapping()
        elif ch == "[":
            val = self.parse_flow_seq()
        elif ch == '"':
            val = self.parse_dquote()
        elif ch == "'":
            val = self.parse_squote()
        else:
            raw_plain = self.parse_plain(in_flow=True, coerce=False)
            val = raw_plain if tag == "str" else self.coerce_plain(raw_plain)
        val = self.apply_tag(tag, val, raw_plain=raw_plain)
        if anchor is not None:
            self.anchors[anchor] = val
        return val

    def parse_block_scalar(self, parent_indent: int) -> str:
        style = self.s[self.i]
        self.i += 1
        chomp = ""
        explicit_ind: int | None = None
        while self.peek() in ("+", "-", "1", "2", "3", "4", "5", "6", "7", "8", "9"):
            c = self.peek()
            if c in ("+", "-"):
                if chomp:
                    raise YamlError(f"duplicate block scalar chomp indicator at offset {self.i}")
                chomp = c
            else:
                if explicit_ind is not None:
                    raise YamlError(f"duplicate block scalar indent indicator at offset {self.i}")
                explicit_ind = int(c)
            self.i += 1
        self.skip_comment_eol()
        raw_lines: list[tuple[str, bool]] = []
        ind: int | None = (parent_indent + explicit_ind) if explicit_ind is not None else None
        while self.i < self.n:
            line_start = self.i
            nl = self.s.find("\n", self.i)
            line_end = self.n if nl == -1 else nl
            line = self.s[line_start:line_end]
            if line.strip(" ") == "":
                extra = line[ind:] if (ind is not None and len(line) > ind) else ""
                raw_lines.append((extra, extra == ""))
                self.i = self.n if nl == -1 else nl + 1
                continue
            cur = len(line) - len(line.lstrip(" "))
            if cur <= parent_indent:
                break
            if ind is None:
                ind = cur
            elif cur < ind:
                raise YamlError("inconsistent block scalar indentation")
            raw_lines.append((line[ind:], False))
            self.i = self.n if nl == -1 else nl + 1
        trailing_blanks = 0
        while raw_lines and raw_lines[-1][1]:
            raw_lines.pop()
            trailing_blanks += 1
        if not raw_lines:
            return ("\n" * trailing_blanks) if chomp == "+" else ""
        if style == "|":
            body = "\n".join(text for text, _ in raw_lines)
        else:
            parts: list[str] = []
            blanks = 0
            prev_text: str | None = None
            for text, is_blank in raw_lines:
                if is_blank:
                    blanks += 1
                    continue
                if prev_text is None:
                    if blanks > 0:
                        parts.append("\n" * blanks)
                elif blanks > 0:
                    if prev_text.startswith((" ", "\t")) or text.startswith((" ", "\t")):
                        parts.append("\n" * (blanks + 1))
                    else:
                        parts.append("\n" * blanks)
                elif prev_text.startswith((" ", "\t")) or text.startswith((" ", "\t")):
                    parts.append("\n")
                else:
                    parts.append(" ")
                parts.append(text)
                prev_text = text
                blanks = 0
            body = "".join(parts)
        if chomp == "-":
            return body
        if chomp == "+":
            return body + ("\n" * (1 + trailing_blanks))
        return body + "\n"

    def _starts_block_mapping_entry(self) -> bool:
        save_i = self.i
        save_anchors = dict(self.anchors)
        try:
            self.parse_key(in_flow=False)
            self.skip_hws()
            return self.peek() == ":" and self.peek(1) in ("", " ", "\t", "\n")
        except YamlError:
            return False
        finally:
            self.i = save_i
            self.anchors = save_anchors

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
            elif self.peek() == "{":
                items.append(self.parse_flow_mapping())
                self.skip_comment_eol()
            elif self.peek() == "[":
                items.append(self.parse_flow_seq())
                self.skip_comment_eol()
            elif self._starts_block_mapping_entry():
                ls = self.s.rfind("\n", 0, self.i)
                item_indent = self.i - (0 if ls == -1 else ls + 1)
                seen_keys: set[tuple[str, bool]] = set()
                merged: dict = {}
                explicit: dict = {}
                k, allow_merge = self.parse_key(in_flow=False)
                self.skip_hws()
                self.i += 1  # consume ':'
                self.skip_hws()
                val = self.parse_block_value(item_indent)
                self.apply_merge_or_set(seen_keys, merged, explicit, k, val, allow_merge=allow_merge)
                rest = self.parse_block_mapping(item_indent, seen_keys=seen_keys, merged=merged, explicit=explicit)
                items.append(rest)
            elif self.peek() in ("!", "&", "*"):
                items.append(self.parse_block_value(seq_indent))
            elif self.peek() == '"':
                items.append(self.parse_dquote())
                self.skip_comment_eol()
            elif self.peek() == "'":
                items.append(self.parse_squote())
                self.skip_comment_eol()
            else:
                items.append(self.parse_plain(in_flow=False))
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
        tag, anchor_name = self.parse_node_props(in_flow=False)
        ch = self.peek()
        if ch == "*":
            if tag is not None or anchor_name is not None:
                raise YamlError("YAML alias cannot carry an anchor or tag")
            alias = self.read_indicator_name("*", in_flow=False)
            self.skip_comment_eol()
            if alias not in self.anchors:
                raise YamlError(f"undefined YAML alias '*{alias}'")
            return self.anchors[alias]
        raw_plain: str | None = None
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
            raw_plain = self.parse_plain(in_flow=False, coerce=False)
            val = raw_plain if tag == "str" else self.coerce_plain(raw_plain)
        val = self.apply_tag(tag, val, raw_plain=raw_plain)
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
            saved = self.i
            self.i += ind
            if self._starts_block_mapping_entry():
                self.i = saved
                return self.parse_block_mapping(ind)
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

    def parse_block_mapping(
        self,
        min_indent: int,
        seen_keys: set[str] | None = None,
        merged: dict | None = None,
        explicit: dict | None = None,
    ) -> dict:
        if seen_keys is None:
            seen_keys = set()
        if merged is None:
            merged = {}
        if explicit is None:
            explicit = {}
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
            k, allow_merge = self.parse_key(in_flow=False)
            self.skip_hws()
            if self.peek() != ":":
                raise YamlError(f"expected ':' after key {k!r}")
            self.i += 1
            if self.peek() not in ("", " ", "\t", "\n"):
                raise YamlError(f"expected whitespace after ':' for key {k!r}")
            self.skip_hws()
            val = self.parse_block_value(block_indent)
            self.apply_merge_or_set(seen_keys, merged, explicit, k, val, allow_merge=allow_merge)
        return {**merged, **explicit}


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
    root_tag: str | None = None
    root_anchor: str | None = None
    if p.s[p.i + ind] in ("!", "&"):
        saved = p.i
        p.i += ind
        if p._starts_block_mapping_entry():
            p.i = saved
        else:
            root_tag, root_anchor = p.parse_node_props(in_flow=False)
            if p.peek() in ("", "\n", "#"):
                p.skip_comment_eol()
                p.skip_blank_and_comments()
                if p.eof() or p.at_doc_marker():
                    doc = p.apply_tag(root_tag, None)
                    if not isinstance(doc, dict):
                        raise YamlError(f"{path}: root must be a YAML mapping")
                    if root_anchor is not None:
                        p.anchors[root_anchor] = doc
                    return doc
                ind = p.current_line_indent()
            else:
                ind = 0
    first = p.s[p.i + ind]
    if first == "{":
        p.i += ind
        doc = p.parse_flow_mapping()
        p.skip_comment_eol()
    elif first in ("[", "-", "|", ">", "*"):
        raise YamlError(f"{path}: root must be a YAML mapping")
    else:
        doc = p.parse_block_mapping(ind)
    doc = p.apply_tag(root_tag, doc)
    if not isinstance(doc, dict):
        raise YamlError(f"{path}: root must be a YAML mapping")
    if root_anchor is not None:
        p.anchors[root_anchor] = doc
    p.skip_blank_and_comments()
    if not p.eof() and p.s.startswith("...", p.i) and p.peek(3) in ("", " ", "\t", "\n", "#"):
        return doc
    if not p.eof():
        raise YamlError(f"{path}: unexpected trailing YAML content at offset {p.i}")
    return doc


def parse_systemd_env_entries(path: str) -> dict[str, tuple[str, str | None]]:
    """Parse EnvironmentFile= entries matching systemd/src/basic/env-file.c v255."""
    out: dict[str, tuple[str, str | None]] = {}
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
        raw_key = src[k_start:i]
        key = raw_key.strip(" \t\r")
        i += 1  # consume '='
        state = "PRE_VALUE"
        buf: list[str] = []
        last_non_ws = 0
        while i < n:
            ch = src[i]
            if state == "PRE_VALUE":
                if ch == "\n":
                    i += 1
                    break
                if ch in (" ", "\t", "\r"):
                    i += 1
                    continue
                if ch == '"':
                    state = "DQUOTE"
                    i += 1
                    continue
                if ch == "'":
                    state = "SQUOTE"
                    i += 1
                    continue
                if ch == "\\":
                    if i + 1 < n and src[i + 1] == "\n":
                        i += 2
                        state = "VALUE"
                        continue
                    if i + 2 < n and src[i + 1] == "\r" and src[i + 2] == "\n":
                        i += 3
                        state = "VALUE"
                        continue
                    if i + 1 < n:
                        buf.append(src[i + 1])
                        i += 2
                        last_non_ws = len(buf)
                        state = "VALUE"
                        continue
                    i += 1
                    state = "VALUE"
                    continue
                buf.append(ch)
                last_non_ws = len(buf)
                i += 1
                state = "VALUE"
            elif state == "VALUE":
                if ch == "\n":
                    i += 1
                    break
                if ch == "\\":
                    if i + 1 < n and src[i + 1] == "\n":
                        i += 2
                        state = "VALUE"
                        continue
                    if i + 2 < n and src[i + 1] == "\r" and src[i + 2] == "\n":
                        i += 3
                        state = "VALUE"
                        continue
                    if i + 1 < n:
                        buf.append(src[i + 1])
                        i += 2
                        last_non_ws = len(buf)
                        continue
                buf.append(ch)
                if ch not in (" ", "\t", "\r"):
                    last_non_ws = len(buf)
                i += 1
            elif state == "DQUOTE":
                if ch == '"':
                    state = "PRE_VALUE"
                    last_non_ws = len(buf)
                    i += 1
                    continue
                if ch == "\\" and i + 1 < n:
                    nxt = src[i + 1]
                    # systemd EnvironmentFile double quotes interpret \, ", $, `
                    # and preserve unrecognized backslashes literally.
                    if nxt in ("\\", '"', "$", "`"):
                        buf.append(nxt)
                        last_non_ws = len(buf)
                        i += 2
                        continue
                    if nxt == "\n":
                        i += 2
                        continue
                    if nxt == "\r" and i + 2 < n and src[i + 2] == "\n":
                        i += 3
                        continue
                buf.append(ch)
                last_non_ws = len(buf)
                i += 1
            else:
                if ch == "'":
                    state = "PRE_VALUE"
                    last_non_ws = len(buf)
                    i += 1
                    continue
                buf.append(ch)
                last_non_ws = len(buf)
                i += 1
        val = "".join(buf[:last_non_ws])
        end_pos = i - 1 if (i > k_start and src[i - 1] == "\n") else i
        raw_slice = src[k_start:end_pos].rstrip("\r")
        raw_line = (
            raw_slice
            if (k_start == 0 or src[k_start - 1] == "\n")
            and raw_key == key
            and "\n" not in raw_slice
            else None
        )
        if key:
            out[key] = (val, raw_line)
    return out


def parse_systemd_env_file(path: str) -> dict[str, str]:
    """Parse EnvironmentFile= entries matching systemd/src/basic/env-file.c v255."""
    return {k: val for k, (val, _) in parse_systemd_env_entries(path).items()}


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
    elif isinstance(val, float) and math.isfinite(val) and val.is_integer():
        sys.stdout.write(str(int(val)))
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


def cmd_env_get(args: list[str]) -> int:
    if len(args) != 2:
        sys.stderr.write("usage: yaml-config.py env-get FILE KEY\n")
        return 2
    env_map = parse_systemd_env_file(args[0])
    key = args[1]
    if key not in env_map:
        return 1
    sys.stdout.write(env_map[key])
    return 0


def cmd_env_copy(args: list[str]) -> int:
    if len(args) < 2:
        sys.stderr.write("usage: yaml-config.py env-copy FILE KEY [KEY ...]\n")
        return 2
    try:
        env_map = parse_systemd_env_file(args[0])
        for key in args[1:]:
            val = env_map.get(key)
            if val:
                sys.stdout.write(fmt_systemd_env_line(key, val))
    except (OSError, YamlError) as exc:
        sys.stderr.write(f"{exc}\n")
        return 2
    return 0


def cmd_env_preserve(args: list[str]) -> int:
    if len(args) != 2:
        sys.stderr.write("usage: yaml-config.py env-preserve FILE KEY\n")
        return 2
    entries = parse_systemd_env_entries(args[0])
    key = args[1]
    if key not in entries:
        return 1
    val, raw_line = entries[key]
    if "\n" in val or "\r" in val:
        sys.stderr.write(f"TLS setting {key} must be one EnvironmentFile line (use a config file for JSON)\n")
        return 2
    if val == "":
        return 3
    if raw_line is not None:
        sys.stdout.write(f"{raw_line}\n")
    else:
        sys.stdout.write(fmt_systemd_env_line(key, val))
    return 0


def _koanf_bool(val) -> bool:
    # Matches koanf v2.3.6 Bool() / strconv.ParseBool returning false on invalid.
    if isinstance(val, bool):
        return val
    if isinstance(val, (int, float)):
        return val == 1
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
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(newline="\n")
    if len(argv) < 2:
        sys.stderr.write("usage: yaml-config.py <get|env-line|env-get|env-copy|env-preserve|render-storage> ...\n")
        return 2
    cmd = argv[1]
    if cmd == "get":
        return cmd_get(argv[2:])
    if cmd == "env-line":
        return cmd_env_line(argv[2:])
    if cmd == "env-get":
        return cmd_env_get(argv[2:])
    if cmd == "env-copy":
        return cmd_env_copy(argv[2:])
    if cmd == "env-preserve":
        return cmd_env_preserve(argv[2:])
    if cmd == "render-storage":
        return cmd_render_storage(argv[2:])
    sys.stderr.write(f"unknown subcommand: {cmd}\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
