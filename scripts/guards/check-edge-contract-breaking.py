#!/usr/bin/env python3
"""Deterministic OpenAPI 3.1 breaking-change detector & 12-month sunset waiver validator (#561).

Runs with Python 3.9+ stdlib only (uses PyYAML when installed, falls back to a
built-in deterministic YAML 1.2 block/flow parser for OpenAPI YAML documents).

Detects breaking API evolutions between `--base` and `--head`:
  - removed paths
  - removed HTTP methods
  - removed response status codes (2xx AND error/non-2xx responses) or media types
  - removed response properties or optionalized previously-required response properties
  - newly required request bodies, request properties, or parameters
  - narrowed enums (removed enum members on request or response schemas)
  - incompatible property/schema type changes (including nullability shifts)
  - incompatible map `additionalProperties` schema changes
  - removed union (`anyOf`/`oneOf`) object variants
  - any unwaived `ERR` findings emitted by `oasdiff breaking --format json`

Enforces the 12-month compatibility window on `contracts/edge/approved-breaking.json`:
  - every waiver must have `sunset_after - deprecated_on >= 365 days`
  - a waiver only suppresses a breaking change once `today >= sunset_after`
  - the waived target MUST already be marked deprecated (`deprecated: true` or
    `x-deprecated-on`) in the `--base` OpenAPI spec
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys
from typing import Any

try:
    import yaml as _pyyaml  # type: ignore[import-not-found]
except ModuleNotFoundError:
    _pyyaml = None

HTTP_METHODS = ("get", "post", "put", "delete", "patch", "head", "options")
MIN_COMPAT_WINDOW_DAYS = 365


# ── Minimal pure-Python YAML parser (fallback when PyYAML is unavailable) ───


def _parse_scalar(raw: str) -> Any:
    s = raw.strip()
    if s == "" or s in ("null", "~"):
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    if s == "{}":
        return {}
    if s == "[]":
        return []
    if s.startswith("'") and s.endswith("'") and len(s) >= 2:
        return s[1:-1].replace("''", "'")
    if s.startswith('"') and s.endswith('"') and len(s) >= 2:
        return json.loads(s)
    if s.startswith("{") or s.startswith("["):
        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass
    if re.fullmatch(r"-?[0-9]+", s):
        return int(s)
    if re.fullmatch(r"-?[0-9]+\.[0-9]+", s):
        return float(s)
    return s


def _split_key_value(content: str) -> tuple[str, str | None]:
    """Split a YAML mapping line `key: value` respecting single/double quotes."""
    in_single = False
    in_double = False
    escaped = False
    for i, ch in enumerate(content):
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == ":" and (i + 1 == len(content) or content[i + 1] == " "):
                key_raw = content[:i].strip()
                val_raw = content[i + 1 :].strip()
                key = str(_parse_scalar(key_raw))
                return key, (val_raw if val_raw != "" else None)
    raise ValueError(f"Invalid YAML mapping line: {content!r}")


def _strip_yaml_comment(line: str) -> str:
    in_single = False
    in_double = False
    escaped = False
    for i, ch in enumerate(line):
        if in_single:
            if ch == "'":
                in_single = False
        elif in_double:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_double = False
        else:
            if ch == "'":
                in_single = True
            elif ch == '"':
                in_double = True
            elif ch == "#" and (i == 0 or line[i - 1] == " "):
                return line[:i].rstrip()
    return line.rstrip()


def _load_yaml_stdlib(text: str) -> Any:
    stripped = text.lstrip()
    if stripped.startswith("{") or stripped.startswith("["):
        return json.loads(text)

    tokens: list[tuple[int, str]] = []
    for raw_line in text.splitlines():
        cleaned = _strip_yaml_comment(raw_line)
        if not cleaned.strip():
            continue
        indent = len(cleaned) - len(cleaned.lstrip(" "))
        tokens.append((indent, cleaned[indent:]))

    if not tokens:
        return {}

    def _looks_like_mapping(s: str) -> bool:
        if s.startswith("{") or s.startswith("["):
            return False
        try:
            _split_key_value(s)
            return True
        except ValueError:
            return False

    def parse_block(idx: int, min_indent: int) -> tuple[Any, int]:
        indent, content = tokens[idx]
        if content == "-" or content.startswith("- "):
            return parse_seq(idx, indent)
        return parse_map(idx, indent)

    def parse_seq(idx: int, base_indent: int) -> tuple[list[Any], int]:
        items: list[Any] = []
        while idx < len(tokens):
            indent, content = tokens[idx]
            if indent < base_indent:
                break
            if indent != base_indent or not (content == "-" or content.startswith("- ")):
                break
            rest = content[1:].lstrip(" ") if len(content) > 1 else ""
            if rest == "":
                idx += 1
                if idx < len(tokens) and tokens[idx][0] > base_indent:
                    val, idx = parse_block(idx, tokens[idx][0])
                    items.append(val)
                else:
                    items.append(None)
                continue
            if _looks_like_mapping(rest):
                item_indent = base_indent + 2
                k, v = _split_key_value(rest)
                obj: dict[str, Any] = {}
                idx += 1
                if v is None:
                    if idx < len(tokens) and tokens[idx][0] > item_indent:
                        obj[k], idx = parse_block(idx, tokens[idx][0])
                    else:
                        obj[k] = None
                else:
                    obj[k] = _parse_scalar(v)
                if idx < len(tokens) and tokens[idx][0] >= item_indent:
                    extra, idx = parse_map(idx, item_indent)
                    obj.update(extra)
                items.append(obj)
            else:
                items.append(_parse_scalar(rest))
                idx += 1
        return items, idx

    def parse_map(idx: int, base_indent: int) -> tuple[dict[str, Any], int]:
        obj: dict[str, Any] = {}
        while idx < len(tokens):
            indent, content = tokens[idx]
            if indent < base_indent:
                break
            if indent != base_indent or content == "-" or content.startswith("- "):
                break
            key, val_raw = _split_key_value(content)
            idx += 1
            if val_raw is not None:
                if val_raw in ("|", ">", "|-", ">-"):
                    lines: list[str] = []
                    block_indent: int | None = None
                    while idx < len(tokens) and tokens[idx][0] > base_indent:
                        if block_indent is None:
                            block_indent = tokens[idx][0]
                        lines.append(tokens[idx][1])
                        idx += 1
                    obj[key] = "\n".join(lines)
                else:
                    obj[key] = _parse_scalar(val_raw)
            else:
                if idx < len(tokens) and tokens[idx][0] > base_indent:
                    val, idx = parse_block(idx, tokens[idx][0])
                    obj[key] = val
                elif (
                    idx < len(tokens)
                    and tokens[idx][0] == base_indent
                    and (tokens[idx][1] == "-" or tokens[idx][1].startswith("- "))
                ):
                    val, idx = parse_seq(idx, base_indent)
                    obj[key] = val
                else:
                    obj[key] = None
        return obj, idx

    result, _ = parse_block(0, tokens[0][0])
    return result


def load_openapi(path: pathlib.Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if _pyyaml is not None:
        doc = _pyyaml.safe_load(text)
    else:
        doc = _load_yaml_stdlib(text)
    if not isinstance(doc, dict):
        raise ValueError(f"OpenAPI document is not a mapping: {path}")
    return doc


# ── OpenAPI 3.1 schema resolution & compatibility comparison ────────────────


def resolve_schema(doc: dict[str, Any], schema: Any, seen: set[str] | None = None) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    if "$ref" in schema:
        ref = str(schema["$ref"])
        seen = seen or set()
        if ref in seen:
            return {}
        seen = seen | {ref}
        prefix = "#/components/schemas/"
        if ref.startswith(prefix):
            name = ref[len(prefix) :]
            target = (doc.get("components") or {}).get("schemas", {}).get(name)
            if isinstance(target, dict):
                return resolve_schema(doc, target, seen)
        return {}
    return schema


def union_branches(doc: dict[str, Any], schema: dict[str, Any]) -> list[dict[str, Any]] | None:
    raw = schema.get("anyOf") if isinstance(schema.get("anyOf"), list) else schema.get("oneOf")
    if not isinstance(raw, list):
        return None
    return [x for x in raw if isinstance(x, dict)]


def normalize_type(
    doc: dict[str, Any], schema: dict[str, Any]
) -> tuple[str | None, str | None, bool, dict[str, Any]]:
    """Return (base_type, format, nullable, effective_schema)."""
    s = resolve_schema(doc, schema)
    branches = union_branches(doc, s)
    if branches is not None:
        non_null = [b for b in branches if resolve_schema(doc, b).get("type") != "null"]
        has_null = any(resolve_schema(doc, b).get("type") == "null" for b in branches)
        if len(non_null) == 1:
            t, fmt, inner_null, inner = normalize_type(doc, non_null[0])
            return t, fmt, (has_null or inner_null), inner
        return "union", None, has_null, s
    raw_type = s.get("type")
    if isinstance(raw_type, list):
        non_null_t = [t for t in raw_type if t != "null"]
        has_null = "null" in raw_type
        base_t = non_null_t[0] if len(non_null_t) == 1 else "union"
        return base_t, s.get("format"), has_null, s
    return (
        (str(raw_type) if raw_type is not None else None),
        s.get("format"),
        bool(s.get("nullable", False)),
        s,
    )


def types_compatible(
    base_type: tuple[str | None, str | None, bool],
    head_type: tuple[str | None, str | None, bool],
    direction: str,
) -> bool:
    bt, bfmt, bnull = base_type
    ht, hfmt, hnull = head_type
    if bt is None or ht is None:
        return True
    if bt != ht:
        if direction == "request" and bt == "integer" and ht == "number":
            pass
        else:
            return False
    if bt == "integer" and bfmt and hfmt and bfmt != hfmt:
        if direction == "request" and bfmt == "int32" and hfmt == "int64":
            pass
        elif direction == "response" and bfmt == "int64" and hfmt == "int32":
            pass
        else:
            return False
    if direction == "response" and (not bnull) and hnull:
        return False
    if direction == "request" and bnull and (not hnull):
        return False
    return True


def branch_key(doc: dict[str, Any], branch: dict[str, Any], idx: int) -> str:
    if isinstance(branch.get("$ref"), str):
        return str(branch["$ref"]).rsplit("/", 1)[-1]
    resolved = resolve_schema(doc, branch)
    props = resolved.get("properties") if isinstance(resolved.get("properties"), dict) else {}
    dir_prop = props.get("direction")
    if isinstance(dir_prop, dict):
        resolved_dir = resolve_schema(doc, dir_prop)
        enum_vals = resolved_dir.get("enum")
        if isinstance(enum_vals, list) and len(enum_vals) == 1:
            return f"direction={enum_vals[0]}"
    return f"branch[{idx}]"


def compare_schemas(
    base_doc: dict[str, Any],
    head_doc: dict[str, Any],
    base_schema: Any,
    head_schema: Any,
    location: str,
    direction: str,
    findings: list[tuple[str, str]],
    depth: int = 0,
) -> None:
    if depth > 16:
        return
    bt, bfmt, bnull, bs = normalize_type(
        base_doc, base_schema if isinstance(base_schema, dict) else {}
    )
    ht, hfmt, hnull, hs = normalize_type(
        head_doc, head_schema if isinstance(head_schema, dict) else {}
    )

    if not types_compatible((bt, bfmt, bnull), (ht, hfmt, hnull), direction):
        findings.append(
            (
                f"incompatible-type:{location}",
                f"{location}: incompatible type change ({bt}/{bfmt}/nullable={bnull} -> {ht}/{hfmt}/nullable={hnull})",
            )
        )
        return

    # Multi-branch union comparison (e.g., discriminated Inbound/Outbound variants)
    if bt == "union" and ht == "union":
        b_branches = union_branches(base_doc, bs) or []
        h_branches = union_branches(head_doc, hs) or []
        b_map = {
            branch_key(base_doc, b, i): b
            for i, b in enumerate(b_branches)
            if resolve_schema(base_doc, b).get("type") != "null"
        }
        h_map = {
            branch_key(head_doc, b, i): b
            for i, b in enumerate(h_branches)
            if resolve_schema(head_doc, b).get("type") != "null"
        }
        for key in sorted(b_map):
            if key not in h_map:
                findings.append(
                    (
                        f"removed-union-variant:{location}:{key}",
                        f"{location}: union variant `{key}` removed",
                    )
                )
            else:
                compare_schemas(
                    base_doc,
                    head_doc,
                    b_map[key],
                    h_map[key],
                    f"{location}|{key}",
                    direction,
                    findings,
                    depth + 1,
                )
        return

    # Enum checks
    b_enum = bs.get("enum")
    h_enum = hs.get("enum")
    if isinstance(b_enum, list) and isinstance(h_enum, list):
        removed = [v for v in b_enum if v not in h_enum]
        added = [v for v in h_enum if v not in b_enum]
        if removed:
            findings.append(
                (
                    f"narrowed-enum:{location}",
                    f"{location}: enum values removed: {removed}",
                )
            )
        if direction == "response" and added:
            findings.append(
                (
                    f"widened-response-enum:{location}",
                    f"{location}: new enum values added to response enum: {added}",
                )
            )

    if bt == "array":
        compare_schemas(
            base_doc,
            head_doc,
            bs.get("items") or {},
            hs.get("items") or {},
            f"{location}[]",
            direction,
            findings,
            depth + 1,
        )
        return

    if bt == "object":
        b_props = bs.get("properties") if isinstance(bs.get("properties"), dict) else {}
        h_props = hs.get("properties") if isinstance(hs.get("properties"), dict) else {}
        b_req = set(bs.get("required") or [])
        h_req = set(hs.get("required") or [])

        # Check map additionalProperties value schema compatibility (e.g., RuleAction.params, ViewPreferences)
        b_addl = bs.get("additionalProperties")
        h_addl = hs.get("additionalProperties")
        b_unrestricted = b_addl in (None, True, {})
        if b_addl is not None or h_addl is not None:
            if direction == "request" and b_addl is not False and h_addl is False:
                findings.append(
                    (
                        f"restricted-additional-properties:{location}",
                        f"{location}: additionalProperties became disallowed on request object",
                    )
                )
            elif (
                direction == "request"
                and b_unrestricted
                and isinstance(h_addl, dict)
                and bool(h_addl)
            ):
                findings.append(
                    (
                        f"narrowed-additional-properties:{location}",
                        f"{location}: unrestricted request additionalProperties narrowed to {h_addl}",
                    )
                )
            elif isinstance(b_addl, dict) and isinstance(h_addl, dict):
                if b_addl or h_addl:
                    compare_schemas(
                        base_doc,
                        head_doc,
                        b_addl,
                        h_addl,
                        f"{location}.*",
                        direction,
                        findings,
                        depth + 1,
                    )
            elif isinstance(b_addl, dict) and h_addl is False:
                findings.append(
                    (
                        f"removed-additional-properties:{location}",
                        f"{location}: map additionalProperties schema removed",
                    )
                )

        if direction == "response":
            for prop in sorted(b_props):
                if prop not in h_props:
                    findings.append(
                        (
                            f"removed-response-property:{location}.{prop}",
                            f"{location}.{prop}: response property removed",
                        )
                    )
                else:
                    if prop in b_req and prop not in h_req:
                        findings.append(
                            (
                                f"optionalized-response-property:{location}.{prop}",
                                f"{location}.{prop}: previously required response property became optional",
                            )
                        )
                    compare_schemas(
                        base_doc,
                        head_doc,
                        b_props[prop],
                        h_props[prop],
                        f"{location}.{prop}",
                        direction,
                        findings,
                        depth + 1,
                    )
        else:
            for prop in sorted(h_req):
                if prop not in b_req:
                    findings.append(
                        (
                            f"new-required-request-property:{location}.{prop}",
                            f"{location}.{prop}: newly required request property",
                        )
                    )
            for prop in sorted(b_props):
                if prop not in h_props:
                    findings.append(
                        (
                            f"removed-request-property:{location}.{prop}",
                            f"{location}.{prop}: request property removed",
                        )
                    )
                else:
                    compare_schemas(
                        base_doc,
                        head_doc,
                        b_props[prop],
                        h_props[prop],
                        f"{location}.{prop}",
                        direction,
                        findings,
                        depth + 1,
                    )


def diff_openapi(base_doc: dict[str, Any], head_doc: dict[str, Any]) -> list[tuple[str, str]]:
    findings: list[tuple[str, str]] = []
    base_paths = base_doc.get("paths") if isinstance(base_doc.get("paths"), dict) else {}
    head_paths = head_doc.get("paths") if isinstance(head_doc.get("paths"), dict) else {}

    for path_key in sorted(base_paths):
        b_item = base_paths[path_key]
        if not isinstance(b_item, dict):
            continue
        if path_key not in head_paths or not isinstance(head_paths[path_key], dict):
            findings.append((f"removed-path:{path_key}", f"path removed: {path_key}"))
            continue
        h_item = head_paths[path_key]
        for method in HTTP_METHODS:
            if method not in b_item or not isinstance(b_item[method], dict):
                continue
            op_label = f"{method.upper()} {path_key}"
            if method not in h_item or not isinstance(h_item[method], dict):
                findings.append((f"removed-operation:{op_label}", f"operation removed: {op_label}"))
                continue

            b_op = b_item[method]
            h_op = h_item[method]

            # Parameters check
            b_params = {
                (p.get("in"), p.get("name")): p
                for p in (b_op.get("parameters") or [])
                if isinstance(p, dict)
            }
            h_params = {
                (p.get("in"), p.get("name")): p
                for p in (h_op.get("parameters") or [])
                if isinstance(p, dict)
            }
            for key, hp in sorted(h_params.items()):
                bp = b_params.get(key)
                if hp.get("required") and (bp is None or not bp.get("required")):
                    findings.append(
                        (
                            f"new-required-param:{op_label}:{key[0]}:{key[1]}",
                            f"{op_label}: newly required {key[0]} parameter `{key[1]}`",
                        )
                    )
                if bp is not None:
                    compare_schemas(
                        base_doc,
                        head_doc,
                        bp.get("schema") or {},
                        hp.get("schema") or {},
                        f"{op_label}:param:{key[1]}",
                        "request",
                        findings,
                    )

            # Request body check
            b_rb = b_op.get("requestBody") if isinstance(b_op.get("requestBody"), dict) else None
            h_rb = h_op.get("requestBody") if isinstance(h_op.get("requestBody"), dict) else None
            if h_rb and h_rb.get("required") and (not b_rb or not b_rb.get("required")):
                findings.append(
                    (
                        f"new-required-request-body:{op_label}",
                        f"{op_label}: request body became required",
                    )
                )
            if b_rb and h_rb:
                b_content = b_rb.get("content") if isinstance(b_rb.get("content"), dict) else {}
                h_content = h_rb.get("content") if isinstance(h_rb.get("content"), dict) else {}
                for media, b_media in sorted(b_content.items()):
                    if media not in h_content:
                        findings.append(
                            (
                                f"removed-request-media:{op_label}:{media}",
                                f"{op_label}: request media type `{media}` removed",
                            )
                        )
                    else:
                        compare_schemas(
                            base_doc,
                            head_doc,
                            (b_media or {}).get("schema") or {},
                            (h_content[media] or {}).get("schema") or {},
                            f"{op_label}:request",
                            "request",
                            findings,
                        )

            # Responses check (ALL status codes: 2xx AND non-2xx/error contracts)
            b_resps = b_op.get("responses") if isinstance(b_op.get("responses"), dict) else {}
            h_resps = h_op.get("responses") if isinstance(h_op.get("responses"), dict) else {}
            for status_code, b_resp in sorted(b_resps.items()):
                sc = str(status_code)
                if sc not in h_resps:
                    findings.append(
                        (
                            f"removed-response-status:{op_label}:{sc}",
                            f"{op_label}: response status {sc} removed",
                        )
                    )
                    continue
                b_content = (
                    (b_resp or {}).get("content")
                    if isinstance((b_resp or {}).get("content"), dict)
                    else {}
                )
                h_content = (
                    (h_resps[sc] or {}).get("content")
                    if isinstance((h_resps[sc] or {}).get("content"), dict)
                    else {}
                )
                for media, b_media in sorted(b_content.items()):
                    if media not in h_content:
                        findings.append(
                            (
                                f"removed-response-media:{op_label}:{sc}:{media}",
                                f"{op_label}: response {sc} media type `{media}` removed",
                            )
                        )
                        continue
                    compare_schemas(
                        base_doc,
                        head_doc,
                        (b_media or {}).get("schema") or {},
                        (h_content[media] or {}).get("schema") or {},
                        f"{op_label}:response:{sc}",
                        "response",
                        findings,
                    )

    return findings


# ── Base-spec deprecation proof & 12-month sunset waiver validation ───────────


def _is_marked_deprecated(node: Any) -> bool:
    if not isinstance(node, dict):
        return False
    return bool(node.get("deprecated") is True or isinstance(node.get("x-deprecated-on"), str))


def _walk_schema_deprecated(
    doc: dict[str, Any], schema: Any, segments: list[str]
) -> bool:
    """Walk strictly down `segments` from an operation's schema; never search unrelated components."""
    cur = resolve_schema(doc, schema)
    if _is_marked_deprecated(cur):
        return True
    if not segments:
        return False

    seg = segments[0]
    rest = segments[1:]

    # Handle array suffix `foo[]` or bare `[]`
    is_array_step = seg.endswith("[]")
    clean_seg = seg[:-2] if is_array_step else seg

    # Handle union variant selector `|VariantName`
    if "|" in clean_seg:
        head_seg, variant = clean_seg.split("|", 1)
        next_segs = ([head_seg] if head_seg else []) + [f"|{variant}"] + rest
        if head_seg:
            return _walk_schema_deprecated(doc, cur, next_segs)
        branches = union_branches(doc, cur) or []
        for idx, branch in enumerate(branches):
            if branch_key(doc, branch, idx) == variant:
                if _is_marked_deprecated(branch):
                    return True
                return _walk_schema_deprecated(doc, branch, rest)
        return False

    # Unwrap single-branch nullable anyOf/oneOf
    branches = union_branches(doc, cur)
    if branches is not None:
        non_null = [b for b in branches if resolve_schema(doc, b).get("type") != "null"]
        if len(non_null) == 1:
            cur = resolve_schema(doc, non_null[0])
            if _is_marked_deprecated(cur):
                return True

    if clean_seg == "":
        if is_array_step and isinstance(cur.get("items"), dict):
            return _walk_schema_deprecated(doc, cur["items"], rest)
        return False

    if clean_seg == "*":
        addl = cur.get("additionalProperties")
        if isinstance(addl, dict):
            return _walk_schema_deprecated(doc, addl, rest)
        return False

    props = cur.get("properties")
    if isinstance(props, dict) and clean_seg in props:
        raw_prop = props[clean_seg]
        if _is_marked_deprecated(raw_prop):
            return True
        resolved_prop = resolve_schema(doc, raw_prop)
        if _is_marked_deprecated(resolved_prop):
            return True
        if is_array_step:
            if isinstance(resolved_prop.get("items"), dict):
                return _walk_schema_deprecated(doc, resolved_prop["items"], rest)
            return False
        return _walk_schema_deprecated(doc, resolved_prop, rest)
    return False


def is_deprecated_in_base(base_doc: dict[str, Any], change_key: str) -> bool:
    """Verify the exact target of `change_key` was already marked deprecated in `--base`."""
    paths = base_doc.get("paths") if isinstance(base_doc.get("paths"), dict) else {}
    kind, _, rest = change_key.partition(":")

    if kind == "removed-path":
        item = paths.get(rest)
        if not isinstance(item, dict):
            return False
        if _is_marked_deprecated(item):
            return True
        ops = [item[m] for m in HTTP_METHODS if isinstance(item.get(m), dict)]
        return bool(ops) and all(_is_marked_deprecated(op) for op in ops)

    # Extract `<METHOD> <path>` prefix for operation-scoped keys.
    op_match = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^:]+)", rest)
    if not op_match:
        return False
    method = op_match.group(1).lower()
    path_key = op_match.group(2)
    item = paths.get(path_key)
    if not isinstance(item, dict):
        return False
    op = item.get(method)
    if not isinstance(op, dict):
        return False
    if _is_marked_deprecated(item) or _is_marked_deprecated(op):
        return True

    suffix = rest[op_match.end() :]
    if not suffix:
        return False

    # Parameter deprecation: `:param:<name>`
    param_match = re.match(r"^:param:([^.:]+)(?:\.(.*))?$", suffix)
    if param_match:
        pname = param_match.group(1)
        subpath = [s for s in (param_match.group(2) or "").split(".") if s]
        for p in op.get("parameters") or []:
            if isinstance(p, dict) and p.get("name") == pname:
                if _is_marked_deprecated(p):
                    return True
                return _walk_schema_deprecated(base_doc, p.get("schema") or {}, subpath)
        return False

    # Request body schema path: `:request...`
    req_match = re.match(r"^:request(?:\.(.*)|(\[\].*)|(\|.*))?$", suffix)
    if req_match:
        tail = req_match.group(1) or req_match.group(2) or req_match.group(3) or ""
        segments = [s for s in tail.split(".") if s]
        rb = op.get("requestBody")
        if isinstance(rb, dict):
            if _is_marked_deprecated(rb):
                return True
            content = rb.get("content") if isinstance(rb.get("content"), dict) else {}
            for media in content.values():
                if isinstance(media, dict) and _walk_schema_deprecated(
                    base_doc, media.get("schema") or {}, segments
                ):
                    return True
        return False

    # Response schema path: `:response:<status>...`
    resp_match = re.match(r"^:response:([^.:|\[]+)(?:\.(.*)|(\[\].*)|(\|.*))?$", suffix)
    if resp_match:
        status = resp_match.group(1)
        tail = resp_match.group(2) or resp_match.group(3) or resp_match.group(4) or ""
        segments = [s for s in tail.split(".") if s]
        resps = op.get("responses") if isinstance(op.get("responses"), dict) else {}
        resp = resps.get(status)
        if isinstance(resp, dict):
            if _is_marked_deprecated(resp):
                return True
            content = resp.get("content") if isinstance(resp.get("content"), dict) else {}
            for media in content.values():
                if isinstance(media, dict) and _walk_schema_deprecated(
                    base_doc, media.get("schema") or {}, segments
                ):
                    return True
        return False

    return False


def load_valid_waivers(
    waiver_path: pathlib.Path | None,
    base_doc: dict[str, Any],
    today: dt.date,
) -> tuple[set[str], list[str]]:
    if waiver_path is None or not waiver_path.exists():
        return set(), []
    data = json.loads(waiver_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("waivers"), list):
        return set(), [f"{waiver_path}: invalid waivers JSON structure"]

    valid_keys: set[str] = set()
    errors: list[str] = []
    for idx, entry in enumerate(data["waivers"]):
        entry_errors: list[str] = []
        if not isinstance(entry, dict):
            errors.append(f"{waiver_path}: waiver[{idx}] must be an object")
            continue
        wid = entry.get("id", f"waiver[{idx}]")
        for req_field in ("id", "change_key", "deprecated_on", "sunset_after", "issue", "reason"):
            if not isinstance(entry.get(req_field), str) or not entry[req_field].strip():
                entry_errors.append(
                    f"{waiver_path}: waiver `{wid}` missing required string field `{req_field}`"
                )
        if entry_errors:
            errors.extend(entry_errors)
            continue
        try:
            dep_date = dt.date.fromisoformat(entry["deprecated_on"])
            sunset_date = dt.date.fromisoformat(entry["sunset_after"])
        except ValueError as exc:
            errors.append(f"{waiver_path}: waiver `{wid}` has invalid ISO date: {exc}")
            continue
        window_days = (sunset_date - dep_date).days
        if window_days < MIN_COMPAT_WINDOW_DAYS:
            errors.append(
                f"{waiver_path}: waiver `{wid}` violates 12-month compatibility window "
                f"(sunset_after - deprecated_on = {window_days} days < {MIN_COMPAT_WINDOW_DAYS})"
            )
            continue
        if today < sunset_date:
            errors.append(
                f"{waiver_path}: waiver `{wid}` cannot be exercised before sunset_after "
                f"({sunset_date.isoformat()} > today {today.isoformat()})"
            )
            continue
        if not is_deprecated_in_base(base_doc, entry["change_key"]):
            errors.append(
                f"{waiver_path}: waiver `{wid}` target `{entry['change_key']}` was not marked "
                "`deprecated: true` in the base OpenAPI spec (cannot backdate deprecation in the breaking PR)"
            )
            continue
        valid_keys.add(entry["change_key"])
    return valid_keys, errors


def _is_oasdiff_err_level(level: Any) -> bool:
    """oasdiff v1.41+ emits numeric level 3 for ERR (INFO=1, WARN=2, ERR=3); older builds emit 'ERR'."""
    if isinstance(level, bool):
        return False
    if isinstance(level, int):
        return level >= 3
    s = str(level).strip().upper()
    return s in ("3", "ERR", "ERROR")


def parse_oasdiff_errors(
    oasdiff_json_path: pathlib.Path | None,
    valid_waivers: set[str],
) -> list[tuple[str, str]]:
    """Return unwaived ERR findings from `oasdiff breaking --format json` output."""
    if oasdiff_json_path is None or not oasdiff_json_path.exists():
        return []
    raw = oasdiff_json_path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        items = json.loads(raw)
    except json.JSONDecodeError as exc:
        return [("oasdiff-parse-error", f"failed to parse oasdiff JSON output: {exc}")]
    if not isinstance(items, list):
        return []

    # Only whole-path (`removed-path`) and whole-operation (`removed-operation`) waivers
    # match broadly at path/operation scope. Narrower waivers (e.g. a single removed status
    # or property) MUST NOT suppress unrelated oasdiff ERR findings on the same operation.
    waived_paths: set[str] = set()
    waived_removed_ops: set[tuple[str, str]] = set()
    for wkey in valid_waivers:
        kind, _, rest = wkey.partition(":")
        if kind == "removed-path":
            waived_paths.add(rest)
        elif kind == "removed-operation":
            m = re.match(r"^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) ([^:]+)$", rest)
            if m:
                waived_removed_ops.add((m.group(1), m.group(2)))

    unwaived: list[tuple[str, str]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if not _is_oasdiff_err_level(item.get("level")):
            continue
        oid = str(item.get("id", "oasdiff-err"))
        op = str(item.get("operation", "")).upper()
        path = str(item.get("path", ""))
        text = str(item.get("text", oid))
        fp = f"oasdiff:{oid}:{op} {path}".strip()
        if (
            fp in valid_waivers
            or (path and path in waived_paths)
            or (op and path and (op, path) in waived_removed_ops)
        ):
            continue
        unwaived.append((fp, f"oasdiff ERR ({oid}) on {op} {path}: {text}"))
    return unwaived


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=pathlib.Path, required=True, help="Baseline OpenAPI 3.1 YAML")
    parser.add_argument("--head", type=pathlib.Path, required=True, help="Candidate OpenAPI 3.1 YAML")
    parser.add_argument("--waivers", type=pathlib.Path, default=None, help="approved-breaking.json path")
    parser.add_argument(
        "--oasdiff-json",
        type=pathlib.Path,
        default=None,
        help="Optional JSON output file from `oasdiff breaking --format json`",
    )
    parser.add_argument("--today", type=str, default=None, help="Override UTC date YYYY-MM-DD (tests)")
    args = parser.parse_args()

    today = (
        dt.date.fromisoformat(args.today)
        if args.today
        else dt.datetime.now(dt.timezone.utc).date()
    )

    base_doc = load_openapi(args.base)
    head_doc = load_openapi(args.head)

    head_ver = str(head_doc.get("openapi", ""))
    if not head_ver.startswith("3.1."):
        print(
            f"EDGE-CONTRACT-BREAKING-FAIL: head spec must be OpenAPI 3.1.x, got {head_ver!r}",
            file=sys.stderr,
        )
        return 1

    valid_waivers, waiver_errors = load_valid_waivers(args.waivers, base_doc, today)
    if waiver_errors:
        print("EDGE-CONTRACT-BREAKING-FAIL: invalid compatibility waiver(s):", file=sys.stderr)
        for err in waiver_errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    findings = diff_openapi(base_doc, head_doc)
    unwaived = [(k, msg) for k, msg in findings if k not in valid_waivers]
    waived = [(k, msg) for k, msg in findings if k in valid_waivers]
    oasdiff_unwaived = parse_oasdiff_errors(args.oasdiff_json, valid_waivers)
    unwaived.extend(oasdiff_unwaived)

    if unwaived:
        print(
            f"EDGE-CONTRACT-BREAKING-FAIL: {len(unwaived)} unwaived breaking change(s) detected "
            "(12-month compatibility window enforced):",
            file=sys.stderr,
        )
        for key, msg in unwaived:
            print(f"  - [{key}] {msg}", file=sys.stderr)
        return 1

    print(
        f"edge-contract-breaking: PASS (OpenAPI {head_ver}, "
        f"{len(head_doc.get('paths') or {})} paths, {len(waived)} waived breaking change(s))"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
