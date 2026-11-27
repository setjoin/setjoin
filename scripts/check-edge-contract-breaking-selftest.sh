#!/usr/bin/env bash
# Self-test for scripts/check-edge-contract-breaking.sh (#561).
# Proves breaking mutants (removed path, removed response property, newly
# required request property, incompatible type, removed 401 error response,
# incompatible additionalProperties value type, narrowed unrestricted request
# additionalProperties, short waiver, un-deprecated waiver, unrelated-component
# deprecated property spoofing, numeric oasdiff level: 3 ERR, narrow waiver not
# silencing unrelated same-op oasdiff ERR, and invalid EDGE_CONTRACT_BASE_REF)
# all fail, while additive evolutions + properly pre-deprecated >=12m waiver pass.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD="$ROOT/scripts/check-edge-contract-breaking.sh"
PY="$ROOT/scripts/check-edge-contract-breaking.py"
BASE="$ROOT/contracts/edge/openapi/edge.v1.yaml"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/edge-breaking-selftest.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

python3 - "$BASE" "$tmp" "$PY" <<'PY'
import copy, importlib.util, json, pathlib, sys

base_path = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
py_path = pathlib.Path(sys.argv[3])

spec = importlib.util.spec_from_file_location("breaking", str(py_path))
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

base = mod.load_openapi(base_path)

def dump(name, doc):
    (out_dir / f"{name}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")

# Base variant with /api/user/quota pre-marked deprecated: true (for valid waiver test)
base_dep = copy.deepcopy(base)
base_dep["paths"]["/api/user/quota"]["get"]["deprecated"] = True
dump("base_deprecated", base_dep)

# Base variant with an UNRELATED component having a deprecated `usedBytes` property
# (must NOT authorize waiving MailboxQuota.usedBytes!)
base_unrelated_dep = copy.deepcopy(base)
base_unrelated_dep["components"]["schemas"]["Common.CursorPageMeta"]["properties"]["usedBytes"] = {
    "type": "integer",
    "deprecated": True,
}
dump("base_unrelated_deprecated", base_unrelated_dep)

# Base variant with ONLY the 401 response of GET /api/user/quota deprecated
base_401_dep = copy.deepcopy(base)
base_401_dep["paths"]["/api/user/quota"]["get"]["responses"]["401"]["deprecated"] = True
dump("base_401_deprecated", base_401_dep)

# Negative 1: removed path
m1 = copy.deepcopy(base)
del m1["paths"]["/api/user/quota"]
dump("neg_removed_path", m1)

# Negative 2: removed response property
m2 = copy.deepcopy(base)
del m2["components"]["schemas"]["Offline.OfflineSizeBucket"]["properties"]["bodyBytes"]
m2["components"]["schemas"]["Offline.OfflineSizeBucket"]["required"].remove("bodyBytes")
dump("neg_removed_resp_field", m2)

# Negative 3: newly required request property
m3 = copy.deepcopy(base)
m3["components"]["schemas"]["Rules.RuleInput"]["properties"]["priorityTag"] = {"type": "string"}
m3["components"]["schemas"]["Rules.RuleInput"]["required"].append("priorityTag")
dump("neg_new_req_field", m3)

# Negative 4: incompatible type change
m4 = copy.deepcopy(base)
m4["components"]["schemas"]["Offline.MailboxQuota"]["properties"]["usedBytes"] = {"type": "string"}
dump("neg_incompatible_type", m4)

# Negative 5: removed 401 error response
m5 = copy.deepcopy(base)
del m5["paths"]["/api/user/quota"]["get"]["responses"]["401"]
dump("neg_removed_401", m5)

# Negative 6: incompatible map additionalProperties value type (RuleAction.params)
m6 = copy.deepcopy(base)
m6["components"]["schemas"]["Rules.RuleAction"]["properties"]["params"]["additionalProperties"] = {
    "type": "integer"
}
dump("neg_addl_props_type", m6)

# Negative 7: narrowing unrestricted request additionalProperties ({} -> { type: "string" })
m7 = copy.deepcopy(base)
m7["components"]["schemas"]["Offline.ViewPreferences"]["additionalProperties"] = {"type": "string"}
dump("neg_narrowed_req_addl_props", m7)

# Negative 8: removed usedBytes from MailboxQuota (for unrelated-component deprecation spoof test)
m8 = copy.deepcopy(base)
del m8["components"]["schemas"]["Offline.MailboxQuota"]["properties"]["usedBytes"]
m8["components"]["schemas"]["Offline.MailboxQuota"]["required"].remove("usedBytes")
dump("neg_removed_used_bytes", m8)

# Positive 1: new optional response field
p1 = copy.deepcopy(base)
p1["components"]["schemas"]["Rules.UserRule"]["properties"]["displayHint"] = {"type": "string"}
dump("pos_optional_resp_field", p1)

# Positive 2: new endpoint
p2 = copy.deepcopy(base)
p2["paths"]["/api/settings/rules/summary"] = {
    "get": {
        "operationId": "RulesOperations_summary",
        "responses": {
            "200": {
                "description": "OK",
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "properties": {"count": {"type": "integer"}}}
                    }
                },
            }
        },
    }
}
dump("pos_new_endpoint", p2)

# Waiver fixtures
(out_dir / "waiver_short.json").write_text(
    json.dumps(
        {
            "version": 1,
            "waivers": [
                {
                    "id": "EDGE-BREAK-SHORT",
                    "change_key": "removed-path:/api/user/quota",
                    "deprecated_on": "2026-01-01",
                    "sunset_after": "2026-06-01",
                    "issue": "#561",
                    "reason": "Too short (<12 months)",
                }
            ],
        }
    ),
    encoding="utf-8",
)

(out_dir / "waiver_valid.json").write_text(
    json.dumps(
        {
            "version": 1,
            "waivers": [
                {
                    "id": "EDGE-BREAK-VALID",
                    "change_key": "removed-path:/api/user/quota",
                    "deprecated_on": "2025-01-01",
                    "sunset_after": "2026-01-02",
                    "issue": "#561",
                    "reason": "Completed 12-month compatibility window",
                }
            ],
        }
    ),
    encoding="utf-8",
)

(out_dir / "waiver_spoof_used_bytes.json").write_text(
    json.dumps(
        {
            "version": 1,
            "waivers": [
                {
                    "id": "EDGE-BREAK-SPOOF",
                    "change_key": "removed-response-property:GET /api/user/quota:response:200.usedBytes",
                    "deprecated_on": "2025-01-01",
                    "sunset_after": "2026-01-02",
                    "issue": "#561",
                    "reason": "Attempt to spoof deprecation via unrelated component",
                }
            ],
        }
    ),
    encoding="utf-8",
)

(out_dir / "waiver_narrow_401.json").write_text(
    json.dumps(
        {
            "version": 1,
            "waivers": [
                {
                    "id": "EDGE-BREAK-401",
                    "change_key": "removed-response-status:GET /api/user/quota:401",
                    "deprecated_on": "2025-01-01",
                    "sunset_after": "2026-01-02",
                    "issue": "#561",
                    "reason": "Narrow single-status waiver",
                }
            ],
        }
    ),
    encoding="utf-8",
)

# Simulated oasdiff v1.41.0 JSON emitting numeric level: 3 (ERR) on a different endpoint
(out_dir / "oasdiff_unwaived_num3.json").write_text(
    json.dumps(
        [
            {
                "id": "endpoint-removed",
                "level": 3,
                "operation": "GET",
                "path": "/api/offline/size-estimate",
                "text": "endpoint removed",
            }
        ]
    ),
    encoding="utf-8",
)

# Simulated oasdiff v1.41.0 JSON emitting numeric level: 3 (ERR) on the SAME operation as a narrow 401 waiver
(out_dir / "oasdiff_same_op_unrelated_err.json").write_text(
    json.dumps(
        [
            {
                "id": "response-property-removed",
                "level": 3,
                "operation": "GET",
                "path": "/api/user/quota",
                "text": "response property quotaBytes removed",
            }
        ]
    ),
    encoding="utf-8",
)
PY

expect_fail() {
  local label="$1"
  shift
  if bash "$GUARD" "$@" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $label was NOT rejected" >&2
    exit 1
  fi
}

expect_pass() {
  local label="$1"
  shift
  if ! bash "$GUARD" "$@" >/dev/null 2>&1; then
    echo "SELF-TEST FAIL: $label was unexpectedly rejected" >&2
    bash "$GUARD" "$@" >&2 || true
    exit 1
  fi
}

expect_fail "negative 1: removed path" --base "$BASE" --head "$tmp/neg_removed_path.json"
expect_fail "negative 2: removed response property" --base "$BASE" --head "$tmp/neg_removed_resp_field.json"
expect_fail "negative 3: newly required request property" --base "$BASE" --head "$tmp/neg_new_req_field.json"
expect_fail "negative 4: incompatible type change" --base "$BASE" --head "$tmp/neg_incompatible_type.json"
expect_fail "negative 5: removed 401 error response" --base "$BASE" --head "$tmp/neg_removed_401.json"
expect_fail "negative 6: map additionalProperties type change" --base "$BASE" --head "$tmp/neg_addl_props_type.json"
expect_fail "negative 7: narrowed unrestricted request additionalProperties" --base "$BASE" --head "$tmp/neg_narrowed_req_addl_props.json"
expect_fail "negative 8: waiver < 12 months" --base "$tmp/base_deprecated.json" --head "$tmp/neg_removed_path.json" --waivers "$tmp/waiver_short.json" --today 2026-11-27
expect_fail "negative 9: waiver without prior base deprecation" --base "$BASE" --head "$tmp/neg_removed_path.json" --waivers "$tmp/waiver_valid.json" --today 2026-11-27
expect_fail "negative 10: unrelated component deprecated property spoofing" --base "$tmp/base_unrelated_deprecated.json" --head "$tmp/neg_removed_used_bytes.json" --waivers "$tmp/waiver_spoof_used_bytes.json" --today 2026-11-27

if EDGE_CONTRACT_BASE_REF="nonexistent-ref-selftest-561" bash "$GUARD" >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: invalid EDGE_CONTRACT_BASE_REF did not fail closed" >&2
  exit 1
fi

if python3 "$PY" --base "$tmp/base_deprecated.json" --head "$tmp/neg_removed_path.json" --waivers "$tmp/waiver_valid.json" --oasdiff-json "$tmp/oasdiff_unwaived_num3.json" --today 2026-11-27 >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: unwaived oasdiff numeric level=3 ERR was not caught" >&2
  exit 1
fi

if python3 "$PY" --base "$tmp/base_401_deprecated.json" --head "$tmp/neg_removed_401.json" --waivers "$tmp/waiver_narrow_401.json" --oasdiff-json "$tmp/oasdiff_same_op_unrelated_err.json" --today 2026-11-27 >/dev/null 2>&1; then
  echo "SELF-TEST FAIL: narrow 401 waiver silenced unrelated same-operation oasdiff ERR" >&2
  exit 1
fi

expect_pass "positive 1: new optional response field" --base "$BASE" --head "$tmp/pos_optional_resp_field.json"
expect_pass "positive 2: new endpoint" --base "$BASE" --head "$tmp/pos_new_endpoint.json"
expect_pass "positive 3: valid pre-deprecated >=12-month sunset waiver" --base "$tmp/base_deprecated.json" --head "$tmp/neg_removed_path.json" --waivers "$tmp/waiver_valid.json" --today 2026-11-27

echo "check-edge-contract-breaking self-test: PASS (all breaking mutants, narrowed request map, numeric oasdiff level=3, narrow waiver scoping, and unrelated-component deprecation spoof rejected; additive evolutions + valid waiver passed)"
