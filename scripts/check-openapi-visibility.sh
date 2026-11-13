#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-openapi-visibility.sh — the doc-visibility ↔ auth-boundary tripwire.
#
# Each documented OpenAPI path carries `x-visibility: admin|public`. That tag is
# the SECURITY boundary the served spec splits on: the anonymous endpoints
# (HandleYAML/HandleJSON/HandleDocs) drop every `admin` path, while the full spec
# (/api/openapi.full.yaml) is admin-gated. A hand-set tag could DRIFT from the
# route's real auth wrapper — silently re-exposing an admin path in the public
# subset, or hiding a public one. This guard forbids that drift: for every
# documented path it consumes the runtime-emitted production wrapper chain and
# fails if that disagrees with the path's stamped x-visibility.
#
# DERIVATION (single source = the emitted production registrar chain):
#   A route whose wrapper chain contains an ADMIN middleware => visibility ADMIN.
#   Two admin families:
#     (1) ROLE wrappers — RequireAdmin or a RequireRole over admin/auditor/
#         user_admin/read_only (requireAdmin / requireSuperAdmin / requireReadOnly
#         / requireAuditor / requireAdminOrAuditor).
#     (2) PERMISSION wrappers — the RBAC cut-over moved admin routes onto
#         `requireAuth(require<Perm>(...))`, where require<Perm> is a
#         RequirePermAudited / RequireAnyPermAudited middleware (requireUsersCreate,
#         requireMailPerm, requireSystemConfig, requireAuthPerm, …). The PLAIN
#         requireAuth wrapper is PUBLIC (authenticated-but-not-admin); the inner
#         perm wrapper is what makes the route admin. This set is DERIVED from
#         gateway registrar (not a second visibility list)
#         — that drift is exactly what blinded this guard to the cut-over's 8
#         perm-gated admin routes.
#   Anonymous, plain requireAuth, or the auth-proxy (login/refresh/logout/me) => PUBLIC.
#
# Drive, Chat, Meet, and SCIM child operations come from production-used private
# registrars. The merger applies each gateway mount's outer chain; SCIM records
# its provisioning-token/content-type boundary directly.
#
# COMPONENT GRANULARITY. The served public subset also prunes COMPONENTS: the
# anonymous document keeps only the transitive $ref closure over the public
# operations (admin and public operations share schemas — Problem, the SCIM and
# Drive families — so shared components stay intact; the admin-only residue —
# identity-source bindDN/baseDN surfaces, MailboxPurgeScheduleCommand with its
# approverUserId, the upgrade/updater chain, the webhook secret note — goes),
# and the top-level tag taxonomy splits on the same reachability rule. This
# guard therefore additionally enforces reference integrity on the SOURCE spec,
# so component-level drift is detectable as reference integrity and not just as
# path absence:
#   (1) every "#/components/..." $ref must resolve to a defined component
#       (no dangling references anywhere in the document);
#   (2) every defined component must be reachable from some documented path
#       through a $ref chain or a security requirement — an unreachable
#       component is exactly what an injected admin-only surface looks like
#       (it would either be dead weight in the full spec or evidence the
#       served split no longer derives from real references).
# Failures name the offending component.
#
# Usage:
#   scripts/check-openapi-visibility.sh              # the guard (exit 1 on drift)
#   scripts/check-openapi-visibility.sh --self-test  # prove the guard FIRES
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
export LC_ALL=C
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SPEC="$ROOT/mailserver/api/openapi.yaml"
INVENTORY="${ROUTE_INVENTORY_FILE:-$ROOT/test-results/mailserver/route-inventory.json}"
INVENTORY_READER="$ROOT/scripts/route-inventory-json.mjs"

# ── extract "<path> <x-visibility>" for every documented path object ──────────
# A path object is a top-level "  /foo:" line under paths:; its x-visibility is the
# "    x-visibility: <v>" line that follows before the next path object. A path
# with no x-visibility stamp emits "<path> MISSING" (a hard failure).
spec_path_visibility() {
  if [ ! -f "$SPEC" ] || [ ! -r "$SPEC" ]; then
    echo "  ✗ OpenAPI spec is missing or unreadable: $SPEC" >&2
    return 1
  fi
  awk '
    /^paths:/ {inpaths=1; next}
    inpaths && /^[^ ]/ {inpaths=0}                  # left the paths: block
    inpaths && /^  \/[^ ]*:[[:space:]]*$/ {
      if (curpath != "") print curpath, (vis=="" ? "MISSING" : vis)
      p=$1; sub(/:$/,"",p); curpath=p; vis=""; next
    }
    inpaths && /^    x-visibility:/ {
      vis=$2
    }
    END { if (curpath != "") print curpath, (vis=="" ? "MISSING" : vis) }
  ' "$SPEC"
}

# ── derive admin|public from the emitted registration inventory ──────────────
derive_visibility() {  # $1 = path (e.g. /admin/users/{id})
  local normalized="$1"
  normalized="$(sed -E 's/\{[^}]+\}/{}/g' <<<"$normalized")"
  if [[ ! -r "$INVENTORY" ]]; then
    echo "NOROUTE"
    return
  fi
  local derived
  derived="$(awk -F '\t' -v path="$normalized" '$1 == path { print $2; exit }' <<<"$inventory_rows")"
  if [[ -z "$derived" ]]; then
    echo "NOROUTE"
    return
  fi
  echo "$derived"
}

# ── reference integrity: dangling $ref + unreachable (injected) components ────
# Pass 1 (awk) emits two record kinds from the spec's plain structure:
#   D<TAB><category>/<name><TAB><space-separated component targets>
#       one per component definition (indent-4 key inside a components category),
#       with every "#/components/<cat>/<name>" $ref found in its subtree plus
#       every security-scheme name its subtree's security requirements name;
#   S<TAB><target>
#       closure SEEDS: $ref targets found anywhere OUTSIDE components (the
#       paths block) and security-scheme names named by `security` requirement
#       blocks (root + per-operation; schemes are referenced by name, never by
#       $ref).
# Pass 2 (awk) runs the reachable set to fixed point over the D edges — the
# same transitive closure the Go split derives at serve time — then reports:
#   X<TAB><target>  a referenced component that is never defined (dangling);
#   U<TAB><cat/name> a defined component reachable from NO path (injected).
spec_reference_integrity() {  # echoes failures to stderr; returns 1 on any
  local rc=0 raw raw2 out
  raw="$(mktemp "${TMPDIR:-/tmp}/openapi-vis.XXXXXX")" || return 1
  raw2="$(mktemp "${TMPDIR:-/tmp}/openapi-vis.XXXXXX")" || { rm -f "$raw"; return 1; }
  out="$(mktemp "${TMPDIR:-/tmp}/openapi-vis.XXXXXX")" || { rm -f "$raw" "$raw2"; return 1; }

  awk '
    function flushdef() {
      if (def != "") print "D\t" cat "/" def "\t" targets
      def = ""; targets = ""
    }
    function addref(t) {
      if (comp && def != "") targets = targets (targets == "" ? "" : " ") t
      else print "S\t" t
    }
    function extractrefs(line,   rest, t) {
      rest = line
      while (match(rest, /#\/components\/[A-Za-z0-9_.~-]+\/[A-Za-z0-9_.~-]+/)) {
        t = substr(rest, RSTART, RLENGTH)
        sub(/^#\/components\//, "", t)
        addref(t)
        rest = substr(rest, RSTART + RLENGTH)
      }
    }
    BEGIN { comp = 0; cat = ""; def = ""; insec = 0; secindent = -1 }
    {
      line = $0
      indent = 0
      while (substr(line, indent + 1, 1) == " ") indent++
      if (insec && indent <= secindent) insec = 0
      if (line ~ /^[ ]*security:[ ]*$/) {
        flushdef(); insec = 1; secindent = indent
        next
      }
      if (line ~ /^[^ #]/) {                    # top-level key: paths:, components:, ...
        flushdef()
        comp = (line ~ /^components:/)
        cat = ""
        extractrefs(line)
        next
      }
      if (comp && line ~ /^  [A-Za-z]/) {       # components category: schemas:, responses:, ...
        flushdef()
        cat = line; sub(/:.*/, "", cat); sub(/^ +/, "", cat)
        extractrefs(line)
        next
      }
      if (comp && line ~ /^    [^ ]/) {         # component definition (indent-4 key)
        flushdef()
        def = line; sub(/^[ ]+/, "", def); sub(/:.*/, "", def)
        extractrefs(line)
        next
      }
      extractrefs(line)
      if (insec && indent > secindent) {        # security requirement entry: - schemeName: []
        key = line
        sub(/^[ ]+/, "", key)
        sub(/^-[ ]*/, "", key)
        sub(/:.*/, "", key)
        if (key ~ /^[A-Za-z0-9_.-]+$/) print "S\tsecuritySchemes/" key
      }
    }
    END { flushdef() }
  ' "$SPEC" > "$raw"
  printf 'GO\n' > "$raw2"
  if ! awk -F '\t' '
    NR == FNR {
      if ($1 == "D") {
        defn[$2] = 1
        defs[++m] = $2
        n = split($3, parts, " ")
        for (i = 1; i <= n; i++) if (parts[i] != "") edge[$2, parts[i]] = 1
      } else if ($1 == "S") {
        if (!seed[$2]) { seed[$2] = 1; reach[$2] = 1 }
      }
      next
    }
    {
      # Forward propagation to fixed point: a reachable definition makes every
      # component it targets reachable (same direction as the Go split).
      do {
        changed = 0
        for (i = 1; i <= m; i++) {
          d = defs[i]
          if (!reach[d]) continue
          for (e in edge) {
            if (substr(e, 1, length(d) + 1) == d SUBSEP) {
              t = substr(e, length(d) + 2)
              if (!reach[t]) { reach[t] = 1; changed = 1 }
            }
          }
        }
      } while (changed)
    }
    END {
      for (i = 1; i <= m; i++) if (!reach[defs[i]]) print "U\t" defs[i]
      for (e in edge) {
        idx = index(e, SUBSEP)
        t = substr(e, idx + 1)
        if (!(t in defn)) print "X\t" t
      }
      for (s in seed) if (!(s in defn)) print "X\t" s
    }
  ' "$raw" "$raw2" | sort > "$out"
  then
    rm -f "$raw" "$raw2" "$out"
    echo "  ✗ cannot compute the component reference closure." >&2
    return 1
  fi
  rm -f "$raw" "$raw2"
  while IFS= read -r line; do
    case "$line" in
      X*)
        echo "  ✗ dangling \$ref: ${line#X?} is referenced but never defined — broken reference integrity." >&2
        rc=1
        ;;
      U*)
        echo "  ✗ unreachable component: ${line#U?} is defined but reachable from NO path via \$ref or security requirement — an injected admin-only surface? Remove it or reference it from a documented path." >&2
        rc=1
        ;;
    esac
  done < "$out"
  rm -f "$out"
  return $rc
}

run_guard() {  # echoes failures to stderr; returns 1 on any
  local rc=0 path declared derived rows inventory_rows
  if [[ ! -r "$INVENTORY" ]]; then
    echo "E_ROUTE_INVENTORY_MISSING: $INVENTORY" >&2
    echo "  fix: bash scripts/verify-architecture-r2.sh route" >&2
    return 1
  fi
  if ! inventory_rows="$(node "$INVENTORY_READER" visibility "$INVENTORY")"; then
    return 1
  fi
  if ! rows="$(spec_path_visibility)"; then
    echo "  ✗ cannot inspect OpenAPI visibility: spec extraction failed." >&2
    return 1
  fi
  if [ -z "$rows" ]; then
    echo "  ✗ OpenAPI visibility extraction returned zero documented paths." >&2
    return 1
  fi
  while read -r path declared; do
    [ -n "$path" ] || continue
    if [ "$declared" = "MISSING" ]; then
      echo "  ✗ documented path has NO x-visibility stamp: $path" >&2
      rc=1; continue
    fi
    if [ "$declared" != "admin" ] && [ "$declared" != "public" ]; then
      echo "  ✗ documented path has invalid x-visibility ($declared), want admin|public: $path" >&2
      rc=1; continue
    fi
    derived="$(derive_visibility "$path")"
    if [ "$derived" = "NOROUTE" ]; then
      echo "  ✗ cannot derive visibility for $path: no matching emitted registration." >&2
      rc=1; continue
    fi
    if [ "$declared" != "$derived" ]; then
      echo "  ✗ x-visibility DRIFT: $path is stamped '$declared' but its emitted auth wrapper derives '$derived'." >&2
      echo "     → fix the x-visibility in mailserver/api/openapi.yaml to match the enforced auth wrapper." >&2
      rc=1
    fi
  done <<< "$rows"
  if ! spec_reference_integrity; then
    rc=1
  fi
  return $rc
}

case "${1:-}" in
  --self-test)
    # Prove the guard FIRES on planted drift — and that every assertion here is
    # load-bearing. The real spec is never mutated: each fixture is an
    # INDEPENDENT, non-empty derivative of the REAL spec
    # ($ROOT/mailserver/api/openapi.yaml) written to its own file (never a
    # previous fixture, never the empty fail-closed fixture), and the guard is
    # aimed at it only via the SPEC global. Component-level assertions
    # additionally require the diagnostic to NAME the injected content, so a
    # vacuous pass through unrelated zero-path rejection cannot satisfy them,
    # and a mutation check proves that disabling the component check makes the
    # component tests FAIL.
    echo "==> openapi-visibility guard self-test (must detect a planted x-visibility mismatch)"
    real_spec="$ROOT/mailserver/api/openapi.yaml"
    SPEC="$real_spec"
    tmpdir="$(mktemp -d)"; trap 'rm -rf "$tmpdir"' EXIT
    guard_log="$tmpdir/guard.log"
    # Flip the FIRST `x-visibility: admin` to `public` — a deliberate drift: an
    # admin route now lying that it is public (the exact re-exposure this guards).
    flip="$tmpdir/flip-visibility.yaml"
    awk 'BEGIN{done=0} !done && /^    x-visibility: admin/ {sub(/admin/,"public"); done=1} {print}' "$real_spec" > "$flip"
    if ! grep -q 'x-visibility: public' "$flip"; then
      echo "  ✗ SELF-TEST SETUP FAILED: no 'x-visibility: admin' path to flip in the spec." >&2
      exit 1
    fi
    SPEC="$flip"
    if run_guard >"$guard_log" 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard did NOT catch a planted x-visibility mismatch." >&2
      exit 1
    fi
    echo "  ✓ guard fires on an x-visibility ↔ auth-wrapper mismatch."
    SPEC="$tmpdir/missing.yaml"
    if run_guard >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted a missing spec." >&2
      exit 1
    fi
    echo "  ✓ guard fails closed on a missing spec."
    mkdir "$tmpdir/not-a-readable-spec"
    SPEC="$tmpdir/not-a-readable-spec"
    if run_guard >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted an unreadable/non-file spec." >&2
      exit 1
    fi
    echo "  ✓ guard fails closed on an unreadable/non-file spec."
    : > "$tmpdir/empty.yaml"
    SPEC="$tmpdir/empty.yaml"
    if run_guard >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted an empty spec." >&2
      exit 1
    fi
    echo "  ✓ guard fails closed when extraction yields zero paths."
    SPEC="$real_spec"   # the empty fixture ends here; every fixture below re-derives from the REAL spec
    # ── component-granular fence ──────────────────────────────────────────────
    # A component injected into the spec but referenced by NO path — exactly
    # what a leaked admin-only schema looks like — must be caught by the
    # reference-integrity check, and the diagnostic must NAME the injected
    # component: the fixture is a non-empty real-spec derivative that still
    # carries the documented paths, so a zero-path bail-out cannot produce
    # this pass.
    echo "==> openapi-visibility guard self-test (must detect an injected admin-only unreachable component)"
    inject_unreachable="$tmpdir/inject-unreachable.yaml"
    awk '{ print } /^  schemas:[[:space:]]*$/ {
      print "    RogueAdminSurface:"
      print "      type: object"
      print "      description: injected admin-only bindDN/baseDN surface (self-test)"
      print "      properties:"
      print "        bindDN: { type: string }"
      print "        baseDN: { type: string }"
    }' "$real_spec" > "$inject_unreachable"
    if [ ! -s "$inject_unreachable" ] || ! grep -q '^paths:' "$inject_unreachable" \
       || ! grep -q '^    RogueAdminSurface:' "$inject_unreachable"; then
      echo "  ✗ SELF-TEST SETUP FAILED: unreachable-component fixture is not a non-empty real-spec derivative carrying the injection." >&2
      exit 1
    fi
    SPEC="$inject_unreachable"
    if run_guard >"$guard_log" 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted an injected admin-only unreachable component." >&2
      exit 1
    fi
    if ! grep -qF 'unreachable component: schemas/RogueAdminSurface' "$guard_log"; then
      echo "  ✗ SELF-TEST FAILED: rejection did not name the injected content (schemas/RogueAdminSurface); it did not come from the component check:" >&2
      sed 's/^/      /' "$guard_log" >&2
      exit 1
    fi
    echo "  ✓ guard fires on an injected admin-only unreachable component and names it."
    # A $ref to a component that does not exist breaks the reference integrity
    # the served public subset's derivation depends on — caught from its OWN
    # independent real-spec fixture, again naming the specific content.
    echo "==> openapi-visibility guard self-test (must detect a dangling \$ref)"
    inject_dangling="$tmpdir/inject-dangling.yaml"
    awk '{ print } /^  schemas:[[:space:]]*$/ {
      print "    RogueDanglingRef:"
      print "      type: object"
      print "      properties:"
      print "        ghost: { $ref: \"#/components/schemas/DoesNotExist\" }"
    }' "$real_spec" > "$inject_dangling"
    if [ ! -s "$inject_dangling" ] || ! grep -q '^paths:' "$inject_dangling" \
       || ! grep -q '^    RogueDanglingRef:' "$inject_dangling"; then
      echo "  ✗ SELF-TEST SETUP FAILED: dangling-ref fixture is not a non-empty real-spec derivative carrying the injection." >&2
      exit 1
    fi
    SPEC="$inject_dangling"
    if run_guard >"$guard_log" 2>&1; then
      echo "  ✗ SELF-TEST FAILED: guard accepted a dangling \$ref." >&2
      exit 1
    fi
    if ! grep -qF 'dangling $ref: schemas/DoesNotExist' "$guard_log"; then
      echo "  ✗ SELF-TEST FAILED: rejection did not name the undefined target (schemas/DoesNotExist); it did not come from the reference-integrity check:" >&2
      sed 's/^/      /' "$guard_log" >&2
      exit 1
    fi
    echo "  ✓ guard fires on a dangling \$ref and names the undefined target."
    # ── mutation check: the component assertions must be load-bearing ─────────
    # Patch a COPY of this script that stubs ONLY spec_reference_integrity to a
    # no-op, then prove (a) the mutated guard ACCEPTS both injected fixtures —
    # their paths are valid, so the rejections above are attributable to the
    # component check alone — and (b) a full self-test run under the mutation
    # FAILS on the injected component. OPENAPI_VIS_SELFTEST_SKIP_MUTATION keeps
    # the mutated copy from re-running this block (its component assertion is
    # expected to fail before reaching it; if a regression ever lets it pass,
    # the mutated run exits 0, which is exactly what the check below catches).
    if [ -z "${OPENAPI_VIS_SELFTEST_SKIP_MUTATION:-}" ]; then
      echo "==> openapi-visibility guard self-test (mutation: disabling the component check must make the tests fail)"
      mutated="$tmpdir/mutated-guard.sh"
      awk -v root="$ROOT" '
        index($0, "ROOT=\"") == 1 { print "ROOT=\"" root "\""; next }
        $0 == "SPEC=\"$ROOT/mailserver/api/openapi.yaml\"" {
          print "SPEC=\"${OPENAPI_VIS_SPEC_OVERRIDE:-" root "/mailserver/api/openapi.yaml}\""
          next
        }
        index($0, "case \"${1:-}\" in") == 1 && !stubbed {
          print "spec_reference_integrity() { return 0; }  # MUTATION: component check disabled"
          stubbed = 1
        }
        { print }
      ' "$0" > "$mutated"
      if ! grep -q '^spec_reference_integrity() { return 0; }' "$mutated" \
         || ! grep -qF "ROOT=\"$ROOT\"" "$mutated" \
         || ! grep -q 'OPENAPI_VIS_SPEC_OVERRIDE' "$mutated"; then
        echo "  ✗ SELF-TEST SETUP FAILED: could not build the component-check-disabled mutation copy of $0." >&2
        exit 1
      fi
      for fixture in "$inject_unreachable" "$inject_dangling"; do
        if ! OPENAPI_VIS_SPEC_OVERRIDE="$fixture" bash "$mutated" >"$guard_log" 2>&1; then
          echo "  ✗ SELF-TEST SETUP FAILED: with the component check disabled the guard still rejects ${fixture##*/} — the component rejections were not attributable to the component check:" >&2
          sed 's/^/      /' "$guard_log" >&2
          exit 1
        fi
      done
      echo "  ✓ with the component check disabled the guard accepts both injected fixtures."
      if OPENAPI_VIS_SELFTEST_SKIP_MUTATION=1 bash "$mutated" --self-test >"$guard_log" 2>&1; then
        echo "  ✗ SELF-TEST FAILED: the self-test still PASSES with the component check disabled — the component assertions are vacuous." >&2
        exit 1
      fi
      if ! grep -qF 'guard accepted an injected admin-only unreachable component' "$guard_log"; then
        echo "  ✗ SELF-TEST SETUP FAILED: the disabled-check self-test run failed for an unexpected reason (wanted: vacuous acceptance of the injected component):" >&2
        sed 's/^/      /' "$guard_log" >&2
        exit 1
      fi
      echo "  ✓ mutation check: disabling the component check makes the self-test FAIL on the injected component."
    fi
    # And the checks must NOT fire on the pristine spec (no false positives):
    # reference integrity holds on the real source document.
    SPEC="$real_spec"
    if ! spec_reference_integrity >/dev/null 2>&1; then
      echo "  ✗ SELF-TEST FAILED: reference integrity does not pass on the pristine spec." >&2
      exit 1
    fi
    echo "  ✓ reference integrity passes on the real spec (no dangling \$ref, no unreachable component)."
    exit 0
    ;;
esac

echo "==> OpenAPI doc-visibility ↔ auth-boundary guard"
if run_guard; then
  n="$(spec_path_visibility | awk 'END {print NR}')"
  echo "    OK — every documented path's x-visibility matches its emitted auth visibility ($n paths);"
  echo "        reference integrity holds (no dangling \$ref, no unreachable component)."
  exit 0
else
  echo "" >&2
  echo "  OpenAPI visibility/reference-integrity drift (see ✗ lines). The served public subset splits on" >&2
  echo "  x-visibility and serves only the transitive \$ref closure of the public operations; an admin" >&2
  echo "  path can leak into the anonymous spec, or an admin-only component survive as a dangling or" >&2
  echo "  unreachable entry. Fix mailserver/api/openapi.yaml." >&2
  exit 1
fi
