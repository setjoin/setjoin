#!/bin/sh
set -eu

ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

command -v rg >/dev/null 2>&1 || {
  echo "verify: rg is required" >&2
  exit 1
}

for file in index.html styles.css wireframe.js README.md; do
  test -f "$file" || {
    echo "verify: missing $file" >&2
    exit 1
  }
done

rg -q 'href="styles\.css"' index.html
rg -q 'src="wireframe\.js"' index.html
rg -q 'id="view-overview"' index.html
rg -q 'id="view-assessments"' index.html
rg -q 'id="view-outcomes"' index.html
rg -q 'id="view-mappings"' index.html
rg -q 'id="view-documents"' index.html
rg -q 'id="view-settings"' index.html
rg -q 'A0 receipts can be referenced manually, but they are never importable as product runs' index.html
rg -q 'Static A0 HTML/PDF/JSON reports and receipts.*never importable as product assessments' index.html
rg -q 'aria-live="polite"' index.html
rg -q 'data-state-choice="loading"' index.html
rg -q 'data-state-choice="empty"' index.html
rg -q 'data-state-choice="error"' index.html
rg -q 'data-state-choice="ready"' index.html
rg -q 'data-state-choice="partial"' index.html
rg -q 'data-state-choice="stale"' index.html
rg -q 'data-state-choice="permission"' index.html
rg -q 'migration\.assessment\.read' index.html
rg -q 'migration\.assessment\.run' index.html
rg -q 'migration\.assessment\.decide' index.html
rg -q 'migration\.assessment\.attest' index.html
rg -q 'migration\.assessment\.audit' index.html
rg -q 'migration\.assessment\.publish' index.html
rg -q 'migration\.assessment\.delete' index.html
rg -q ':focus-visible' styles.css
rg -q '@media \(max-width: 1199px\)' styles.css
rg -q '@media \(max-width: 767px\)' styles.css
rg -q 'zh-CN' wireframe.js
rg -q 'window\.location\.hash' wireframe.js

echo "verify: required wireframe files and contract markers present"
