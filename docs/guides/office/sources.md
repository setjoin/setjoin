# Office deployment source inspection

`mailctl sources status` shows the current read-only source posture for the
Collabora test application, external URL-reputation/AI providers, and Ubuntu
APT/Docker configuration. `mailctl sources doctor` emits the same facts and
returns non-zero when a blocking source configuration is invalid.

```bash
mailctl sources status --json
mailctl sources doctor --profile global
mailctl sources doctor --profile china \
  --china-registry registry.example.cn/collabora/code
mailctl sources doctor --profile isolated \
  --isolated-registry registry.lan/collabora/code \
  --isolated-registry-approved
```

The profile may also come from `SETJOIN_CONNECTIVITY_PROFILE`. Existing
`NETWORK_MODE=global|china|airgap|manual` remains a compatibility input when the
new profile is absent. Repository values may be supplied by the matching
`COLLABORA_*_REGISTRY` variables. They are registry/repository names, not URLs:
schemes, credentials, tags, digests, queries and fragments are rejected.

`global` uses the pinned manifest's upstream repository. `china` has no implicit
public accelerator and requires an approved configured registry. `isolated`
requires a local registry plus the explicit approval fact and never falls back
to the public network. These choices describe connectivity only; they do not
claim data residency, compliance, commercial entitlement, or artifact
provenance.

Host inspection reads only fixed files below `/etc/os-release`,
`/etc/apt/sources.list{,.d}` and `/etc/docker/daemon.json`. It ignores symlinks
and oversized/non-regular files, strips URL credentials/query fragments, labels
Setjoin-named files separately from external files, and always returns a
`mutatesHost: false` plan. No `apply`, source rewrite, package refresh, Docker
pull or arbitrary provider request exists in this slice.
