# Deploy wizard and airgap security fixes (#542)

Parent: [Platform](DOX.md). Owner-approved divergences from frozen Go (2026-11-05), all
tested by `bins/gateway/tests/secfix11.rs` and rejected-mutant proven by
`scripts/test-secfix11-mutants.py` (`SETJOIN_SECFIX3_MUTANT`, feature `oracle-mutants`).

| Fix | Behaviour | Mutant |
| --- | --- | --- |
| Org-wide scope | deploy start/cancel/status and airgap upload need an org-wide `system.upgrade` grant (`upgrade_org_wide`, SQL `admin_org_wide_grant`); denial is the bare 403 plus a `console.denied` row | `upgrade-scoped-grant-{deploy-start,deploy-cancel,deploy-status,airgap-upload}` |
| Storage reads | status, DR-scan list/get, migration list/get keep Go's Mail-console gate and also need an org-wide grant (`storage_read_org_wide`) | `storage-read-scoped-{status,scan-list,scan-get,migrate-list,migrate-get}` |
| SSH output | each stream is bounded at 256 KiB while read (`ssh::Capture`); the reported 4096-byte prefix is unchanged | `deploy-ssh-output-unbounded` |
| Request body | `platform_deploy.rs` reads at most 1 MiB, parses once; over the cap answers the bare 400 `invalid JSON body` | `deploy-body-uncapped` |
| Node fields | `deploy::validate`: hostname, IPv4 or bracketed IPv6 (optional `:port`) and POSIX user only (400 `invalid node host` / `invalid ssh_user`); `build` re-checks and `sh_quote`s hosts (ordinary hosts keep their reviewed bytes); `ssh_key` is inline material only, a path is never read (the step fails with `parse key: ssh: no key found`, as a missing file did) | `deploy-node-unvalidated`, `deploy-host-unquoted`, `deploy-ssh-key-path` |
| Fence | the unresolved remote-command fence is the singleton row of `deploy_remote_fence` (V280, Rust-only: Go never references it and its `deployment_steps` statements are untouched). `Wizard::load` restores it; the table is owned by `setjoin_owner` and app/worker cannot DELETE, so an operator resolves it as the owner with `DELETE FROM deploy_remote_fence` (the next start notices, no restart); a failed persist keeps the in-process fence, logs loudly and the fence is re-attempted before the next run is admitted. An unreadable table fails closed | `deploy-fence-memory-only` |
| Rollback floor | per-slug floor in `<store dir>.floor` (JSON, beside the store so the served directory and its snapshots are unchanged), written atomically before an upload becomes visible, max-merged with surviving sidecars at load, never lowered by pruning; an unreadable floor file disables the store | `airgap-floor-sidecar-only` |

Goldens pinned in `platform/divergences.json` (expectations under `platform/security/`): the
four `*-scoped` deploy/airgap routes with row effects, and the five storage read `*-scoped`
cases. The oracle's scoped deploy cases observe the process through an org-wide probe user.
Cases that run the wizard delete `deploy_remote_fence` before and after (the fence is durable).
