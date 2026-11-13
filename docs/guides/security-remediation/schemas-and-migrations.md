# Security-program schemas and migrations

Run `coverage migrate --check` to validate the current C0 control, diagnostic,
epoch, section, and shard schemas without rewriting evidence. Add `--to v2` to validate
the supported projection-v1-to-v2 adapter. The check invokes `migrateProjection`, hashes
the bounded source and resulting projection, and applies the same unfinished-attempt fence
used by publication. It reports `migrationRequired: true` for the v1-to-v2 dry check and
does not publish. Unsupported versions fail closed.

The migration engine publishes a new immutable generation linked to its predecessor,
fences active, detached, orphaned, and completion-unknown attempts, and replays an
interrupted publication idempotently. A rollback pointer is rejected because the latest
pointer must name the monotonic lineage tip. CLI `--execute` remains blocked until a
matching approval and free global lease are bound; never bypass that block manually.
