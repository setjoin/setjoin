# Coverage quickstart

Use `coverage list` to inspect S01-S30 without paths. Add `--section S02 --paths`
to receive the 219 frozen S02/P01 entries and opaque path tokens. Resolve one token
with `coverage show --path-token TOKEN`. `coverage evidence` verifies sanitized C0
hashes and counts; it never prints finding bodies or absolute evidence paths.

No command in this quickstart starts a scanner. `coverage start` remains HOLD until
the plan's admission gates and separate user approval are satisfied.
