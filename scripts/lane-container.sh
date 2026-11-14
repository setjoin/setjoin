#!/usr/bin/env bash
# lane-container.sh CMD...: run CMD as root in the lane image ($LANE_IMAGE) on the host network
# with the Docker socket. Workspace, $HOME and /tmp sit at identical paths, so the bind mounts of
# the sibling containers the oracles start resolve on the host. Lane, cargo, Go and server-rust
# variables pass through; ownership goes back to the runner user on exit. The Go toolchain is masked
# (empty /usr/local/go, LANE_GO_MASKED=1): Go runs only in reviewed sibling containers (#141).
set -uo pipefail
: "${LANE_IMAGE:?}" "${LANE_OWNER:?}" "${LANE_CACHE:?}"
name="setjoin-lane-run-${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}-${LANE_JOB_TAG:-${GITHUB_JOB:-job}}"
docker rm -f "$name" >/dev/null 2>&1 || true
env_args=()
for var in $(compgen -e); do
  case "$var" in LANE_*|CARGO_*|SERVER_RUST_*|GOFREE_*|PGPASSWORD|PEBBLE_BIN|RUSTFLAGS|LLVM_PROFILE_FILE) env_args+=(-e "$var") ;; esac
done
docker run --name "$name" --label "setjoin-lane-run=${GITHUB_RUN_ID:-local}-${GITHUB_RUN_ATTEMPT:-0}" \
  --network host --shm-size=2g --ulimit nofile=1048576:1048576 \
  -v /var/run/docker.sock:/var/run/docker.sock -v "$(command -v docker)":/usr/local/bin/docker:ro \
  -v "$HOME:$HOME" -v /tmp:/tmp -w "$PWD" "${env_args[@]}" -e TMPDIR="$LANE_CACHE/tmp" \
  --mount type=tmpfs,destination=/usr/local/go,tmpfs-mode=0555 -e LANE_GO_MASKED=1 \
  -e "PATH=/usr/local/bin:/root/.cargo/bin:/usr/lib/postgresql/17/bin:/usr/local/sbin:/usr/sbin:/usr/bin:/sbin:/bin" \
  "$LANE_IMAGE" bash -c '
    trap '\''chown -R "$LANE_OWNER" "$PWD" "$LANE_CACHE" "${LANE_BUILD:-$LANE_CACHE}" 2>/dev/null'\'' EXIT
    git config --global --add safe.directory "*"
    mkdir -p "$TMPDIR"
    chown -R 0:0 "$PWD" 2>/dev/null
    chown -R 0:0 "$CARGO_HOME/advisory-dbs" 2>/dev/null
    "$@"' lane "$@"
rc=$?
docker inspect -f 'lane container exit={{.State.ExitCode}} oom_killed={{.State.OOMKilled}}' "$name" || true
docker rm -f "$name" >/dev/null 2>&1 || true
exit "$rc"
