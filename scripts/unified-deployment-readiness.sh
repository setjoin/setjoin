#!/usr/bin/env bash
# Provision, inspect, or remove three prefix-scoped production-shaped Setjoin
# stacks on one authorized Ubuntu Docker host. The stacks share only a private
# test network and an authoritative test DNS resolver. Each stack otherwise
# owns its systemd container, PostgreSQL cluster, object store, runtime config,
# nested Podman/Egress runtime, and installer-generated private key material.
#
# This controller intentionally stops after provisioning. Feature journeys are
# explicit later phases because their state transitions and evidence must run
# serially (D2 -> D6) against retained environments.
#
# Usage:
#   RUN_PREFIX=sj-ready-20260729 bash scripts/unified-deployment-readiness.sh provision
#   RUN_PREFIX=sj-ready-20260729 bash scripts/unified-deployment-readiness.sh resume-provision
#   RUN_PREFIX=sj-ready-20260729 bash scripts/unified-deployment-readiness.sh preflight
#   RUN_PREFIX=sj-ready-20260729 bash scripts/unified-deployment-readiness.sh status
#   RUN_PREFIX=sj-ready-20260729 bash scripts/unified-deployment-readiness.sh cleanup
#
# Overrides:
#   TEST_SUBNET=172.30.240.0/24  dedicated subnet; must be an unused IPv4 /24
#   KEEP_ON_FAIL=0              remove exact prefixed resources after failure
#   REBUILD_BASE=1              rebuild the ga smoke base image
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ACTION="${1:-provision}"
RUN_PREFIX="${RUN_PREFIX:-}"
TEST_SUBNET="${TEST_SUBNET:-172.30.240.0/24}"
PROVISION_ENVS="${PROVISION_ENVS:-a b c}"
KEEP_ON_FAIL="${KEEP_ON_FAIL:-1}"
REBUILD_BASE="${REBUILD_BASE:-0}"
NETWORK=""
DNS_CONTAINER=""
EVIDENCE_DIR=""
DNS_IP=""

say() { printf '\n=== %s ===\n' "$1"; }
die() { printf '\nFAIL: %s\n' "$1" >&2; exit 1; }

validate() {
  case "$RUN_PREFIX" in
    (*[!a-z0-9-]*|'') die "RUN_PREFIX is required and must contain only lowercase a-z, 0-9, or hyphen" ;;
  esac
  [ "${#RUN_PREFIX}" -le 32 ] || die "RUN_PREFIX must be at most 32 characters"
  case "$KEEP_ON_FAIL:$REBUILD_BASE" in
    (*[!01:]*|*::*|:*|*:) die "KEEP_ON_FAIL and REBUILD_BASE must be exactly 0 or 1" ;;
  esac
  case "$PROVISION_ENVS" in
    a|"a b"|"a b c") ;;
    *) die "PROVISION_ENVS must be the ordered prefix 'a', 'a b', or 'a b c'" ;;
  esac
  case "$TEST_SUBNET" in
    (*.*.*".0/24") ;;
    (*) die "TEST_SUBNET must be an IPv4 /24 ending in .0/24" ;;
  esac

  NETWORK="${RUN_PREFIX}-net"
  DNS_CONTAINER="${RUN_PREFIX}-dns"
  SMTP_SINK_CONTAINER="${RUN_PREFIX}-smtp-sink"
  EVIDENCE_DIR="$ROOT/test-results/deployment-readiness/$RUN_PREFIX"
  subnet_base="${TEST_SUBNET%.0/24}"
  DNS_IP="${subnet_base}.53"
}

resource_names() {
  printf '%s\n' \
    "$DNS_CONTAINER" \
    "${RUN_PREFIX}-a" "${RUN_PREFIX}-a-minio" \
    "${RUN_PREFIX}-b" "${RUN_PREFIX}-b-minio" \
    "${RUN_PREFIX}-c" "${RUN_PREFIX}-c-minio" \
    "${RUN_PREFIX}-ldap" \
    "$SMTP_SINK_CONTAINER"
}

cleanup_exact() {
  say "Removing exact prefixed resources"
  while IFS= read -r name; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done < <(resource_names)
  docker network rm "$NETWORK" >/dev/null 2>&1 || true
}

on_exit() {
  rc=$?
  if [ "$rc" -ne 0 ]; then
    if [ "$KEEP_ON_FAIL" = "1" ]; then
      printf '\nMANUAL: preserving %s after failure; inspect %s\n' "$RUN_PREFIX" "$EVIDENCE_DIR" >&2
    else
      cleanup_exact
    fi
  fi
  exit "$rc"
}

preflight() {
  say "Preflight"
  command -v docker >/dev/null 2>&1 || die "docker is required"
  command -v openssl >/dev/null 2>&1 || die "openssl is required"
  command -v awk >/dev/null 2>&1 || die "awk is required"
  docker info >/dev/null 2>&1 || die "Docker daemon is unreachable"

  free_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
  [ "${free_kib:-0}" -ge 12582912 ] ||
    die "at least 12 GiB available memory is required for three full stacks"
  free_kib="$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')"
  [ "${free_kib:-0}" -ge 26214400 ] ||
    die "at least 25 GiB free disk is required"
  [ "$(getconf _NPROCESSORS_ONLN)" -ge 4 ] ||
    die "at least four logical CPUs are required"

  if docker network inspect "$NETWORK" >/dev/null 2>&1; then
    die "network collision: $NETWORK"
  fi
  while IFS= read -r name; do
    if docker container inspect "$name" >/dev/null 2>&1; then
      die "container collision: $name"
    fi
  done < <(resource_names)

  mapfile -t network_ids < <(docker network ls -q)
  if [ "${#network_ids[@]}" -gt 0 ]; then
    if docker network inspect -f '{{range .IPAM.Config}}{{.Subnet}}{{println}}{{end}}' \
        "${network_ids[@]}" 2>/dev/null | grep -Fxq "$TEST_SUBNET"; then
      die "subnet collision: $TEST_SUBNET"
    fi
  fi
  if [ ! -d /run/systemd/system ]; then
    echo "NOTE: host systemd is not required; systemd runs inside privileged containers."
  fi
  printf 'preflight=PASS\nprefix=%s\nsubnet=%s\n' "$RUN_PREFIX" "$TEST_SUBNET"
}

write_dns_config() {
  dns_dir="$EVIDENCE_DIR/dns"
  # These files contain only test names and addresses, not credentials. BIND
  # drops to its unprivileged `bind` user and must be able to traverse/read them.
  install -d -m 0755 "$dns_dir"
  cat >"$dns_dir/named.conf" <<EOF
options {
  directory "/var/cache/bind";
  listen-on { any; };
  listen-on-v6 { none; };
  recursion yes;
  allow-query { any; };
  forwarders { 1.1.1.1; 8.8.8.8; };
  dnssec-validation no;
};
zone "org-a.test" { type primary; file "/etc/bind/db.org-a.test"; };
zone "org-b.test" { type primary; file "/etc/bind/db.org-b.test"; };
zone "org-c.test" { type primary; file "/etc/bind/db.org-c.test"; };
zone "guest-sink.test" { type primary; file "/etc/bind/db.guest-sink.test"; };
EOF
  for env in a b c; do
    case "$env" in
      a) ip="${subnet_base}.11" ;;
      b) ip="${subnet_base}.12" ;;
      c) ip="${subnet_base}.13" ;;
    esac
    cat >"$dns_dir/db.org-${env}.test" <<EOF
\$TTL 30
@ IN SOA ns.org-${env}.test. hostmaster.org-${env}.test. (1 30 30 300 30)
  IN NS ns.org-${env}.test.
ns IN A $DNS_IP
@  IN A $ip
_setjoin-im._tcp IN SRV 0 0 7443 org-${env}.test.
EOF
    if [ "$env" = "b" ]; then
      printf 'ldap IN A %s.61\n' "$subnet_base" >>"$dns_dir/db.org-${env}.test"
    fi
  done
  cat >"$dns_dir/db.guest-sink.test" <<EOF
\$TTL 30
@ IN SOA ns.guest-sink.test. hostmaster.guest-sink.test. (1 30 30 300 30)
  IN NS ns.guest-sink.test.
  IN MX 10 smtp-sink.guest-sink.test.
ns IN A $DNS_IP
smtp-sink IN A ${subnet_base}.60
EOF
  chmod 0644 "$dns_dir"/*
}

run_dns_container() {
  docker run -d --name "$DNS_CONTAINER" \
    --network "$NETWORK" --ip "$DNS_IP" \
    -v "$EVIDENCE_DIR/dns/named.conf:/etc/bind/named.conf:ro" \
    -v "$EVIDENCE_DIR/dns/db.org-a.test:/etc/bind/db.org-a.test:ro" \
    -v "$EVIDENCE_DIR/dns/db.org-b.test:/etc/bind/db.org-b.test:ro" \
    -v "$EVIDENCE_DIR/dns/db.org-c.test:/etc/bind/db.org-c.test:ro" \
    -v "$EVIDENCE_DIR/dns/db.guest-sink.test:/etc/bind/db.guest-sink.test:ro" \
    ubuntu/bind9:9.18-24.04_beta >/dev/null
  for _ in $(seq 1 30); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$DNS_CONTAINER" 2>/dev/null)" = "true" ] &&
       docker logs "$DNS_CONTAINER" 2>&1 | grep -Eq '[[:space:]]running$'; then
      return
    fi
    sleep 1
  done
  docker logs "$DNS_CONTAINER" >&2 || true
  die "authoritative DNS did not become ready"
}

start_dns() {
  say "Private authoritative DNS"
  docker network create --subnet "$TEST_SUBNET" "$NETWORK" >/dev/null
  write_dns_config
  run_dns_container
}

repair_dns_for_resume() {
  say "Repairing exact-name private DNS for resume"
  write_dns_config
  docker rm -f "$DNS_CONTAINER" >/dev/null 2>&1 || true
  run_dns_container
}

provision_one() {
  env="$1"
  case "$env" in
    a) ip="${subnet_base}.11" ;;
    b) ip="${subnet_base}.12" ;;
    c) ip="${subnet_base}.13" ;;
    *) die "unknown environment: $env" ;;
  esac
  name="${RUN_PREFIX}-${env}"
  say "Provision environment ${env^^}: $name"
  resume_preinstall=0
  resume_install=0
  if docker container inspect "$name" >/dev/null 2>&1 ||
     docker container inspect "${name}-minio" >/dev/null 2>&1; then
    if grep -q '^=== RESULT: PASS ===$' "$EVIDENCE_DIR/provision-${env}.log" 2>/dev/null; then
      echo "existing environment has exact PASS evidence; verifying instead of rerunning"
      docker exec "$name" systemctl is-active postgresql setjoin-auth setjoin
      return
    fi
    if docker exec "$name" sh -c \
        'test -f /etc/setjoin/config.env && test -L /opt/setjoin/current && test -e /etc/systemd/system/setjoin.service'; then
      resume_install=1
    else
      resume_preinstall=1
    fi
  fi
  printf '\n--- provision attempt %s ---\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" |
    tee -a "$EVIDENCE_DIR/provision-${env}.log"
  SMOKE_PREFIX="$name" \
  SMOKE_NETWORK="$NETWORK" \
  SMOKE_IPV4="$ip" \
  SMOKE_DNS="$DNS_IP" \
  SMOKE_HOSTNAME="org-${env}.test" \
  KEEP_ON_FAIL=1 \
  KEEP_ON_SUCCESS=1 \
  REPLACE_EXISTING=0 \
  RESUME_PREINSTALL="$resume_preinstall" \
  RESUME_INSTALL="$resume_install" \
  REBUILD_BASE="$REBUILD_BASE" \
    bash "$ROOT/scripts/ga-fresh-install-smoke.sh" \
      2>&1 | tee -a "$EVIDENCE_DIR/provision-${env}.log"
  REBUILD_BASE=0
  docker exec "$name" getent hosts "org-${env}.test" |
    tee "$EVIDENCE_DIR/dns-${env}.txt"
  docker exec "$name" systemctl is-active \
    postgresql setjoin-auth setjoin |
    tee "$EVIDENCE_DIR/services-${env}.txt"
}

write_manifest() {
  {
    printf 'run_prefix=%s\nsubnet=%s\ndns_ip=%s\n' "$RUN_PREFIX" "$TEST_SUBNET" "$DNS_IP"
    printf 'created_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    docker version --format 'docker_client={{.Client.Version}} docker_server={{.Server.Version}}'
    docker ps --filter "name=^/${RUN_PREFIX}-" \
      --format 'container={{.Names}} image={{.Image}} status={{.Status}}'
  } >"$EVIDENCE_DIR/manifest.txt"
}

status() {
  say "Status: $RUN_PREFIX"
  docker ps -a --filter "name=^/${RUN_PREFIX}-" \
    --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Networks}}'
  docker network inspect "$NETWORK" \
    --format '{{range .Containers}}{{.Name}} {{.IPv4Address}}{{println}}{{end}}'
}

validate
case "$ACTION" in
  provision)
    trap on_exit EXIT
    install -d -m 0700 "$EVIDENCE_DIR"
    preflight | tee "$EVIDENCE_DIR/preflight.txt"
    docker ps --format '{{.Names}} {{.Image}} {{.Status}}' >"$EVIDENCE_DIR/preexisting-containers.txt"
    start_dns
    for env in $PROVISION_ENVS; do provision_one "$env"; done
    write_manifest
    status | tee "$EVIDENCE_DIR/status.txt"
    say "PROVISION PASS"
    ;;
  resume-provision)
    trap on_exit EXIT
    [ -d "$EVIDENCE_DIR" ] || die "resume evidence directory is missing: $EVIDENCE_DIR"
    docker network inspect "$NETWORK" >/dev/null 2>&1 ||
      die "resume network is missing: $NETWORK"
    if [ "$(docker inspect -f '{{.State.Running}}' "$DNS_CONTAINER" 2>/dev/null)" != "true" ]; then
      repair_dns_for_resume
    fi
    for env in $PROVISION_ENVS; do provision_one "$env"; done
    write_manifest
    status | tee "$EVIDENCE_DIR/status.txt"
    say "PROVISION PASS"
    ;;
  preflight)
    preflight
    ;;
  status)
    status
    ;;
  cleanup)
    trap - EXIT
    cleanup_exact
    ;;
  self-test)
    expected="$DNS_CONTAINER
${RUN_PREFIX}-a
${RUN_PREFIX}-a-minio
${RUN_PREFIX}-b
${RUN_PREFIX}-b-minio
${RUN_PREFIX}-c
${RUN_PREFIX}-c-minio
${RUN_PREFIX}-ldap
${RUN_PREFIX}-smtp-sink"
    [ "$(resource_names)" = "$expected" ] || die "resource-name contract drifted"
    [ "$DNS_IP" = "${subnet_base}.53" ] || die "DNS address contract drifted"
    printf 'SELF_TEST_PASS prefix=%s resources=9 dns=%s\n' "$RUN_PREFIX" "$DNS_IP"
    ;;
  *)
    die "usage: $0 provision|resume-provision|preflight|status|cleanup|self-test"
    ;;
esac
