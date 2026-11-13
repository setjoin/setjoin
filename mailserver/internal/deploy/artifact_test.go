package deploy

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sha256Hex is the test-side digest of fixture archive bytes, used to build
// the pin that DEPLOY_SEAWEEDFS_SHA256 records for the run.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// buildSeaweedFSTarball builds a real gzipped tar archive — the same shape of
// object the pinned GitHub release serves — containing a single executable
// member named "weed", exactly the member the generated install command
// extracts with `tar -xzf ... weed`. Tests never download: the archive bytes
// are produced locally and served to the command by the curl shim.
func buildSeaweedFSTarball(t *testing.T, weed []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)
	if err := tw.WriteHeader(&tar.Header{
		Name:     "weed",
		Mode:     0o755,
		Size:     int64(len(weed)),
		Typeflag: tar.TypeReg,
		ModTime:  time.Unix(0, 0).UTC(),
	}); err != nil {
		t.Fatalf("write tar header: %v", err)
	}
	if _, err := tw.Write(weed); err != nil {
		t.Fatalf("write weed member: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return buf.Bytes()
}

// installShSandbox executes the generated remote install command under a real
// POSIX shell on the test host. Only two edges are contained, because a test
// must not touch the network or the real filesystem root:
//
//   - curl is shimmed to serve a fixed local archive file (and to refuse any
//     URL other than the pinned artifact URL), replacing only the download
//     transport;
//   - install is shimmed to relocate its destination under a sandbox root and
//     then run the real install binary, so /usr/local/bin is never written.
//
// Everything the HOLD is about runs for real: the sha256 gate (sha256sum or
// the shasum fallback), the tar extraction of the weed member, and the
// `install -m 0755 ... /usr/local/bin/weed` installation step.
type installShSandbox struct {
	binDir     string // shim dir prepended to PATH
	rootDir    string // install destination sandbox root: rootDir/usr/local/bin/weed
	tmpDir     string // TMPDIR for the command's mktemp staging dir
	logDir     string // shim invocation logs
	basePATH   string // PATH (sans shim dir) the command resolves tools against
	weedPath   string // relocated /usr/local/bin/weed
	tarLog     string // log of tar invocations
	curlLog    string // log of URLs the curl shim was asked to fetch
	archiveLog string // file the curl shim serves from
}

// newInstallShSandbox materializes the shim directory for one command run.
func newInstallShSandbox(t *testing.T, servedArchive []byte, expectURL string) *installShSandbox {
	t.Helper()
	realTar, err := exec.LookPath("tar")
	if err != nil {
		t.Fatalf("no real tar binary to exercise the extract step: %v", err)
	}
	realInstall, err := exec.LookPath("install")
	if err != nil {
		t.Fatalf("no real install binary to exercise the install step: %v", err)
	}

	base := t.TempDir()
	sb := &installShSandbox{
		binDir:     filepath.Join(base, "bin"),
		rootDir:    filepath.Join(base, "root"),
		tmpDir:     filepath.Join(base, "tmp"),
		logDir:     filepath.Join(base, "log"),
		basePATH:   os.Getenv("PATH"),
		weedPath:   filepath.Join(base, "root", "usr", "local", "bin", "weed"),
		tarLog:     filepath.Join(base, "log", "tar-calls.log"),
		curlLog:    filepath.Join(base, "log", "curl-urls.log"),
		archiveLog: filepath.Join(base, "served", seaweedfsReleaseAsset),
	}
	for _, dir := range []string{sb.binDir, sb.rootDir, sb.tmpDir, sb.logDir, filepath.Dir(sb.archiveLog)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatalf("sandbox mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(sb.archiveLog, servedArchive, 0o600); err != nil {
		t.Fatalf("stage served archive: %v", err)
	}

	shim := func(name, script string) {
		t.Helper()
		path := filepath.Join(sb.binDir, name)
		if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
			t.Fatalf("write %s shim: %v", name, err)
		}
	}

	shim("curl", fmt.Sprintf(`#!/bin/sh
# Test-only curl shim (artifact_test.go): serves a fixed local archive to the
# -o target and records the requested URL. The download transport is stubbed;
# every downstream step of the generated command runs for real.
out=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
printf '%%s\n' "$url" >> %q
if [ "$url" != %q ]; then
  echo "fake curl: requested URL $url is not the pinned artifact URL" >&2
  exit 22
fi
cp %q "$out" || exit 1
`, sb.curlLog, expectURL, sb.archiveLog))

	shim("tar", fmt.Sprintf(`#!/bin/sh
# Test-only tar shim (artifact_test.go): records the invocation, then runs the
# real tar binary so extraction is genuinely exercised.
printf '%%s\n' "$*" >> %q
exec %q "$@"
`, sb.tarLog, realTar))

	shim("install", fmt.Sprintf(`#!/bin/sh
# Test-only install shim (artifact_test.go): relocates the destination under
# the sandbox root, then runs the real install binary — real mode semantics,
# no writes to the machine's /usr/local/bin.
[ $# -eq 4 ] && [ "$1" = "-m" ] || { echo "fake install: unexpected invocation: $*" >&2; exit 64; }
mode="$2"; src="$3"; dst="$4"
newdst=%q"$dst"
mkdir -p "$(dirname "$newdst")" || exit 1
exec %q -m "$mode" "$src" "$newdst"
`, sb.rootDir+string(os.PathSeparator), realInstall))

	return sb
}

// run executes command (the generated remote install command) via sh -c with
// the sandbox bin dir prepended to PATH and staging contained in TMPDIR.
func (sb *installShSandbox) run(t *testing.T, command string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", command)
	env := make([]string, 0, len(os.Environ())+2)
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "PATH=") || strings.HasPrefix(kv, "TMPDIR=") {
			continue
		}
		env = append(env, kv)
	}
	env = append(env,
		"PATH="+sb.binDir+string(os.PathListSeparator)+sb.basePATH,
		"TMPDIR="+sb.tmpDir,
	)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (sb *installShSandbox) logLines(t *testing.T, logPath string) []string {
	t.Helper()
	data, err := os.ReadFile(logPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read %s: %v", logPath, err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	return lines
}

// installedWeed returns the installed weed binary bytes, or nil when the
// command never installed it.
func (sb *installShSandbox) installedWeed(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(sb.weedPath)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatalf("read installed weed: %v", err)
	}
	return data
}

// installedWeedMode returns the installed weed binary's permission bits.
func (sb *installShSandbox) installedWeedMode(t *testing.T) os.FileMode {
	t.Helper()
	info, err := os.Stat(sb.weedPath)
	if err != nil {
		t.Fatalf("stat installed weed: %v", err)
	}
	return info.Mode().Perm()
}

// pathWithoutDirsContaining returns PATH with every directory that contains
// name removed, so `command -v <name>` inside the generated script fails and
// its fallback branch runs. ok is false when nothing would remain.
func pathWithoutDirsContaining(t *testing.T, name string) (string, bool) {
	t.Helper()
	var kept []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			continue
		}
		kept = append(kept, dir)
	}
	if len(kept) == 0 {
		return "", false
	}
	return strings.Join(kept, string(os.PathListSeparator)), true
}

// lookPathIn resolves name against a specific PATH value.
func lookPathIn(t *testing.T, pathValue, name string) (string, error) {
	t.Helper()
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" {
			continue
		}
		full := filepath.Join(dir, name)
		if info, err := os.Stat(full); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return full, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH", name)
}

// TestArtifactShellVerification_EndToEnd executes the GENERATED remote install
// command under a real POSIX shell against a real local archive, closing the
// review gap: a valid pinned archive must pass the shell checksum gate and be
// extracted and installed unchanged; a single tampered byte must fail
// verification with no extraction and no installation. The download transport
// is stubbed (local archive, pinned-URL assert) and the /usr/local/bin
// destination is relocated; the checksum gate, tar extraction and install step
// all run as real binaries.
func TestArtifactShellVerification_EndToEnd(t *testing.T) {
	weed := []byte("#!/bin/sh\n# fixture weed server binary\necho seaweedfs fixture weed\n")
	archive := buildSeaweedFSTarball(t, weed)
	digest := sha256Hex(archive)
	pinnedURL := seaweedfsArtifactURL(pinnedSeaweedFSVersion)

	buildCommand := func(t *testing.T) string {
		t.Helper()
		t.Setenv(seaweedfsChecksumEnv, digest)
		command, err := buildSeaweedFSInstallCommand()
		if err != nil {
			t.Fatalf("build install command: %v", err)
		}
		return command
	}

	t.Run("valid archive verifies and installs unchanged", func(t *testing.T) {
		sb := newInstallShSandbox(t, archive, pinnedURL)
		command := buildCommand(t)
		out, err := sb.run(t, command)
		if err != nil {
			t.Fatalf("generated install command failed on the valid pinned archive: %v\noutput:\n%s", err, out)
		}
		urls := sb.logLines(t, sb.curlLog)
		if len(urls) != 1 || urls[0] != pinnedURL {
			t.Fatalf("download did not fetch exactly the pinned URL %s: %v", pinnedURL, urls)
		}
		calls := sb.logLines(t, sb.tarLog)
		if len(calls) != 1 {
			t.Fatalf("expected exactly one real tar extraction, got %v", calls)
		}
		installed := sb.installedWeed(t)
		if installed == nil {
			t.Fatalf("weed binary was not installed at the relocated /usr/local/bin/weed\noutput:\n%s", out)
		}
		if !bytes.Equal(installed, weed) {
			t.Fatal("installed weed binary is not byte-identical to the archived binary")
		}
		if mode := sb.installedWeedMode(t); mode != 0o755 {
			t.Fatalf("installed weed mode = %o, want 755", mode)
		}
	})

	t.Run("tampered byte blocks extraction and installation", func(t *testing.T) {
		tampered := append([]byte(nil), archive...)
		tampered[len(tampered)/2] ^= 0xFF
		// The pin still describes the ORIGINAL archive: the served bytes are
		// corrupt, exactly like a tampered or truncated download at install
		// time on a real node.
		sb := newInstallShSandbox(t, tampered, pinnedURL)
		command := buildCommand(t)
		out, err := sb.run(t, command)
		if err == nil {
			t.Fatalf("tampered archive passed verification and ran to completion:\n%s", out)
		}
		if !strings.Contains(out, "checksum mismatch") || !strings.Contains(out, "refusing to install") {
			t.Fatalf("failure is not the checksum-gate refusal:\n%s", out)
		}
		if calls := sb.logLines(t, sb.tarLog); len(calls) != 0 {
			t.Fatalf("tar extraction ran despite failed verification: %v", calls)
		}
		if installed := sb.installedWeed(t); installed != nil {
			t.Fatal("weed binary was installed despite failed verification")
		}
	})

	t.Run("shasum fallback verifies when sha256sum is absent", func(t *testing.T) {
		filtered, ok := pathWithoutDirsContaining(t, "sha256sum")
		if !ok {
			t.Skip("cannot mask sha256sum from PATH on this host")
		}
		if _, err := lookPathIn(t, filtered, "shasum"); err != nil {
			t.Skipf("no shasum available outside the masked dirs: %v", err)
		}
		sb := newInstallShSandbox(t, archive, pinnedURL)
		sb.basePATH = filtered
		command := buildCommand(t)
		out, err := sb.run(t, command)
		if err != nil {
			t.Fatalf("generated install command failed via the shasum fallback: %v\noutput:\n%s", err, out)
		}
		if installed := sb.installedWeed(t); installed == nil {
			t.Fatalf("weed binary was not installed via the shasum fallback leg\noutput:\n%s", out)
		}
	})
}

// TestBuildSeaweedFSInstallCommand_PinnedVersionVerifiedBeforeExtract asserts
// the generated remote command pins the version, never uses the mutable
// "latest" release, downloads to a staging file, and only extracts/installs
// after the checksum gate passes (refusal exits before tar runs).
func TestBuildSeaweedFSInstallCommand_PinnedVersionVerifiedBeforeExtract(t *testing.T) {
	t.Setenv(seaweedfsChecksumEnv, strings.Repeat("cd", 32))
	cmd, err := buildSeaweedFSInstallCommand()
	if err != nil {
		t.Fatalf("build install command: %v", err)
	}

	pinnedURL := seaweedfsArtifactURL(pinnedSeaweedFSVersion)
	if !strings.Contains(cmd, pinnedURL) {
		t.Fatalf("command does not use pinned URL %s:\n%s", pinnedURL, cmd)
	}
	if strings.Contains(cmd, "latest/download") {
		t.Fatalf("command still references the mutable latest release:\n%s", cmd)
	}
	if !strings.Contains(cmd, "curl -fsSL -o $weedTmp/") {
		t.Fatalf("command does not download to a staged temp file:\n%s", cmd)
	}
	if strings.Contains(cmd, "| tar") {
		t.Fatalf("command still pipes the archive straight into tar:\n%s", cmd)
	}
	if !strings.Contains(cmd, "sha256sum") || !strings.Contains(cmd, "shasum -a 256") {
		t.Fatalf("command lacks the sha256 verification step:\n%s", cmd)
	}
	if !strings.Contains(cmd, strings.Repeat("cd", 32)) {
		t.Fatalf("command does not embed the pinned digest:\n%s", cmd)
	}
	refuse := strings.Index(cmd, "exit 1")
	extract := strings.Index(cmd, "tar -xzf")
	if refuse < 0 || extract < 0 || refuse > extract {
		t.Fatalf("checksum refusal (at %d) does not precede extraction (at %d):\n%s", refuse, extract, cmd)
	}
	install := strings.Index(cmd, `install -m 0755 "$weedTmp/weed" /usr/local/bin/weed`)
	if install < extract {
		t.Fatalf("weed install (at %d) does not follow extraction (at %d):\n%s", install, extract, cmd)
	}
}

// TestResolveSeaweedFSSpec_FailsClosedWithoutDigest asserts the fail-closed
// posture: with no pin-table entry and no operator-supplied digest, no
// install command is produced at all.
func TestResolveSeaweedFSSpec_FailsClosedWithoutDigest(t *testing.T) {
	t.Setenv(seaweedfsChecksumEnv, "")

	if _, err := resolveSeaweedFSSpec(); err == nil {
		t.Fatal("spec resolved without any pinned digest — must fail closed")
	} else if !strings.Contains(err.Error(), "refusing to install") {
		t.Fatalf("fail-closed error not explicit: %v", err)
	}
	if cmd, err := buildSeaweedFSInstallCommand(); err == nil {
		t.Fatalf("install command built without a pinned digest:\n%s", cmd)
	}

	t.Setenv(seaweedfsChecksumEnv, "not-a-digest")
	if _, err := resolveSeaweedFSSpec(); err == nil {
		t.Fatal("malformed digest accepted — must fail closed")
	}
}

// TestInstallPackages_FailsClosedBeforeRemoteExecution asserts the wizard's
// install step refuses before contacting any node when the artifact pin
// cannot be resolved — no SSH dial, no root execution.
func TestInstallPackages_FailsClosedBeforeRemoteExecution(t *testing.T) {
	t.Setenv(seaweedfsChecksumEnv, "")
	w := &Wizard{
		state: &DeploymentState{
			Nodes: []NodeConfig{{Host: "203.0.113.10", Role: "standby", SSHUser: "root", SSHKey: "/tmp/deploy-test-key"}},
		},
		logger: slog.Default(),
	}
	err := w.installPackages(t.Context())
	if err == nil {
		t.Fatal("installPackages proceeded with an unresolved SeaweedFS pin")
	}
	msg := err.Error()
	if !strings.Contains(msg, "seaweedfs artifact pin") || !strings.Contains(msg, "refusing to install") {
		t.Fatalf("fail-closed pin error not surfaced: %v", err)
	}
	if strings.Contains(msg, "dial") || strings.Contains(msg, "ssh: ") {
		t.Fatalf("refusal happened after remote contact: %v", err)
	}
}
