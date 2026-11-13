// setjoin-release is a CI-only publisher/verification tool. It is not packaged
// on customer servers and never accepts raw private key material.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"setjoin.com/shared/release"
)

var publisherNow = func() time.Time { return time.Now().UTC() }

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 || args[0] != "manifest" {
		return fmt.Errorf("usage: setjoin-release manifest build|sign|verify|inspect [flags]")
	}
	switch args[1] {
	case "build":
		return runBuild(args[2:])
	case "sign":
		return runSign(args[2:])
	case "verify":
		return runVerify(args[2:])
	case "inspect":
		return runInspect(args[2:])
	default:
		return fmt.Errorf("unknown manifest action %q", args[1])
	}
}

func runBuild(args []string) error {
	fs := flag.NewFlagSet("manifest build", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	draftPath := fs.String("draft", "", "strict unhashed manifest draft")
	artifactsDir := fs.String("artifacts-dir", "", "fixed artifact inventory directory")
	output := fs.String("output", "", "output manifest")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("manifest build flags: %w", err)
	}
	if *draftPath == "" || *artifactsDir == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: manifest build --draft FILE --artifacts-dir DIR --output FILE")
	}
	raw, err := readBounded(*draftPath, release.MaxDocumentBytes)
	if err != nil {
		return err
	}
	manifest, err := release.ParseManifestDraft(raw)
	if err != nil {
		return err
	}
	if err := populateArtifactInventory(manifest, *artifactsDir); err != nil {
		return err
	}
	encoded, err := release.MarshalManifest(manifest)
	if err != nil {
		return err
	}
	return atomicWrite(*output, encoded, 0o644)
}

func populateArtifactInventory(manifest *release.Manifest, root string) error {
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		path := filepath.Join(root, artifact.ID)
		info, err := os.Lstat(path)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ID, err)
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact %q is not a regular file", artifact.ID)
		}
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("artifact %q: %w", artifact.ID, err)
		}
		hash := sha256.New()
		size, copyErr := io.Copy(hash, file)
		closeErr := file.Close()
		if copyErr != nil {
			return fmt.Errorf("artifact %q: hash failed", artifact.ID)
		}
		if closeErr != nil {
			return fmt.Errorf("artifact %q: close failed", artifact.ID)
		}
		artifact.Size = uint64(size)
		artifact.SHA256 = hex.EncodeToString(hash.Sum(nil))
	}
	for i := range manifest.Migrations {
		matched := false
		for _, artifact := range manifest.Artifacts {
			if artifact.ID == manifest.Migrations[i].ID && artifact.Class == release.ArtifactMigration {
				manifest.Migrations[i].SHA256 = artifact.SHA256
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("migration %q has no matching inventory artifact", manifest.Migrations[i].ID)
		}
	}
	return manifest.Validate()
}

type helperSigner struct{ path, keyID string }

func (s helperSigner) KeyID() string { return s.keyID }
func (s helperSigner) Sign(ctx context.Context, payload []byte) ([]byte, error) {
	cmd := exec.CommandContext(ctx, s.path, "sign", "--key-id", s.keyID)
	cmd.Stdin = bytes.NewReader(payload)
	cmd.Stderr = io.Discard
	var output boundedBuffer
	output.maximum = 1024
	cmd.Stdout = &output
	if err := cmd.Run(); err != nil {
		return nil, errors.New("signer helper failed")
	}
	signature, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(output.String()))
	if err != nil {
		return nil, errors.New("signer helper returned invalid signature")
	}
	return signature, nil
}

type boundedBuffer struct {
	bytes.Buffer
	maximum int
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.maximum {
		return 0, errors.New("signer output exceeded limit")
	}
	return b.Buffer.Write(p)
}

func runSign(args []string) error {
	fs := flag.NewFlagSet("manifest sign", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "manifest file")
	helper := fs.String("signer-helper", "", "KMS/PKCS#11 provider helper executable")
	keyID := fs.String("key-id", "", "trusted signing key id")
	output := fs.String("output", "", "signed output")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("manifest sign flags: %w", err)
	}
	if *manifestPath == "" || *helper == "" || *keyID == "" || *output == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: manifest sign --manifest FILE --signer-helper FILE --key-id ID --output FILE")
	}
	raw, err := readBounded(*manifestPath, release.MaxDocumentBytes)
	if err != nil {
		return err
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := release.SignManifest(ctx, manifest, helperSigner{path: *helper, keyID: *keyID}); err != nil {
		return err
	}
	encoded, err := release.MarshalManifest(manifest)
	if err != nil {
		return err
	}
	return atomicWrite(*output, encoded, 0o644)
}

func runVerify(args []string) error {
	fs := flag.NewFlagSet("manifest verify", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "signed manifest")
	artifactsDir := fs.String("artifacts-dir", "", "artifact inventory")
	trustPath := fs.String("trust-roots", "", "release trust roots")
	channel := fs.String("channel", "", "community or enterprise")
	current := fs.String("current-version", "", "current Setjoin version")
	platform := fs.String("platform", "linux", "target platform")
	arch := fs.String("arch", "amd64", "target architecture")
	offline := fs.Bool("offline", false, "verify complete offline bundle")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("manifest verify flags: %w", err)
	}
	if !*offline || *manifestPath == "" || *artifactsDir == "" || *trustPath == "" || *channel == "" || *current == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: manifest verify --offline --manifest FILE --artifacts-dir DIR --trust-roots FILE --channel CHANNEL --current-version VERSION [--platform P --arch A]")
	}
	raw, err := readBounded(*manifestPath, release.MaxDocumentBytes)
	if err != nil {
		return err
	}
	rootsRaw, err := readBounded(*trustPath, release.MaxDocumentBytes)
	if err != nil {
		return err
	}
	keys, err := release.ParseTrustRootDocument(rootsRaw, release.PurposeRelease, false)
	if err != nil {
		return err
	}
	store, err := release.NewTrustStore(keys, false)
	if err != nil {
		return err
	}
	// MinimumThreshold pins the verifier floor (shared/release.MinVerificationThreshold):
	// Signing.Threshold is manifest-authored, so a manifest that lowers its own
	// threshold must still satisfy the policy floor of two vendor signatures.
	verified, err := store.VerifyManifest(raw, release.VerifyManifestOptions{Now: publisherNow(), Channel: release.Channel(*channel), CurrentVersion: *current, Platform: *platform, Architecture: *arch, MinimumThreshold: release.MinVerificationThreshold})
	if err != nil {
		return err
	}
	for _, artifact := range verified.Manifest.Artifacts {
		path := filepath.Join(*artifactsDir, artifact.ID)
		info, statErr := os.Lstat(path)
		if statErr != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("artifact %q is missing or unsafe", artifact.ID)
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			return fmt.Errorf("artifact %q cannot be opened", artifact.ID)
		}
		verifyErr := release.VerifyArtifact(file, artifact)
		closeErr := file.Close()
		if verifyErr != nil {
			return verifyErr
		}
		if closeErr != nil {
			return fmt.Errorf("artifact %q close failed", artifact.ID)
		}
	}
	fmt.Printf("verified release %s digest %s\n", verified.Manifest.ReleaseID, verified.Digest)
	return nil
}

type inspectOutput struct {
	ReleaseID       string          `json:"releaseId"`
	Version         string          `json:"version"`
	Channel         release.Channel `json:"channel"`
	MetadataVersion uint64          `json:"metadataVersion"`
	SchemaFrom      int             `json:"schemaFrom"`
	SchemaTo        int             `json:"schemaTo"`
	ArtifactCount   int             `json:"artifactCount"`
	SignatureKeyIDs []string        `json:"signatureKeyIds"`
}

func runInspect(args []string) error {
	fs := flag.NewFlagSet("manifest inspect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	manifestPath := fs.String("manifest", "", "manifest file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifestPath == "" || fs.NArg() != 0 {
		return fmt.Errorf("usage: manifest inspect --manifest FILE")
	}
	raw, err := readBounded(*manifestPath, release.MaxDocumentBytes)
	if err != nil {
		return err
	}
	manifest, err := release.ParseManifest(raw)
	if err != nil {
		return err
	}
	keys := make([]string, len(manifest.Signatures))
	for i, sig := range manifest.Signatures {
		keys[i] = sig.KeyID
	}
	output := inspectOutput{ReleaseID: manifest.ReleaseID, Version: manifest.Version, Channel: manifest.Channel, MetadataVersion: manifest.MetadataVersion, SchemaFrom: manifest.SchemaFrom, SchemaTo: manifest.SchemaTo, ArtifactCount: len(manifest.Artifacts), SignatureKeyIDs: keys}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(output)
}

func readBounded(path string, maximum int) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maximum {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximum)
	}
	return raw, nil
}
func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".setjoin-release-*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dirHandle, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirHandle.Close()
	return dirHandle.Sync()
}
