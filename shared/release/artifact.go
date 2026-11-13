package release

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

// VerifyArtifact proves the exact declared byte count and digest. The extra
// byte read is intentional: a prefix with the right hash/size is not accepted.
func VerifyArtifact(r io.Reader, artifact Artifact) error {
	if r == nil {
		return fmt.Errorf("artifact %q reader is nil", artifact.ID)
	}
	if artifact.Size == 0 || !sha256RE.MatchString(artifact.SHA256) {
		return fmt.Errorf("artifact %q has invalid expected metadata", artifact.ID)
	}
	h := sha256.New()
	written, err := io.CopyN(h, r, int64(artifact.Size))
	if err != nil {
		return fmt.Errorf("artifact %q size mismatch: read %d of %d bytes", artifact.ID, written, artifact.Size)
	}
	var extra [1]byte
	n, err := r.Read(extra[:])
	if err != io.EOF || n != 0 {
		return fmt.Errorf("artifact %q exceeds declared size", artifact.ID)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != artifact.SHA256 {
		return fmt.Errorf("artifact %q digest mismatch", artifact.ID)
	}
	return nil
}
