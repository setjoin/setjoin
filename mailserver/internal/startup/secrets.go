package startup

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"
)

// secretFileMode is the only permission set a generated secret file may carry.
const secretFileMode os.FileMode = 0o600

// BootstrapSecrets generates all required secrets and writes them to configPath.
// Idempotent -- if configPath already exists with content, does nothing.
// When force is true, overwrites any existing file.
// Hostile pre-existing files (symlinks, other non-regular files, or
// zero-length group/other-accessible plants) are refused with operator
// guidance instead of being written through or widened; a caller-level error
// here refuses startup. Content-bearing regular files found wider than 0600
// are tightened to 0600 via fchmod rather than refused. Re-opened files are
// fchmoded to 0600 before fresh secrets are written, new files are created
// O_EXCL, and no open ever follows a symlink (O_NOFOLLOW).
// Returns nil on success, error if generation or write fails.
func BootstrapSecrets(configPath string, force bool) error {
	if !force {
		bootstrapped, err := secretFileBootstrapped(configPath)
		if err != nil {
			return err
		}
		if bootstrapped {
			return nil
		}
	}

	f, err := openSecretWriteFile(configPath)
	if err != nil {
		return err
	}
	defer f.Close()

	jwtSecret, err := genHex(32)
	if err != nil {
		return fmt.Errorf("generating JWT secret: %w", err)
	}
	dbKey, err := genHex(32)
	if err != nil {
		return fmt.Errorf("generating DB encryption key: %w", err)
	}
	apiKey, err := genHex(32)
	if err != nil {
		return fmt.Errorf("generating internal API key: %w", err)
	}
	vapidKey, err := genECDSA()
	if err != nil {
		return fmt.Errorf("generating VAPID key: %w", err)
	}
	minioAccess, err := genHex(20)
	if err != nil {
		return fmt.Errorf("generating MinIO access key: %w", err)
	}
	minioSecret, err := genHex(40)
	if err != nil {
		return fmt.Errorf("generating MinIO secret key: %w", err)
	}

	_, err = fmt.Fprintf(f, `# Auto-generated on first boot.
# Change these in the Admin Portal under Settings > System.

JWT_SECRET=%s
DB_ENCRYPTION_KEY=%s
INTERNAL_API_KEY=%s
VAPID_PRIVATE_KEY=%s
MINIO_ACCESS_KEY=%s
MINIO_SECRET_KEY=%s
`, jwtSecret, dbKey, apiKey, vapidKey, minioAccess, minioSecret)
	if err != nil {
		return fmt.Errorf("writing config file: %w", err)
	}

	return nil
}

// secretFileBootstrapped reports whether configPath already holds generated
// secrets. It never follows symlinks: any non-regular file at the path is
// refused. A content-bearing regular file whose mode leaks group/other access
// is tightened to 0600 through an O_NOFOLLOW descriptor before being reported
// as bootstrapped, and a zero-length group/other-accessible plant is refused.
func secretFileBootstrapped(configPath string) (bool, error) {
	info, err := os.Lstat(configPath) //nolint:gosec // G703: configPath is operator-controlled (platform config dir or CONFIG_PATH env), never request input
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cannot stat secret file %s: %w", configPath, err)
	}
	if !info.Mode().IsRegular() {
		return false, refuseHostileSecretFile(configPath, info)
	}
	if info.Size() > 0 {
		if err := tightenSecretFileMode(configPath, info.Mode().Perm()); err != nil {
			return false, err
		}
		return true, nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return false, refuseHostileSecretFile(configPath, info)
	}
	return false, nil
}

// tightenSecretFileMode fchmods an existing secret file to 0600 when its mode
// leaks group/other access. The chmod runs on an O_NOFOLLOW descriptor so it
// cannot be redirected onto a symlink swapped in after the Lstat. Owner-only
// files are left untouched.
func tightenSecretFileMode(configPath string, perm os.FileMode) error {
	if perm&0o077 == 0 {
		return nil
	}
	f, err := os.OpenFile(configPath, os.O_RDONLY|syscall.O_NOFOLLOW, 0) //nolint:gosec // G304: configPath is operator-controlled (platform config dir or CONFIG_PATH env), never request input
	if err != nil {
		return fmt.Errorf("cannot re-open secret file %s to tighten permissions: %w", configPath, err)
	}
	// Read-only handle: the operation's verdict is f.Chmod; a Close error on
	// an O_RDONLY descriptor cannot change the outcome.
	defer func() { _ = f.Close() }()
	if err := f.Chmod(secretFileMode); err != nil {
		return fmt.Errorf("cannot tighten secret file %s to 0600: %w", configPath, err)
	}
	return nil
}

// openSecretWriteFile opens configPath for writing freshly generated secrets.
// It refuses any non-regular file and any zero-length group/other-accessible
// pre-existing plant, never follows symlinks (O_NOFOLLOW), creates new files
// exclusively (O_EXCL) with 0600, and fchmods a re-opened file to 0600 before
// any secret byte is written so a planted wide-mode file cannot persist them.
func openSecretWriteFile(configPath string) (*os.File, error) {
	for range 4 {
		info, err := os.Lstat(configPath) //nolint:gosec // G703: configPath is operator-controlled (platform config dir or CONFIG_PATH env), never request input
		switch {
		case err == nil:
			if !info.Mode().IsRegular() {
				return nil, refuseHostileSecretFile(configPath, info)
			}
			if info.Size() == 0 && info.Mode().Perm()&0o077 != 0 {
				return nil, refuseHostileSecretFile(configPath, info)
			}
			f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, secretFileMode) //nolint:gosec // G304: configPath is operator-controlled (platform config dir or CONFIG_PATH env), never request input
			if err != nil {
				// Includes ELOOP when the path was swapped to a symlink
				// after the Lstat: the open must not follow it.
				return nil, fmt.Errorf("cannot open secret file %s: %w", configPath, err)
			}
			// The mode argument only applies at creation time; a pre-existing
			// re-opened file keeps its old mode until fchmoded here.
			if err := f.Chmod(secretFileMode); err != nil {
				// The chmod error is the one reported; the handle is being
				// discarded either way.
				_ = f.Close()
				return nil, fmt.Errorf("cannot set 0600 on secret file %s: %w", configPath, err)
			}
			return f, nil
		case errors.Is(err, os.ErrNotExist):
			f, err := os.OpenFile(configPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, secretFileMode) //nolint:gosec // G304: configPath is operator-controlled (platform config dir or CONFIG_PATH env), never request input
			if errors.Is(err, os.ErrExist) {
				continue // lost a create race; re-evaluate the path state
			}
			if err != nil {
				return nil, fmt.Errorf("cannot create secret file %s: %w", configPath, err)
			}
			return f, nil
		default:
			return nil, fmt.Errorf("cannot stat secret file %s: %w", configPath, err)
		}
	}
	return nil, fmt.Errorf("secret file %s changed state repeatedly during open; refusing", configPath)
}

// refuseHostileSecretFile builds the operator-guidance error returned whenever
// the secret path does not hold a service-owned regular file.
func refuseHostileSecretFile(configPath string, info os.FileInfo) error {
	kind := "a special file"
	switch {
	case info.Mode()&os.ModeSymlink != 0:
		kind = "a symlink"
	case info.IsDir():
		kind = "a directory"
	}
	return fmt.Errorf(
		"refusing unsafe secret file %s: path holds %s with mode %04o; remove it so a plain owner-only regular file (0600) can be generated, then restart",
		configPath, kind, uint32(info.Mode().Perm()),
	)
}

func genHex(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand failed: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func genECDSA() (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("ecdsa keygen failed: %w", err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("ecdsa marshal failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(der), nil
}
