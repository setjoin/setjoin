package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type privateArtifactMode string

const (
	privateArtifactCreateOnly      privateArtifactMode = "create-only"
	privateArtifactReplaceExisting privateArtifactMode = "replace-existing"
)

type privateArtifactCleanup string

const (
	privateArtifactCleanupNotRequired privateArtifactCleanup = "not-required"
	privateArtifactCleanupComplete    privateArtifactCleanup = "complete"
	privateArtifactCleanupFailed      privateArtifactCleanup = "failed"
)

type privateArtifactDirectorySync string

const (
	privateArtifactDirectorySyncNotAttempted privateArtifactDirectorySync = "not-attempted"
	privateArtifactDirectorySyncComplete     privateArtifactDirectorySync = "complete"
	privateArtifactDirectorySyncUnsupported  privateArtifactDirectorySync = "unsupported"
	privateArtifactDirectorySyncFailed       privateArtifactDirectorySync = "failed"
)

type privateArtifactReplacement string

const (
	privateArtifactReplacementNotApplicable privateArtifactReplacement = "not-applicable"
	privateArtifactReplacementNotNeeded     privateArtifactReplacement = "not-needed"
	privateArtifactReplacementComplete      privateArtifactReplacement = "complete"
	privateArtifactReplacementUnsupported   privateArtifactReplacement = "unsupported"
	privateArtifactReplacementFailed        privateArtifactReplacement = "failed"
)

// privateArtifactInstallResult distinguishes failures before publication from a
// directory-sync failure after the new name is already visible. Callers keep
// command-specific diagnostics and policy; the filesystem primitive reports fact.
type privateArtifactInstallResult struct {
	Mode          privateArtifactMode
	Published     bool
	Cleanup       privateArtifactCleanup
	DirectorySync privateArtifactDirectorySync
	Replacement   privateArtifactReplacement
}

type privateArtifactPublishedError struct{ err error }

func (e privateArtifactPublishedError) Error() string {
	return "private artifact is published but directory durability is uncertain: " + e.err.Error()
}

func (e privateArtifactPublishedError) Unwrap() error { return e.err }

type privateArtifactRollbackDurabilityError struct{ err error }

func (e privateArtifactRollbackDurabilityError) Error() string {
	return "private artifact target was restored but directory durability is uncertain: " + e.err.Error()
}

func (e privateArtifactRollbackDurabilityError) Unwrap() error { return e.err }

type privateArtifactFile interface {
	io.Writer
	Chmod(os.FileMode) error
	Sync() error
	Close() error
	Name() string
}

type privateArtifactOperations struct {
	createTemp func(string, string) (privateArtifactFile, error)
	lstat      func(string) (os.FileInfo, error)
	link       func(string, string) error
	replace    func(string, string, os.FileInfo) (bool, privateArtifactCleanup, bool, error)
	remove     func(string) error
	syncDir    func(string) (privateArtifactDirectorySync, error)
}

var systemPrivateArtifactOperations = privateArtifactOperations{
	createTemp: func(dir, pattern string) (privateArtifactFile, error) {
		return os.CreateTemp(dir, pattern)
	},
	lstat:   os.Lstat,
	link:    os.Link,
	replace: replacePrivateArtifactExisting,
	remove:  os.Remove,
	syncDir: syncPrivateArtifactDirectory,
}

// publishPrivateNew atomically publishes one private regular file and never
// replaces any existing directory entry. The parent directory must already
// exist and support same-directory hard links.
func publishPrivateNew(path string, data []byte) (privateArtifactInstallResult, error) {
	return publishPrivateNewWithOperations(systemPrivateArtifactOperations, path, data)
}

func publishPrivateNewWithOperations(
	ops privateArtifactOperations,
	path string,
	data []byte,
) (privateArtifactInstallResult, error) {
	result := privateArtifactInstallResult{
		Mode:          privateArtifactCreateOnly,
		Cleanup:       privateArtifactCleanupNotRequired,
		DirectorySync: privateArtifactDirectorySyncNotAttempted,
		Replacement:   privateArtifactReplacementNotApplicable,
	}
	dir := filepath.Dir(path)
	file, err := ops.createTemp(dir, ".mailctl-private-artifact-*")
	if err != nil {
		return result, fmt.Errorf("create temporary private artifact: %w", err)
	}
	tempName := file.Name()
	fail := func(cause error) (privateArtifactInstallResult, error) {
		closeErr := file.Close()
		removeErr := ops.remove(tempName)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			result.Cleanup = privateArtifactCleanupComplete
			return result, errors.Join(cause, closeErr)
		}
		result.Cleanup = privateArtifactCleanupFailed
		return result, errors.Join(cause, closeErr, fmt.Errorf("clean temporary private artifact: %w", removeErr))
	}
	if err := file.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("secure temporary private artifact: %w", err))
	}
	if err := writePrivateArtifactData(file, data); err != nil {
		return fail(fmt.Errorf("write temporary private artifact: %w", err))
	}
	if err := file.Sync(); err != nil {
		return fail(fmt.Errorf("sync temporary private artifact: %w", err))
	}
	if err := file.Close(); err != nil {
		removeErr := ops.remove(tempName)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			result.Cleanup = privateArtifactCleanupComplete
			return result, fmt.Errorf("close temporary private artifact: %w", err)
		}
		result.Cleanup = privateArtifactCleanupFailed
		return result, errors.Join(
			fmt.Errorf("close temporary private artifact: %w", err),
			fmt.Errorf("clean temporary private artifact: %w", removeErr),
		)
	}
	if err := ops.link(tempName, path); err != nil {
		removeErr := ops.remove(tempName)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			result.Cleanup = privateArtifactCleanupComplete
			return result, fmt.Errorf("publish new private artifact: %w", err)
		}
		result.Cleanup = privateArtifactCleanupFailed
		return result, errors.Join(
			fmt.Errorf("publish new private artifact: %w", err),
			fmt.Errorf("clean temporary private artifact: %w", removeErr),
		)
	}
	result.Published = true
	if err := ops.remove(tempName); err != nil && !errors.Is(err, os.ErrNotExist) {
		result.Cleanup = privateArtifactCleanupFailed
		return result, privateArtifactPublishedError{err: fmt.Errorf("temporary artifact cleanup failed: %w", err)}
	}
	result.Cleanup = privateArtifactCleanupComplete
	status, err := ops.syncDir(dir)
	result.DirectorySync = status
	if err != nil {
		return result, privateArtifactPublishedError{err: fmt.Errorf("sync private artifact directory: %w", err)}
	}
	return result, nil
}

// installPrivateReplace atomically installs bytes at an absent or regular-file
// destination. It refuses symlinks and all other non-regular entries. The parent
// directory must already exist; confirmation and artifact validation stay local.
func installPrivateReplace(path string, data []byte) (privateArtifactInstallResult, error) {
	return installPrivateReplaceWithOperations(systemPrivateArtifactOperations, path, data)
}

func installPrivateReplaceWithOperations(
	ops privateArtifactOperations,
	path string,
	data []byte,
) (privateArtifactInstallResult, error) {
	result := privateArtifactInstallResult{
		Mode:          privateArtifactReplaceExisting,
		Cleanup:       privateArtifactCleanupNotRequired,
		DirectorySync: privateArtifactDirectorySyncNotAttempted,
		Replacement:   privateArtifactReplacementNotNeeded,
	}
	var expectedTarget os.FileInfo
	if info, err := ops.lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return result, fmt.Errorf("refusing to replace non-regular private artifact %s", path)
		}
		expectedTarget = info
		if !privateArtifactReplaceExistingSupported {
			result.Replacement = privateArtifactReplacementUnsupported
			return result, fmt.Errorf("atomic replacement of an existing private artifact is unsupported on this platform")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return result, fmt.Errorf("inspect private artifact %s: %w", path, err)
	}

	dir := filepath.Dir(path)
	temp, err := ops.createTemp(dir, ".mailctl-private-artifact-*")
	if err != nil {
		return result, fmt.Errorf("create temporary private artifact: %w", err)
	}
	tempName := temp.Name()
	cleanup := func(cause error, closeFile bool) (privateArtifactInstallResult, error) {
		var closeErr error
		if closeFile {
			closeErr = temp.Close()
		}
		removeErr := ops.remove(tempName)
		if removeErr == nil || errors.Is(removeErr, os.ErrNotExist) {
			result.Cleanup = privateArtifactCleanupComplete
			return result, errors.Join(cause, closeErr)
		}
		result.Cleanup = privateArtifactCleanupFailed
		return result, errors.Join(cause, closeErr, fmt.Errorf("clean temporary private artifact: %w", removeErr))
	}
	if err := temp.Chmod(0o600); err != nil {
		return cleanup(fmt.Errorf("secure temporary private artifact: %w", err), true)
	}
	if err := writePrivateArtifactData(temp, data); err != nil {
		return cleanup(fmt.Errorf("write temporary private artifact: %w", err), true)
	}
	if err := temp.Sync(); err != nil {
		return cleanup(fmt.Errorf("sync temporary private artifact: %w", err), true)
	}
	if err := temp.Close(); err != nil {
		return cleanup(fmt.Errorf("close temporary private artifact: %w", err), false)
	}
	if expectedTarget == nil {
		// Link is an atomic no-replace publication. In particular, an entry
		// created after the initial Lstat is never overwritten.
		if err := ops.link(tempName, path); err != nil {
			return cleanup(fmt.Errorf("publish absent private artifact: %w", err), false)
		}
		result.Published = true
		if err := ops.remove(tempName); err != nil && !errors.Is(err, os.ErrNotExist) {
			result.Cleanup = privateArtifactCleanupFailed
			return result, privateArtifactPublishedError{err: fmt.Errorf("temporary artifact cleanup failed: %w", err)}
		}
		result.Cleanup = privateArtifactCleanupComplete
	} else {
		published, artifactCleanup, namespaceMutated, err := ops.replace(tempName, path, expectedTarget)
		result.Published = published
		result.Cleanup = artifactCleanup
		if err != nil {
			result.Replacement = privateArtifactReplacementFailed
			if published {
				return result, privateArtifactPublishedError{err: fmt.Errorf("replace private artifact: %w", err)}
			}
			if namespaceMutated {
				cleanedResult, cleanupErr := cleanup(fmt.Errorf("replace private artifact: %w", err), false)
				status, syncErr := ops.syncDir(dir)
				cleanedResult.DirectorySync = status
				if syncErr != nil {
					return cleanedResult, privateArtifactRollbackDurabilityError{err: errors.Join(
						cleanupErr,
						fmt.Errorf("sync restored private artifact directory: %w", syncErr),
					)}
				}
				return cleanedResult, cleanupErr
			}
			if artifactCleanup == privateArtifactCleanupNotRequired {
				return cleanup(fmt.Errorf("replace private artifact: %w", err), false)
			}
			return result, fmt.Errorf("replace private artifact: %w", err)
		}
		result.Replacement = privateArtifactReplacementComplete
	}
	status, err := ops.syncDir(dir)
	result.DirectorySync = status
	if err != nil {
		return result, privateArtifactPublishedError{err: fmt.Errorf("sync private artifact directory: %w", err)}
	}
	return result, nil
}

func writePrivateArtifactData(file io.Writer, data []byte) error {
	for len(data) > 0 {
		written, err := file.Write(data)
		if written < 0 || written > len(data) {
			return fmt.Errorf("invalid write count %d", written)
		}
		data = data[written:]
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
