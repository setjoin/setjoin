//go:build windows

package main

import (
	"fmt"
	"os"
)

const privateArtifactReplaceExistingSupported = false

func replacePrivateArtifactExisting(string, string, os.FileInfo) (bool, privateArtifactCleanup, bool, error) {
	return false, privateArtifactCleanupNotRequired, false, fmt.Errorf("atomic guarded replacement is unsupported on this platform")
}

func syncPrivateArtifactDirectory(string) (privateArtifactDirectorySync, error) {
	// Go/Windows does not expose a portable directory-handle fsync contract.
	// The file itself is synced; callers receive the explicit capability result.
	return privateArtifactDirectorySyncUnsupported, nil
}
