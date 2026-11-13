//go:build !linux && !darwin && !windows

package main

import (
	"fmt"
	"os"
)

const privateArtifactReplaceExistingSupported = false

func replacePrivateArtifactExisting(string, string, os.FileInfo) (bool, privateArtifactCleanup, bool, error) {
	return false, privateArtifactCleanupNotRequired, false, fmt.Errorf("atomic guarded replacement is unsupported on this platform")
}
