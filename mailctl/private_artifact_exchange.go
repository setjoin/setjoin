//go:build linux || darwin

package main

import (
	"errors"
	"fmt"
	"os"
)

const privateArtifactReplaceExistingSupported = true

// replacePrivateArtifactExisting atomically exchanges the staged and current
// directory entries. The displaced entry remains named by tempPath until its
// identity is checked, so a target swapped after inspection is restored rather
// than overwritten or removed.
func replacePrivateArtifactExisting(tempPath, targetPath string, expected os.FileInfo) (bool, privateArtifactCleanup, bool, error) {
	if err := exchangePrivateArtifactNames(tempPath, targetPath); err != nil {
		return false, privateArtifactCleanupNotRequired, false, err
	}
	displaced, inspectErr := os.Lstat(tempPath)
	if inspectErr == nil && os.SameFile(expected, displaced) {
		if err := os.Remove(tempPath); err != nil {
			return true, privateArtifactCleanupFailed, true, fmt.Errorf("remove replaced private artifact: %w", err)
		}
		return true, privateArtifactCleanupComplete, true, nil
	}

	rollbackErr := exchangePrivateArtifactNames(tempPath, targetPath)
	if rollbackErr != nil {
		return true, privateArtifactCleanupFailed, true, errors.Join(
			fmt.Errorf("target identity changed during private artifact replacement"),
			inspectErr,
			fmt.Errorf("restore intervening target: %w", rollbackErr),
		)
	}
	if inspectErr != nil {
		return false, privateArtifactCleanupNotRequired, true, fmt.Errorf("inspect displaced private artifact: %w", inspectErr)
	}
	return false, privateArtifactCleanupNotRequired, true, fmt.Errorf("target identity changed during private artifact replacement")
}
