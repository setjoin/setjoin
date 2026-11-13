//go:build !windows

package main

import (
	"errors"
	"os"
)

func syncPrivateArtifactDirectory(path string) (privateArtifactDirectorySync, error) {
	dir, err := os.Open(path)
	if err != nil {
		return privateArtifactDirectorySyncFailed, err
	}
	if err := dir.Sync(); err != nil {
		return privateArtifactDirectorySyncFailed, errors.Join(err, dir.Close())
	}
	if err := dir.Close(); err != nil {
		return privateArtifactDirectorySyncFailed, err
	}
	return privateArtifactDirectorySyncComplete, nil
}
