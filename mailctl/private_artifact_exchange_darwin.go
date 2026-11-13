//go:build darwin

package main

import "golang.org/x/sys/unix"

func exchangePrivateArtifactNames(first, second string) error {
	return unix.RenamexNp(first, second, unix.RENAME_SWAP)
}
