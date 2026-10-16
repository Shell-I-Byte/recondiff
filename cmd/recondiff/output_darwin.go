//go:build darwin

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// writeAtomic pins the output directory to a directory file descriptor.
// Every temporary-file creation, rename and cleanup uses that descriptor so
// replacing any pathname component with a symlink cannot redirect data
// through path resolution. Privileged mount changes and an already-open
// directory being moved after resolution remain separate trust boundaries.
func writeAtomic(name string, b []byte) error {
	if name == "" {
		return errors.New("empty output path")
	}
	// Validate the *original* name: filepath.Dir and filepath.Clean erase
	// literal parent components before they can be rejected.
	if strings.HasSuffix(name, "/") {
		return errors.New("output filename must not end in slash")
	}
	for _, part := range strings.Split(name, "/") {
		if part == ".." {
			return errors.New("parent directory component is forbidden")
		}
	}
	dir, base := filepath.Dir(name), filepath.Base(name)
	if base == "." || base == ".." || base == "/" {
		return errors.New("invalid output filename")
	}
	fd, err := openSecureOutputDir(dir)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	// Deliberately do NOT re-open or resolve dir by pathname after this point.
	// Creation excludes preexisting symlinks/hardlinks and runs only under fd.
	var nonce [16]byte
	var tmp string
	var tf *os.File
	for attempt := 0; attempt < 8; attempt++ {
		if _, err = rand.Read(nonce[:]); err != nil {
			return err
		}
		tmp = ".recondiff-" + hex.EncodeToString(nonce[:]) + ".tmp"
		var tempfd int
		tempfd, err = unix.Openat(fd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
		if err == unix.EEXIST {
			continue
		}
		if err != nil {
			return err
		}
		tf = os.NewFile(uintptr(tempfd), "private-output-temp")
		if tf == nil {
			unix.Close(tempfd)
			return errors.New("cannot wrap temporary output descriptor")
		}
		break
	}
	if tf == nil {
		return errors.New("cannot create unique temporary output")
	}
	defer unix.Unlinkat(fd, tmp, 0)
	if _, err = tf.Write(b); err != nil {
		tf.Close()
		return err
	}
	if err = tf.Sync(); err != nil {
		tf.Close()
		return err
	}
	if err = tf.Close(); err != nil {
		return err
	}
	if err = unix.Renameat(fd, tmp, fd, base); err != nil {
		return err
	}
	// Durability requires syncing the directory entry after the atomic rename.
	return unix.Fsync(fd)
}

// openSecureOutputDir walks every parent component relative to a pinned
// descriptor, refusing symlinks at every level. Unlike a single O_NOFOLLOW
// applied to the whole pathname, this also protects ancestor components.
// Caller owns the returned descriptor and must close it.
func openSecureOutputDir(dir string) (int, error) {
	start := "."
	if filepath.IsAbs(dir) {
		start = "/"
	}
	fd, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(dir, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			unix.Close(fd)
			return -1, errors.New("parent directory component is forbidden")
		}
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if openErr != nil {
			unix.Close(fd)
			return -1, openErr
		}
		unix.Close(fd)
		fd = next
	}
	return fd, nil
}
