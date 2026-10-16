//go:build linux

package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
	defer syscall.Close(fd)
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
		tempfd, err = syscall.Openat(fd, tmp, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
		if err == syscall.EEXIST {
			continue
		}
		if err != nil {
			return err
		}
		tf = os.NewFile(uintptr(tempfd), "private-output-temp")
		if tf == nil {
			syscall.Close(tempfd)
			return errors.New("cannot wrap temporary output descriptor")
		}
		break
	}
	if tf == nil {
		return errors.New("cannot create unique temporary output")
	}
	defer syscall.Unlinkat(fd, tmp)
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
	if err = syscall.Renameat(fd, tmp, fd, base); err != nil {
		return err
	}
	// Durability requires syncing the directory entry after the atomic rename.
	return syscall.Fsync(fd)
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
	fd, err := syscall.Open(start, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	for _, part := range strings.Split(dir, "/") {
		if part == "" || part == "." {
			continue
		}
		if part == ".." {
			syscall.Close(fd)
			return -1, errors.New("parent directory component is forbidden")
		}
		next, openErr := syscall.Openat(fd, part, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			syscall.Close(fd)
			return -1, openErr
		}
		syscall.Close(fd)
		fd = next
	}
	return fd, nil
}
