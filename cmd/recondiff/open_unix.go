//go:build linux || darwin

package main

import (
	"errors"
	"os"
	"syscall"
)

var errInputNotRegular = errors.New("input must be a regular file")

// openRegularInput is nonblocking at open(2), even if an attacker swaps a
// regular pathname for a FIFO after any pathname-based preliminary check.
// The descriptor (not the pathname) is inspected before reading. Ordinary
// symlinks to regular files remain accepted; directory traversal protections
// and authentication of the enclosing workspace are outside this contract.
func openRegularInput(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	if f == nil {
		syscall.Close(fd)
		return nil, errors.New("cannot wrap opened descriptor")
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() {
		f.Close()
		return nil, errInputNotRegular
	}
	return f, nil
}
