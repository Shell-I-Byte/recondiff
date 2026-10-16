//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
	"path/filepath"
)

// The non-Linux implementation retains the existing best-effort atomic
// replacement semantics; hostile path races require native OS qualification.
func writeAtomic(name string, b []byte) error {
	if name == "" {
		return errors.New("empty output path")
	}
	dir := filepath.Dir(name)
	f, err := os.CreateTemp(dir, ".recondiff-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, name)
}
