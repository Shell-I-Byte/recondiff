//go:build !linux && !darwin

package main

import (
	"errors"
	"os"
)

var errInputNotRegular = errors.New("input must be a regular file")

// Portable fallback: preflight rejects directly provided special files but
// concurrent pathname swaps are NOT proven safe on these platforms.
func openRegularInput(path string) (*os.File, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errInputNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	st, err = f.Stat()
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
