//go:build unix

package main

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO (or device) as token file would block AirScap at startup or feed
// it data from another process; only regular files are accepted.
func TestScanAuthorizerRejectsFIFO(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scanner.token")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Skip("mkfifo:", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := scanAuthorizer("http://127.0.0.1:18082", path)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted as token file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scanAuthorizer blocked on a FIFO token file")
	}
}
