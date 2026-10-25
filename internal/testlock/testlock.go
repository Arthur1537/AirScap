// Package testlock serializes tests of different packages that bind the
// fixed VENS client ports (55264 discovery, 55265 notify). `go test ./...`
// runs packages in parallel processes; an advisory file lock keeps them
// from stealing each other's port. Test-only; never imported by commands.
package testlock

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// VENSPorts holds the lock until the test (and its cleanups) end.
func VENSPorts(t testing.TB) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(os.TempDir(), "airscap-vens-ports.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("test lock: %v", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		t.Fatalf("test lock: %v", err)
	}
	t.Cleanup(func() {
		unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	})
}
