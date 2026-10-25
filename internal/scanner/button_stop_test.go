package scanner

import (
	"context"
	"testing"
	"time"

	"github.com/mzyy94/airscap/internal/testlock"
)

// Stop must return also while the context is still alive (it closes the
// socket; the read loop used to retry forever on the closed socket).
func TestButtonListenerStopsBeforeContextEnds(t *testing.T) {
	testlock.VENSPorts(t)
	listener := NewButtonListener("127.0.0.2", func() {})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := listener.Start(ctx); err != nil {
		t.Skipf("notify port busy: %v", err)
	}
	stopped := make(chan struct{})
	go func() { listener.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not return")
	}
}
