package vens

import (
	"net"
	"testing"
)

func TestClosePropagatesMissingEndScanAcknowledgement(t *testing.T) {
	client, server := net.Pipe()
	session := &ScanSession{conn: client}
	done := make(chan struct{})
	go func() { defer close(done); defer server.Close(); buffer := make([]byte, 4096); server.Read(buffer) }()
	if err := session.Close(); err == nil {
		t.Fatal("missing scanner ACK was reported as success")
	}
	<-done
}
