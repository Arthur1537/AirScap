package scanner

import (
	"net"
	"testing"
	"time"
)

func TestButtonOriginTypeAndReplayPolicy(t *testing.T) {
	b := NewButtonListener("192.0.2.10", nil)
	now := time.Now()
	if b.acceptEvent(&net.UDPAddr{IP: net.ParseIP("192.0.2.11")}, 1, 0x02000000, now) {
		t.Fatal("foreign scanner")
	}
	src := &net.UDPAddr{IP: net.ParseIP("192.0.2.10")}
	if b.acceptEvent(src, 2, 0x02000000, now) || b.acceptEvent(src, 1, 0, now) {
		t.Fatal("not a button event")
	}
	if !b.acceptEvent(src, 1, 0x02000000, now) {
		t.Fatal("documented button event")
	}
	if b.acceptEvent(src, 1, 0x02000000, now.Add(time.Second)) {
		t.Fatal("duplicate notification")
	}
	if !b.acceptEvent(src, 1, 0x02000000, now.Add(3*time.Second)) {
		t.Fatal("new event")
	}
	for i := 1; i <= 12; i++ {
		if b.acceptEvent(src, 1, 0x02000000, now.Add(3*time.Second+time.Duration(i)*500*time.Millisecond)) {
			t.Fatal("repeated notification burst")
		}
	}
	if !b.acceptEvent(src, 1, 0x02000000, now.Add(12*time.Second)) {
		t.Fatal("new event after quiet period")
	}

}
