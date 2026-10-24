package main

import "testing"

func TestHTTPListenDefaultsToLoopbackWithoutMDNS(t *testing.T) {
	for _, tc := range []struct {
		address   string
		addr      string
		advertise bool
	}{
		{"", "127.0.0.1:8080", false},
		{"127.0.0.1", "127.0.0.1:8080", false},
		{"::1", "[::1]:8080", false},
		{"192.168.0.238", "192.168.0.238:8080", true},
		{"0.0.0.0", "0.0.0.0:8080", true},
	} {
		addr, advertise, err := httpListen(tc.address, 8080)
		if err != nil || addr != tc.addr || advertise != tc.advertise {
			t.Errorf("%q: %q %v %v", tc.address, addr, advertise, err)
		}
	}
	for _, bad := range []string{"qnap.local", "localhost", "1.2.3"} {
		if _, _, err := httpListen(bad, 8080); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, err := httpListen("", 0); err == nil {
		t.Error("port 0 accepted")
	}
}
