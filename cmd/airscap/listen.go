package main

import (
	"fmt"
	"net"
	"strconv"
)

// httpListen resolves AIRSCAP_LISTEN_ADDR (an IP literal). The fork listens
// on loopback by default: eSCL scans are disabled, and the Web UI has no
// authentication. Only a non-loopback address is advertised via mDNS.
func httpListen(address string, port int) (addr string, advertise bool, err error) {
	if address == "" {
		address = "127.0.0.1"
	}
	ip := net.ParseIP(address)
	if ip == nil || port <= 0 || port > 65535 {
		return "", false, fmt.Errorf("AIRSCAP_LISTEN_ADDR must be an IP address and the port valid")
	}
	return net.JoinHostPort(ip.String(), strconv.Itoa(port)), !ip.IsLoopback(), nil
}
