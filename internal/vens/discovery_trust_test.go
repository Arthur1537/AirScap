package vens

import (
	"encoding/binary"
	"github.com/mzyy94/airscap/internal/testlock"
	"net"
	"strings"
	"testing"
	"time"
)

func deviceInfoPacket(deviceIP net.IP, dataPort uint16, name string) []byte {
	info := make([]byte, 132)
	copy(info[0:4], Magic[:])
	copy(info[16:20], deviceIP.To4())
	binary.BigEndian.PutUint16(info[22:24], dataPort)
	binary.BigEndian.PutUint16(info[26:28], DefaultControlPort)
	copy(info[40:104], testSerial+"\x00")
	copy(info[104:120], name+"\x00")
	return info
}

// A host other than the configured scanner floods forged discovery replies
// (also claiming the scanner's IP); the scanner itself first sends a reply
// describing another device, then its genuine one, late.
func TestFindScannerIgnoresForgedReplies(t *testing.T) {
	testlock.VENSPorts(t) // fixed client port, shared with internal/scanner
	scanner, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: DiscoveryPort})
	if err != nil {
		t.Skipf("discovery port %d unavailable: %v", DiscoveryPort, err)
	}
	defer scanner.Close()
	spoofer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Skipf("second loopback address unavailable: %v", err)
	}
	defer spoofer.Close()

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: ClientDiscoveryPort}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		forged := deviceInfoPacket(net.IPv4(127, 0, 0, 1), 1, "Forged")
		for {
			select {
			case <-stop:
				return
			case <-time.After(10 * time.Millisecond):
				spoofer.WriteToUDP(forged, client)
			}
		}
	}()
	go func() {
		buf := make([]byte, 512)
		_, addr, err := scanner.ReadFromUDP(buf)
		if err != nil {
			return
		}
		time.Sleep(200 * time.Millisecond) // the forgeries arrive first
		scanner.WriteToUDP(deviceInfoPacket(net.IPv4(10, 9, 9, 9), 2, "Other"), addr)
		scanner.WriteToUDP(deviceInfoPacket(net.IPv4(127, 0, 0, 1), DefaultDataPort, "ScanSnap iX500"), addr)
	}()

	info, err := FindScanner(t.Context(), DiscoveryOptions{
		ScannerIP: "127.0.0.1", Token: testToken, Timeout: 5 * time.Second,
	})
	if err != nil {
		if strings.Contains(err.Error(), "bind discovery port") {
			t.Skipf("client discovery port unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if info.Name != "ScanSnap iX500" || info.DataPort != DefaultDataPort || info.DeviceIP != "127.0.0.1" {
		t.Fatalf("accepted forged reply: %+v", info)
	}
}

func TestAcceptReply(t *testing.T) {
	genuine := &DeviceInfo{DeviceIP: "192.168.0.210"}
	from := func(ip string) *net.UDPAddr { return &net.UDPAddr{IP: net.ParseIP(ip), Port: DiscoveryPort} }
	for _, tc := range []struct {
		scanner string
		remote  *net.UDPAddr
		info    *DeviceInfo
		want    bool
	}{
		{"192.168.0.210", from("192.168.0.210"), genuine, true},
		{"192.168.0.210", from("192.168.0.99"), genuine, false},                                // other host
		{"192.168.0.210", from("192.168.0.210"), &DeviceInfo{DeviceIP: "192.168.0.99"}, false}, // redirect
		{"192.168.0.210", nil, genuine, false},
		{"not-an-ip", from("192.168.0.210"), genuine, false},
	} {
		if got := acceptReply(tc.scanner, tc.remote, tc.info); got != tc.want {
			t.Errorf("acceptReply(%q, %v, %s) = %v", tc.scanner, tc.remote, tc.info.DeviceIP, got)
		}
	}
}
