package vens

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"github.com/mzyy94/airscap/internal/testlock"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeControlServer simulates the scanner's TCP control channel on
// 127.0.0.1: welcome packet, then one request per connection. It records
// the requests so the test can check their bytes never reach the log.
type fakeControlServer struct {
	listener net.Listener
	mu       sync.Mutex
	requests [][]byte
	wg       sync.WaitGroup
}

func newFakeControlServer(t *testing.T) *fakeControlServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeControlServer{listener: listener}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() {
		listener.Close()
		s.wg.Wait()
	})
	return s
}

func (s *fakeControlServer) port() uint16 {
	return uint16(s.listener.Addr().(*net.TCPAddr).Port)
}

func (s *fakeControlServer) serve() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		s.handle(conn)
	}
}

func (s *fakeControlServer) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	welcome := make([]byte, WelcomeSize)
	binary.BigEndian.PutUint32(welcome[0:4], WelcomeSize)
	copy(welcome[4:8], Magic[:])
	conn.Write(welcome)

	head := make([]byte, 12)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	size := binary.BigEndian.Uint32(head[0:4])
	request := append(head, make([]byte, size-12)...)
	if _, err := io.ReadFull(conn, request[12:]); err != nil {
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, request)
	s.mu.Unlock()

	var response []byte
	switch binary.BigEndian.Uint32(head[8:12]) {
	case CmdRelease:
		response = make([]byte, 16) // fixed ack, not length-prefixed
	case CmdReserve:
		response = make([]byte, 20) // status 0 at [8:12]: accepted
		binary.BigEndian.PutUint32(response[0:4], 20)
	default:
		response = make([]byte, 32)
		binary.BigEndian.PutUint32(response[0:4], 32)
		binary.BigEndian.PutUint32(response[16:20], 3)
	}
	// Echo the token, as the real scanner's responses may contain it.
	copy(response[min(16, len(response)-8):], request[16:24])
	conn.Write(response)
}

func TestControlSessionLogsNoSecretsAtDebug(t *testing.T) {
	server := newFakeControlServer(t)
	buf := captureLogs(t)
	identity := testIdentity(t)
	session := NewControlSession("127.0.0.1", server.port())

	if err := session.Register(testToken); err != nil {
		t.Fatalf("Register: %v", err)
	}
	accepted, err := session.Configure(testToken, "192.168.0.238", ClientNotifyPort, identity)
	if err != nil || !accepted {
		t.Fatalf("Configure: accepted=%v err=%v", accepted, err)
	}
	if _, err := session.CheckStatus(testToken); err != nil {
		t.Fatalf("CheckStatus: %v", err)
	}
	if err := session.Deregister(testToken); err != nil {
		t.Fatalf("Deregister: %v", err)
	}

	out := buf.String()
	assertNoSecrets(t, out, secretForms(t))
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.requests) != 4 {
		t.Fatalf("requests = %d, want 4", len(server.requests))
	}
	for _, request := range server.requests {
		// Neither the whole packet nor its token part, as hex or as the
		// escaped raw bytes a TextHandler writes for a string.
		raw := strings.Trim(strconv.Quote(string(request[16:22])), `"`)
		if strings.Contains(out, hex.EncodeToString(request)) ||
			strings.Contains(out, hex.EncodeToString(request[16:24])) ||
			strings.Contains(out, raw) {
			t.Errorf("raw request in log: %x", request)
		}
	}
	// Diagnosis stays possible from non-sensitive metadata.
	for _, want := range []string{"packet.bytes=384", "packet.magic=VENS", "pairing accepted"} {
		if !strings.Contains(out, want) {
			t.Errorf("metadata %q missing:\n%s", want, out)
		}
	}
}

// fakeDiscoveryScanner answers VENS discovery on 127.0.0.1 with a device
// info packet that carries the test serial.
func fakeDiscoveryScanner(t *testing.T) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: DiscoveryPort})
	if err != nil {
		t.Skipf("discovery port %d unavailable: %v", DiscoveryPort, err)
	}
	t.Cleanup(func() { conn.Close() })

	info := make([]byte, 132)
	copy(info[0:4], Magic[:])
	copy(info[16:20], []byte{127, 0, 0, 1})
	binary.BigEndian.PutUint16(info[22:24], DefaultDataPort)
	binary.BigEndian.PutUint16(info[26:28], DefaultControlPort)
	copy(info[40:104], testSerial+"\x00")
	copy(info[104:120], "ScanSnap iX500\x00")

	go func() {
		buf := make([]byte, 512)
		for {
			_, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("fake discovery: %v", err)
				}
				return
			}
			conn.WriteToUDP(info, addr)
		}
	}()
}

func TestFindScannerLogsNoSerial(t *testing.T) {
	testlock.VENSPorts(t) // fixed client port, shared with internal/scanner
	fakeDiscoveryScanner(t)
	buf := captureLogs(t)

	info, err := FindScanner(t.Context(), DiscoveryOptions{
		ScannerIP: "127.0.0.1", Token: testToken, Timeout: 5 * time.Second,
	})
	if err != nil {
		if strings.Contains(err.Error(), "bind discovery port") {
			t.Skipf("client discovery port unavailable: %v", err)
		}
		t.Fatalf("FindScanner: %v", err)
	}
	if info.Serial != testSerial {
		t.Fatalf("Serial = %q, want %q", info.Serial, testSerial)
	}

	out := buf.String()
	assertNoSecrets(t, out, secretForms(t))
	if !strings.Contains(out, "serial=iX500-****") {
		t.Errorf("redacted serial missing:\n%s", out)
	}
}
