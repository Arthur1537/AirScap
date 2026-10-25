// Package vensim simulates a ScanSnap iX500 on the VENS protocol for tests.
//
// It is a test tool: never part of the production image (the Dockerfile
// builds ./cmd/airscap only, see cmd/vensim for the stand-alone binary).
// It speaks the subset AirScap uses, with the real wire formats:
//
//   - UDP discovery/heartbeat on 52217, button notification to the
//     client's notify port (from the pairing request);
//   - TCP control channel 53219: welcome, register/deregister, pairing
//     with identity check, Wi-Fi status;
//   - TCP data channel 53218: INQUIRY, scan parameters, CONFIG, and a full
//     scan: settings, scan config, tone curve, prepare, GET_STATUS, WAIT,
//     chunked page transfer, REQUEST SENSE, END SCAN.
//
// Scanner states (paper, cover, jam, multi-feed, offline) and the end-of-
// document behaviours of review E (H0-H3) are set per Profile. Every data
// request is recorded by opcode so tests can pin the wire sequence.
package vensim

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// Terminal is the scanner's answer at the end of a document.
type Terminal string

const (
	TerminalClean        Terminal = "H0"               // no paper, no error, NO SENSE
	TerminalPending      Terminal = "H1"               // error field set until REQUEST SENSE (scan complete) is read
	TerminalUpperBits    Terminal = "H2"               // error field upper 16 bits set, in every status
	TerminalStateBits    Terminal = "H3"               // an undocumented state bit after the last sheet
	TerminalScanComplete Terminal = "H0-scan-complete" // clean status, sense MEDIUM ERROR 80/03
)

// Profile is the scanner state for the next scans.
type Profile struct {
	Sheets      int      // sheets in the feeder
	CoverOpen   bool     // ADF cover open
	JamAtSheet  int      // 1-based sheet whose transfer ends in a paper jam; 0 = none
	MultiFeedAt int      // 1-based sheet with a multi-feed; 0 = none
	Terminal    Terminal // end-of-document behaviour; "" = H0
	ChunkSize   int      // bytes per page chunk; 0 = what the client asks for
	PageWidth   int      // JPEG width in pixels; 0 = 320
}

// Config identifies the simulated scanner.
type Config struct {
	IP       string // address to listen on and to advertise, e.g. 127.0.0.2
	Password string // pairing password (identity is derived like the real scanner)
	Serial   string
	Name     string
}

// Simulator is a running simulated scanner.
type Simulator struct {
	cfg      Config
	identity string

	mu        sync.Mutex
	profile   Profile
	requests  []string
	client    *net.UDPAddr // notify target from the pairing request
	paired    bool
	online    bool
	discovery *net.UDPConn
	listeners []net.Listener
	wg        sync.WaitGroup
	cancel    context.CancelFunc
}

// Start begins listening on cfg.IP (discovery 52217, data 53218, control 53219).
func Start(ctx context.Context, cfg Config, profile Profile) (*Simulator, error) {
	if net.ParseIP(cfg.IP).To4() == nil {
		return nil, errors.New("vensim: IPv4 address required")
	}
	if cfg.Serial == "" {
		cfg.Serial = "iX500-SIM0001"
	}
	if cfg.Name == "" {
		cfg.Name = "iX500-SIM"
	}
	if cfg.Password == "" {
		cfg.Password = vens.PasswordFromSerial(cfg.Serial)
	}
	identity, err := vens.ComputeIdentity(cfg.Password)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &Simulator{cfg: cfg, identity: identity, profile: profile, cancel: cancel}
	if err := s.listen(ctx); err != nil {
		cancel()
		return nil, err
	}
	return s, nil
}

func (s *Simulator) listen(ctx context.Context) error {
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.IP), Port: vens.DiscoveryPort})
	if err != nil {
		return err
	}
	data, err := net.Listen("tcp4", net.JoinHostPort(s.cfg.IP, fmt.Sprint(vens.DefaultDataPort)))
	if err != nil {
		udp.Close()
		return err
	}
	control, err := net.Listen("tcp4", net.JoinHostPort(s.cfg.IP, fmt.Sprint(vens.DefaultControlPort)))
	if err != nil {
		udp.Close()
		data.Close()
		return err
	}
	s.mu.Lock()
	s.discovery, s.listeners, s.online = udp, []net.Listener{data, control}, true
	s.mu.Unlock()
	s.wg.Add(3)
	go s.serveDiscovery(ctx, udp)
	go s.accept(data, s.serveData)
	go s.accept(control, s.serveControl)
	return nil
}

// SetProfile changes the scanner state for the next requests.
func (s *Simulator) SetProfile(p Profile) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profile = p
}

// Requests returns the recorded data and control requests ("data:C2", "control:reserve", ...).
func (s *Simulator) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.requests...)
}

// Paired reports whether a client paired with the right identity.
func (s *Simulator) Paired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paired
}

func (s *Simulator) record(r string) {
	s.mu.Lock()
	s.requests = append(s.requests, r)
	s.mu.Unlock()
}

// PressButton sends the scan-button notification to the paired client.
func (s *Simulator) PressButton() error {
	s.mu.Lock()
	client, paired := s.client, s.paired
	s.mu.Unlock()
	if !paired || client == nil {
		return errors.New("vensim: no paired client")
	}
	conn, err := net.DialUDP("udp4", &net.UDPAddr{IP: net.ParseIP(s.cfg.IP)}, client)
	if err != nil {
		return err
	}
	defer conn.Close()
	p := make([]byte, 48)
	copy(p[4:8], vens.Magic[:])
	binary.BigEndian.PutUint32(p[8:12], 1)
	binary.BigEndian.PutUint32(p[16:20], 0x02000000)
	_, err = conn.Write(p)
	return err
}

// GoOffline closes every listener (the scanner disappears from the network).
func (s *Simulator) GoOffline() {
	s.mu.Lock()
	listeners, udp := s.listeners, s.discovery
	s.listeners, s.discovery, s.online, s.paired = nil, nil, false, false
	s.mu.Unlock()
	for _, l := range listeners {
		l.Close()
	}
	if udp != nil {
		udp.Close()
	}
}

// GoOnline listens again after GoOffline.
func (s *Simulator) GoOnline(ctx context.Context) error {
	s.mu.Lock()
	online := s.online
	s.mu.Unlock()
	if online {
		return nil
	}
	return s.listen(ctx)
}

// Close stops the simulator.
func (s *Simulator) Close() {
	s.cancel()
	s.GoOffline()
	s.wg.Wait()
}

func (s *Simulator) accept(l net.Listener, serve func(net.Conn)) {
	defer s.wg.Done()
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(2 * time.Minute))
			serve(conn)
		}()
	}
}

// ---------------------------------------------------------------- UDP

func (s *Simulator) serveDiscovery(ctx context.Context, conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 256)
	for ctx.Err() == nil {
		n, remote, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 32 || [4]byte(buf[0:4]) != vens.Magic {
			continue // ssNR companion packets and noise
		}
		if binary.BigEndian.Uint32(buf[4:8]) == 1 {
			continue // heartbeat
		}
		s.record("udp:discovery")
		clientIP := net.IP(append([]byte(nil), buf[8:12]...))
		port := binary.BigEndian.Uint16(buf[22:24])
		reply := s.deviceInfo(clientIP)
		conn.WriteToUDP(reply, &net.UDPAddr{IP: clientIP, Port: int(port)})
		_ = remote
	}
}

func (s *Simulator) deviceInfo(clientIP net.IP) []byte {
	p := make([]byte, 132)
	copy(p[0:4], vens.Magic[:])
	if s.Paired() {
		binary.BigEndian.PutUint16(p[4:6], 1)
	}
	copy(p[16:20], net.ParseIP(s.cfg.IP).To4())
	binary.BigEndian.PutUint16(p[22:24], vens.DefaultDataPort)
	binary.BigEndian.PutUint16(p[26:28], vens.DefaultControlPort)
	copy(p[28:34], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(p[40:104], s.cfg.Serial)
	copy(p[104:120], s.cfg.Name)
	copy(p[120:124], clientIP.To4())
	return p
}

// ---------------------------------------------------------------- control channel

func welcome() []byte {
	p := make([]byte, vens.WelcomeSize)
	binary.BigEndian.PutUint32(p[0:4], vens.WelcomeSize)
	copy(p[4:8], vens.Magic[:])
	return p
}

func readPacket(conn net.Conn) ([]byte, error) {
	var size [4]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(size[:])
	if n < 8 || n > 1<<20 {
		return nil, fmt.Errorf("vensim: bad request size %d", n)
	}
	p := make([]byte, n)
	copy(p, size[:])
	_, err := io.ReadFull(conn, p[4:])
	return p, err
}

func response(size int) []byte {
	p := make([]byte, size)
	binary.BigEndian.PutUint32(p[0:4], uint32(size))
	copy(p[4:8], vens.Magic[:])
	return p
}

func (s *Simulator) serveControl(conn net.Conn) {
	if _, err := conn.Write(welcome()); err != nil {
		return
	}
	for {
		req, err := readPacket(conn)
		if err != nil || len(req) < 24 {
			return
		}
		switch binary.BigEndian.Uint32(req[8:12]) {
		case vens.CmdRelease:
			s.record("control:release")
			ack := make([]byte, 16)
			copy(ack[4:8], vens.Magic[:])
			conn.Write(ack)
		case vens.CmdReserve:
			s.record("control:reserve")
			r := response(20)
			if len(req) < 100 || strings.TrimRight(string(req[52:100]), "\x00") != s.identity {
				binary.BigEndian.PutUint32(r[8:12], 1) // pairing rejected
			} else {
				ip := net.IP(append([]byte(nil), req[44:48]...))
				port := int(binary.BigEndian.Uint16(req[50:52]))
				s.mu.Lock()
				s.client, s.paired = &net.UDPAddr{IP: ip, Port: port}, true
				s.mu.Unlock()
			}
			conn.Write(r)
		case vens.CmdGetWifiStatus:
			s.record("control:status")
			r := response(32)
			binary.BigEndian.PutUint32(r[16:20], 1)
			conn.Write(r)
		default:
			s.record(fmt.Sprintf("control:0x%X", binary.BigEndian.Uint32(req[8:12])))
			return
		}
	}
}

// ---------------------------------------------------------------- data channel

// session is the scanner side of one data-channel connection.
type session struct {
	profile    Profile
	started    bool // first WAIT answered "scan started"
	fed        int  // sheets fed (WAIT answered 0)
	transfers  int  // sides transferred of the current sheet
	terminal   bool // WAIT answered 2 after the last sheet
	senseAfter bool // REQUEST SENSE read after the terminal WAIT
	jammed     bool
	pending    *[3]byte // sense to report next (key, asc, ascq)
}

func (s *Simulator) serveData(conn net.Conn) {
	if _, err := conn.Write(welcome()); err != nil {
		return
	}
	s.mu.Lock()
	st := &session{profile: s.profile}
	s.mu.Unlock()
	for {
		req, err := readPacket(conn)
		if err != nil || len(req) < 49 {
			return
		}
		command := binary.BigEndian.Uint32(req[32:36])
		op := req[48]
		s.record(fmt.Sprintf("data:%02X", op))
		var reply []byte
		switch {
		case command == vens.CmdPageTransfer && op == vens.SCSIOpcodeRead10:
			if err := s.transfer(conn, st, req); err != nil {
				return
			}
			continue
		case op == vens.SCSIOpcodeInquiry && len(req) > 50 && req[49]&0x01 != 0:
			reply = scanParams()
		case op == vens.SCSIOpcodeInquiry:
			reply = inquiry()
		case op == 0xC2:
			reply = st.status()
		case op == 0xE0:
			reply = st.wait()
		case op == vens.SCSIOpcodeRequestSense:
			reply = st.sense()
		default: // D8 settings, D4 config, DB tone curve, D5 prepare, D6 end, EB config
			reply = response(40)
		}
		if _, err := conn.Write(reply); err != nil {
			return
		}
		if op == 0xD6 {
			return
		}
	}
}

func inquiry() []byte {
	r := response(136)
	copy(r[48:81], "FUJITSU ScanSnap iX500  0M00")
	return r
}

func scanParams() []byte {
	r := response(184)
	r[40], r[41] = 0x06, 0xF0
	binary.BigEndian.PutUint16(r[45:47], 600)
	binary.BigEndian.PutUint16(r[47:49], 600)
	r[49] = 0x07
	binary.BigEndian.PutUint16(r[54:56], 150)
	binary.BigEndian.PutUint16(r[56:58], 150)
	binary.BigEndian.PutUint16(r[62:64], 5100)
	binary.BigEndian.PutUint16(r[66:68], 7020)
	return r
}

func (st *session) remaining() int { return st.profile.Sheets - st.fed }

func (st *session) status() []byte {
	r := response(72)
	var state, errorField uint32
	switch {
	case !st.started && st.profile.Sheets == 0, st.started && st.remaining() == 0 && !st.terminal:
		state = vens.ADFPaperMask
	case st.terminal:
		state = vens.ADFPaperMask
	}
	if st.profile.CoverOpen {
		state |= vens.ADFCoverOpenMask
	}
	if st.profile.Terminal == TerminalUpperBits {
		errorField = 0x00010000
	}
	if st.terminal {
		switch st.profile.Terminal {
		case TerminalPending:
			if !st.senseAfter {
				errorField = 0x00000003
			}
		case TerminalStateBits:
			state |= 0x00000001
		}
	}
	binary.BigEndian.PutUint32(r[40:44], state)
	binary.BigEndian.PutUint32(r[44:48], errorField)
	return r
}

func (st *session) wait() []byte {
	r := response(40)
	switch {
	case !st.started && st.profile.Sheets > 0 && !st.profile.CoverOpen:
		st.started, st.fed, st.transfers = true, 1, 0
	case st.started && st.remaining() > 0 && !st.jammed:
		st.fed++
		st.transfers = 0
	default:
		if st.started {
			st.terminal = true
		}
		binary.BigEndian.PutUint32(r[12:16], 2)
	}
	return r
}

func (st *session) sense() []byte {
	r := response(58)
	r[40] = 0x70
	r[47] = 10
	switch {
	case st.pending != nil:
		r[42], r[52], r[53] = st.pending[0], st.pending[1], st.pending[2]
		st.pending = nil
	case st.terminal:
		st.senseAfter = true
		if st.profile.Terminal == TerminalPending || st.profile.Terminal == TerminalScanComplete {
			r[42], r[52], r[53] = vens.SenseKeyMediumError, vens.VendorASC, vens.ASCQScanComplete
		}
	}
	return r
}

// transfer answers one chunk request with a page header and JPEG data.
func (s *Simulator) transfer(conn net.Conn, st *session, req []byte) error {
	cdb := req[48:60]
	sheet, chunk, back := int(cdb[10]), int(cdb[11]), cdb[5]&0x80 != 0
	want := int(cdb[6])<<16 | int(cdb[7])<<8 | int(cdb[8])
	if st.profile.ChunkSize > 0 {
		want = st.profile.ChunkSize
	}
	if st.fed == 0 || (st.profile.JamAtSheet != 0 && st.fed == st.profile.JamAtSheet && st.transfers > 0) {
		_, err := conn.Write(response(40)) // short answer: transfer error
		return err
	}
	page := s.page(st.fed, back)
	start := chunk * want
	if start > len(page) {
		start = len(page)
	}
	end := min(start+want, len(page))
	header := make([]byte, vens.PageHeaderSize)
	binary.BigEndian.PutUint32(header[0:4], uint32(vens.PageHeaderSize+end-start))
	copy(header[4:8], vens.Magic[:])
	if end == len(page) {
		binary.BigEndian.PutUint32(header[12:16], vens.PageTypeFinal)
		st.transfers++
		switch {
		case st.profile.JamAtSheet == st.fed:
			st.pending, st.jammed = &[3]byte{vens.SenseKeyMediumError, vens.VendorASC, vens.ASCQPaperJam}, true
		case st.profile.MultiFeedAt == st.fed:
			st.pending, st.jammed = &[3]byte{vens.SenseKeyMediumError, vens.VendorASC, vens.ASCQMultiFeed}, true
		}
	}
	header[40], header[41] = byte(sheet), 0
	if back {
		header[41] = 1
	}
	if _, err := conn.Write(header); err != nil {
		return err
	}
	_, err := conn.Write(page[start:end])
	return err
}

// page renders a small, valid JPEG that names its sheet and side.
func (s *Simulator) page(sheet int, back bool) []byte {
	s.mu.Lock()
	width := s.profile.PageWidth
	s.mu.Unlock()
	if width == 0 {
		width = 320
	}
	height := width * 297 / 210
	img := image.NewGray(image.Rect(0, 0, width, height))
	shade := uint8(230)
	if back {
		shade = 200
	}
	for y := 0; y < height; y++ {
		for x := 0; x < width; x++ {
			v := shade
			if (x/8+y/8+sheet)%7 == 0 {
				v = 40 // a pattern that differs per sheet
			}
			img.SetGray(x, y, color.Gray{Y: v})
		}
	}
	var buf bytes.Buffer
	jpeg.Encode(&buf, img, &jpeg.Options{Quality: 70})
	return buf.Bytes()
}
