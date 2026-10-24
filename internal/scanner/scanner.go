package scanner

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/authz"
	"github.com/mzyy94/airscap/internal/vens"
)

// Scanner is a high-level interface for ScanSnap operations.
type Scanner struct {
	mu               sync.Mutex
	host             string
	dataPort         uint16
	controlPort      uint16
	token            [8]byte
	identity         string
	control          *vens.ControlSession
	heartbeat        *vens.Heartbeat
	connected        bool
	name             string
	serial           string
	deviceName       string           // full device name with manufacturer from TCP GET_SET sub=0x12
	firmwareRevision string           // firmware revision from device name suffix (e.g. "0M00")
	scanParams       *vens.ScanParams // capabilities from INQUIRY VPD 0xF0
	authorizer       authz.Authorizer // nil: every scan is refused
	// openSession sends the scan commands; tests replace it with a
	// simulated scanner. nil: the real data channel.
	openSession func(cfg vens.ScanConfig) (pageStream, error)
	wifiState   uint32 // last GET_WIFI_STATUS state (signal strength, 0 to 3)

	reconnCancel context.CancelFunc
	reconnDone   chan struct{}
}

// New creates a Scanner targeting the given host with a pre-computed identity.
func New(host string, dataPort, controlPort uint16, identity string) *Scanner {
	var token [8]byte
	rand.Read(token[:6])
	vens.RegisterToken(token)
	vens.RegisterSecret(identity)
	slog.Debug("scanner created", "host", host, "dataPort", dataPort, "controlPort", controlPort, "authentication", "configured")
	return &Scanner{
		host:        host,
		dataPort:    dataPort,
		controlPort: controlPort,
		token:       token,
		identity:    identity,
		control:     vens.NewControlSession(host, controlPort),
	}
}

// Online returns whether the scanner session is active (thread-safe).
func (s *Scanner) Online() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected
}

// Connect establishes a session with the scanner: discovery, heartbeat, configure, data setup.
func (s *Scanner) Connect(ctx context.Context) error {
	// Clean up any previous connection state (idempotent for reconnection)
	s.mu.Lock()
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
	s.mu.Unlock()

	// Step 1: UDP discovery to let the scanner know our token
	slog.Debug("discovery...", "host", s.host)
	info, err := vens.FindScanner(ctx, vens.DiscoveryOptions{
		ScannerIP: s.host,
		Token:     s.token,
	})
	if err != nil {
		return fmt.Errorf("discovery: %w", err)
	}
	slog.Debug("discovery OK", "name", info.Name, "serial", vens.RedactSerial(info.Serial), "ip", info.DeviceIP, "dataPort", info.DataPort, "controlPort", info.ControlPort)

	// Update ports from discovery response
	if info.DataPort != 0 {
		s.dataPort = info.DataPort
	}
	if info.ControlPort != 0 {
		s.controlPort = info.ControlPort
		s.control = vens.NewControlSession(s.host, s.controlPort)
	}

	// Step 2: Start heartbeats
	slog.Debug("starting heartbeat...")
	hb, err := vens.StartHeartbeat(ctx, s.host, s.token, 0)
	if err != nil {
		return fmt.Errorf("heartbeat: %w", err)
	}
	s.mu.Lock()
	s.heartbeat = hb
	s.mu.Unlock()
	time.Sleep(300 * time.Millisecond)

	// Step 3: Configure session
	slog.Debug("configuring session...")
	localIP := vens.GetLocalIP(s.host)
	accepted, err := s.control.Configure(s.token, localIP, vens.ClientNotifyPort, s.identity)
	if err != nil {
		hb.Stop()
		s.mu.Lock()
		s.heartbeat = nil
		s.mu.Unlock()
		return fmt.Errorf("configure: %w", err)
	}
	if !accepted {
		hb.Stop()
		s.mu.Lock()
		s.heartbeat = nil
		s.mu.Unlock()
		return fmt.Errorf("pairing rejected — wrong password/identity")
	}

	// Step 4: Data channel setup (with status check interleaved, matching Python flow)
	slog.Debug("data channel setup...", "host", s.host, "port", s.dataPort)
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	devInfo, err := dataCh.GetDeviceInfo()
	if err != nil {
		slog.Warn("get device info failed, retrying in 2s", "err", err)
		time.Sleep(2 * time.Second)
		devInfo, err = dataCh.GetDeviceInfo()
		if err != nil {
			hb.Stop()
			s.mu.Lock()
			s.heartbeat = nil
			s.mu.Unlock()
			return fmt.Errorf("device info: %w", err)
		}
	}

	// Step 5: Status check (between data channel operations, matching Python flow)
	slog.Debug("status check...")
	if wifiState, err := s.control.CheckStatus(s.token); err != nil {
		slog.Warn("status check failed", "err", err)
	} else {
		s.mu.Lock()
		s.wifiState = wifiState
		s.mu.Unlock()
	}

	scanParams, err := dataCh.GetScanParams()
	if err != nil {
		slog.Warn("get scan params failed", "err", err)
	}

	if _, err := dataCh.SetConfig(); err != nil {
		slog.Warn("set config failed", "err", err)
	}

	s.mu.Lock()
	s.connected = true
	s.name = info.Name
	vens.RegisterSecret(info.Serial)
	vens.RegisterSecret(vens.PasswordFromSerial(info.Serial))
	s.serial = info.Serial
	if devInfo != nil {
		s.deviceName = devInfo.DeviceName
		s.firmwareRevision = devInfo.FirmwareRevision
	}
	s.scanParams = scanParams
	s.mu.Unlock()
	slog.Info("connected to scanner", "host", s.host, "name", info.Name, "serial", vens.RedactSerial(info.Serial), "deviceName", s.deviceName)
	return nil
}

// pageStream is a running scan: vens.ScanSession or a simulated scanner.
type pageStream interface {
	NextPage() (vens.Page, error)
	Close() error
}

// SetAuthorizer sets who grants scans (ScanSnap Control). Without one every
// scan is refused.
func (s *Scanner) SetAuthorizer(a authz.Authorizer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizer = a
}

func (s *Scanner) currentAuthorizer() authz.Authorizer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.authorizer == nil {
		return authz.Deny{}
	}
	return s.authorizer
}

// StartScan is the only way to start a physical scan. It obtains a grant
// for source before sending the first scan command (the data channel's
// StartScan already feeds the first sheet); without one nothing is sent.
// Pages are pulled one at a time via AuthorizedSession.NextPage.
func (s *Scanner) StartScan(ctx context.Context, source authz.Source, cfg vens.ScanConfig) (*AuthorizedSession, error) {
	if !s.Online() {
		return nil, fmt.Errorf("scanner not connected")
	}
	grant, err := s.currentAuthorizer().Authorize(ctx, source)
	if err != nil {
		slog.Warn("scan refused", "source", source, "err", err)
		return nil, err
	}
	slog.Info("starting scan session", "source", source, "job", grant.JobID(), "mode", grant.Mode(),
		"colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex, "paperSize", cfg.PaperSize)

	open := s.openSession
	if open == nil {
		open = func(cfg vens.ScanConfig) (pageStream, error) {
			return vens.NewDataChannel(s.host, s.dataPort, s.token).StartScan(cfg)
		}
	}
	stream, err := open(cfg)
	if err != nil {
		grant.Finish(ctx, false)
		return nil, err
	}
	// The session outlives the request that started it: eSCL clients fetch
	// the pages with later requests, and go-mfp passes the context of the
	// ScanJobs request, which ends before the first page. The scan ends
	// with Close or a lost grant, not with that context.
	return &AuthorizedSession{ctx: context.WithoutCancel(ctx), inner: stream, grant: grant}, nil
}

// AuthorizedSession is a running scan with its grant. Before every page it
// confirms the grant with ScanSnap Control; if the session ended or expired
// the scan is stopped (EndScan) and ErrAuthorizationLost returned. Close
// ends the scan and reports the outcome: success only after the scanner
// signalled the end of the document.
type AuthorizedSession struct {
	ctx      context.Context
	inner    pageStream
	grant    authz.Grant
	mu       sync.Mutex
	complete bool
	failed   bool
	closed   bool
	closeErr error
}

// Grant returns the grant of this scan.
func (a *AuthorizedSession) Grant() authz.Grant { return a.grant }

// NextPage returns the next page or io.EOF.
func (a *AuthorizedSession) NextPage() (vens.Page, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return vens.Page{}, io.EOF
	}
	if err := a.grant.Activity(a.ctx); err != nil {
		a.failed = true
		a.closeLocked()
		slog.Warn("scan stopped: authorization lost", "job", a.grant.JobID(), "err", err)
		return vens.Page{}, fmt.Errorf("%w: %v", authz.ErrAuthorizationLost, err)
	}
	page, err := a.inner.NextPage()
	switch {
	case errors.Is(err, io.EOF):
		a.complete = true
	case err != nil:
		a.failed = true
	}
	return page, err
}

// Close ends the scan and releases the reservation (idempotent).
func (a *AuthorizedSession) Close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.closeLocked()
}

func (a *AuthorizedSession) closeLocked() error {
	if a.closed {
		return a.closeErr
	}
	a.closed = true
	err := a.inner.Close()
	success := a.complete && !a.failed && err == nil
	if ferr := a.grant.Finish(a.ctx, success); ferr != nil {
		slog.Warn("reservation release failed", "job", a.grant.JobID(), "err", ferr)
		err = errors.Join(err, ferr)
	}
	a.closeErr = err
	return err
}

// Scan executes an authorized scan and returns the pages.
func (s *Scanner) Scan(ctx context.Context, source authz.Source, cfg vens.ScanConfig, onPage func(vens.Page)) ([]vens.Page, error) {
	session, err := s.StartScan(ctx, source, cfg)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var pages []vens.Page
	for {
		page, err := session.NextPage()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			slog.Warn("scan error", "err", err, "pages_so_far", len(pages))
			return pages, err
		}
		pages = append(pages, page)
		if onPage != nil {
			onPage(page)
		}
	}
	// Filter out empty pages
	var result []vens.Page
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			result = append(result, p)
		}
	}
	slog.Info("scan complete", "total_pages", len(pages), "non_empty", len(result))
	return result, nil
}

// Disconnect deregisters from the scanner and stops heartbeat.
func (s *Scanner) Disconnect() {
	slog.Debug("disconnecting from scanner...")
	if s.control != nil {
		if err := s.control.Deregister(s.token); err != nil {
			slog.Warn("deregister failed", "err", err)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
	slog.Info("disconnected from scanner")
}

// markOffline stops the heartbeat and marks the scanner as disconnected.
func (s *Scanner) markOffline() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.connected {
		return
	}
	slog.Warn("scanner went offline", "host", s.host)
	if s.heartbeat != nil {
		s.heartbeat.Stop()
		s.heartbeat = nil
	}
	s.connected = false
}

// StartReconnectLoop starts a background goroutine that monitors scanner
// health and reconnects automatically when the connection is lost.
func (s *Scanner) StartReconnectLoop(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	s.reconnCancel = cancel
	s.reconnDone = make(chan struct{})
	go s.reconnectLoop(ctx)
}

// StopReconnectLoop stops the reconnection goroutine and waits for it to exit.
func (s *Scanner) StopReconnectLoop() {
	if s.reconnCancel != nil {
		s.reconnCancel()
		<-s.reconnDone
	}
}

func (s *Scanner) reconnectLoop(ctx context.Context) {
	defer close(s.reconnDone)

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.Online() {
				s.healthCheck()
			} else {
				s.tryReconnect(ctx)
			}
		}
	}
}

func (s *Scanner) healthCheck() {
	s.mu.Lock()
	ctrl := s.control
	token := s.token
	s.mu.Unlock()

	if ctrl == nil {
		s.markOffline()
		return
	}
	state, err := ctrl.CheckStatus(token)
	if err != nil {
		slog.Warn("health check failed", "err", err)
		s.markOffline()
		return
	}
	s.mu.Lock()
	s.wifiState = state
	s.mu.Unlock()
}

func (s *Scanner) tryReconnect(ctx context.Context) {
	slog.Info("attempting reconnection...", "host", s.host)
	if err := s.Connect(ctx); err != nil {
		slog.Debug("reconnect failed", "host", s.host, "err", err)
	}
}

// CheckSenseStatus probes the scanner for error conditions via REQUEST SENSE.
func (s *Scanner) CheckSenseStatus() *vens.ScanError {
	if !s.Online() {
		return nil
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.CheckSenseStatus()
}

// CheckADFStatus queries the scanner's ADF and returns paper/error status.
func (s *Scanner) CheckADFStatus() (*vens.ADFStatus, error) {
	if !s.Online() {
		return nil, fmt.Errorf("scanner not connected")
	}
	dataCh := vens.NewDataChannel(s.host, s.dataPort, s.token)
	return dataCh.CheckADFStatus()
}

// Host returns the scanner's IP address.
func (s *Scanner) Host() string { return s.host }

// Name returns the scanner's device name from discovery.
func (s *Scanner) Name() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.TrimSpace(s.name)
}

// DisplaySerial returns the serial number from discovery for display
// (Web UI, eSCL). The part that holds the default password is masked
// (vens.RedactSerial); the full serial is never handed out.
func (s *Scanner) DisplaySerial() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return vens.RedactSerial(s.serial)
}

// DeviceName returns the full device name from TCP GET_SET sub=0x12
func (s *Scanner) DeviceName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deviceName
}

// FirmwareRevision returns the firmware revision from the device name suffix.
func (s *Scanner) FirmwareRevision() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firmwareRevision
}

// ScanParams returns the scanner capabilities from INQUIRY VPD 0xF0.
func (s *Scanner) ScanParams() *vens.ScanParams {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scanParams
}

// WifiState returns the last known WiFi state from GET_WIFI_STATUS (signal strength, 0 to 3).
func (s *Scanner) WifiState() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wifiState
}

// MakeAndModel returns the device name (already stripped of firmware revision by ParseDataDeviceInfo).
// Falls back to the discovery name if the full device name is unavailable.
func (s *Scanner) MakeAndModel() string {
	s.mu.Lock()
	dn := s.deviceName
	name := strings.TrimSpace(s.name)
	s.mu.Unlock()
	if dn != "" {
		return dn
	}
	return name
}
