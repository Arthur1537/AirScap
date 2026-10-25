package vens

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"
)

// ScanErrorKind classifies scanner errors.
type ScanErrorKind int

const (
	ScanErrGeneric   ScanErrorKind = iota // Unknown/generic scanner error
	ScanErrNoPaper                        // No paper in ADF
	ScanErrPaperJam                       // Paper jam
	ScanErrMultiFeed                      // Multi-feed (double feed) detected
	ScanErrCoverOpen                      // ADF cover open
)

// ErrorCodeToKind maps GET_STATUS error codes (offset 44, lower 16 bits) to ScanErrorKind.
func ErrorCodeToKind(code uint16) ScanErrorKind {
	switch code {
	case ErrorCodeMultiFeed:
		return ScanErrMultiFeed
	default:
		return ScanErrGeneric
	}
}

// ScanError indicates a scanner-level error (no paper, hardware failure, etc.).
type ScanError struct {
	Kind ScanErrorKind
	Msg  string
}

func (e *ScanError) Error() string { return e.Msg }

// Page holds a single scanned page image.
type Page struct {
	Sheet     int            // Physical sheet index (0-based)
	Side      int            // 0=front, 1=back
	JPEG      []byte         // Raw JPEG data
	PixelSize *PixelSizeInfo // Actual pixel dimensions (nil if not queried)
}

// DataChannel manages TCP data channel connections (port 53218).
type DataChannel struct {
	host  string
	port  uint16
	token [8]byte
}

// NewDataChannel creates a DataChannel for the given scanner address.
func NewDataChannel(host string, port uint16, token [8]byte) *DataChannel {
	return &DataChannel{host: host, port: port, token: token}
}

// connect opens a TCP connection and reads the welcome packet.
func (d *DataChannel) connect() (net.Conn, error) {
	addr := net.JoinHostPort(d.host, fmt.Sprintf("%d", d.port))
	slog.Debug("data channel connecting", "addr", addr)
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("data connect: %w", err)
	}

	welcome := make([]byte, WelcomeSize)
	if _, err := io.ReadFull(conn, welcome); err != nil {
		conn.Close()
		return nil, fmt.Errorf("data welcome: %w", err)
	}
	if err := ValidateWelcome(welcome); err != nil {
		conn.Close()
		return nil, err
	}
	slog.Debug("data channel connected", "addr", addr, "welcome", PacketSummary(welcome))
	return conn, nil
}

// request opens a connection, sends data, reads a length-prefixed response, and closes.
func (d *DataChannel) request(data []byte) ([]byte, error) {
	conn, err := d.connect()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	slog.Debug("data send", "bytes", len(data))
	if _, err := conn.Write(data); err != nil {
		return nil, fmt.Errorf("data send: %w", err)
	}
	resp, err := readResponse(conn)
	if err != nil {
		return nil, err
	}
	slog.Debug("data recv", "bytes", len(resp))
	return resp, nil
}

// readResponse reads a length-prefixed VENS response from a connection.
func readResponse(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("read response length: %w", err)
	}
	respLen := binary.BigEndian.Uint32(lenBuf)
	if respLen < 4 || respLen > 16*1024*1024 {
		return nil, fmt.Errorf("invalid response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	copy(resp[:4], lenBuf)
	if _, err := io.ReadFull(r, resp[4:]); err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}
	return resp, nil
}

// GetDeviceInfo queries device identity (cmd=0x06, sub=0x12).
func (d *DataChannel) GetDeviceInfo() (*DataDeviceInfo, error) {
	slog.Debug("getting device info...")
	resp, err := d.request(MarshalGetDeviceInfo(d.token))
	if err != nil {
		return nil, err
	}
	info, err := ParseDataDeviceInfo(resp)
	if err != nil {
		return nil, err
	}
	slog.Debug("device info OK", "deviceName", info.DeviceName, "revision", info.FirmwareRevision)
	return info, nil
}

// GetScanParams queries scanner capabilities (cmd=0x06, sub=0x90).
func (d *DataChannel) GetScanParams() (*ScanParams, error) {
	slog.Debug("getting scan params...")
	resp, err := d.request(MarshalGetScanParams(d.token))
	if err != nil {
		return nil, err
	}
	params, err := ParseScanParams(resp)
	if err != nil {
		return nil, err
	}
	slog.Debug("scan params OK", "bytes", len(resp))
	return params, nil
}

// GetScanSettings queries current scan settings (cmd=0x06, sub=0xD8).
func (d *DataChannel) GetScanSettings() ([]byte, error) {
	slog.Debug("getting scan settings...")
	resp, err := d.request(MarshalGetScanSettings(d.token))
	if err != nil {
		return nil, err
	}
	slog.Debug("scan settings OK", "bytes", len(resp))
	return resp, nil
}

// SetConfig sends scanner config (cmd=0x08).
func (d *DataChannel) SetConfig() ([]byte, error) {
	slog.Debug("setting config...")
	resp, err := d.request(MarshalConfigCommand(d.token))
	if err != nil {
		return nil, err
	}
	slog.Debug("config OK", "bytes", len(resp))
	return resp, nil
}

// ScanSession manages an ongoing scan, allowing pages to be pulled one at a time.
// This enables lazy scanning where the client can stop after any page without
// the scanner feeding additional sheets.
type ScanSession struct {
	dc            *DataChannel
	conn          net.Conn
	token         [8]byte
	sidesPerSheet int
	physicalSheet int
	transferSheet int
	sideIdx       int
	done          bool
}

// StartScan begins a scan session (setup, config, prepare, status check,
// wait for first sheet) and returns a ScanSession from which pages can be
// pulled one at a time via NextPage.
func (d *DataChannel) StartScan(cfg ScanConfig) (*ScanSession, error) {
	slog.Debug("starting scan session", "colorMode", cfg.ColorMode, "quality", cfg.Quality, "duplex", cfg.Duplex, "paperSize", cfg.PaperSize)
	conn, err := d.connect()
	if err != nil {
		return nil, err
	}

	sendAndRecv := func(data []byte) ([]byte, error) {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(data); err != nil {
			return nil, err
		}
		return readResponse(conn)
	}

	// Step 1: Get current settings
	slog.Debug("scan step 1: getting current scan settings...")
	resp, err := sendAndRecv(MarshalGetScanSettings(d.token))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("get settings: %w", err)
	}
	slog.Debug("get settings response", "bytes", len(resp))

	// Step 2: Write scan config
	slog.Debug("scan step 2: writing scan config...")
	resp, err = sendAndRecv(MarshalScanConfig(d.token, cfg))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("set scan config: %w", err)
	}
	slog.Debug("set config response", "packet", PacketSummary(resp))

	// Step 2.5: Write tone curve for bleed-through reduction (sub=0xDB)
	if cfg.BleedThrough {
		slog.Debug("scan step 2.5: writing bleed-through tone curve...")
		resp, err = sendAndRecv(MarshalWriteToneCurve(d.token))
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("write tone curve: %w", err)
		}
		slog.Debug("tone curve response", "bytes", len(resp))
	}

	// Step 3: Prepare scan
	slog.Debug("scan step 3: preparing scan...")
	resp, err = sendAndRecv(MarshalPrepareScan(d.token))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("prepare scan: %w", err)
	}
	slog.Debug("prepare scan response", "bytes", len(resp))

	// Step 4: Get status — check for paper in ADF
	slog.Debug("scan step 4: getting status...")
	resp, err = sendAndRecv(MarshalGetStatus(d.token))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("get status: %w", err)
	}
	slog.Debug("status response", "packet", PacketSummary(resp))
	if len(resp) >= StatusRespScanStatusOffset+4 {
		scanStatus := binary.BigEndian.Uint32(resp[StatusRespScanStatusOffset : StatusRespScanStatusOffset+4])
		slog.Info("scan status", "status", fmt.Sprintf("0x%08X", scanStatus))
		if scanStatus&ADFCoverOpenMask != 0 {
			conn.Close()
			return nil, &ScanError{Kind: ScanErrCoverOpen, Msg: "ADF cover open"}
		}
		if !HasPaper(scanStatus) {
			conn.Close()
			return nil, &ScanError{Kind: ScanErrNoPaper, Msg: "no paper in ADF"}
		}
	}

	// Step 5: Wait for scan to start
	slog.Debug("scan step 5: waiting for scan to start...")
	conn.SetDeadline(time.Now().Add(120 * time.Second)) // Long timeout for user interaction
	if _, err := conn.Write(MarshalWaitForScan(d.token)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("wait for scan: %w", err)
	}
	resp, err = readResponse(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("wait for scan response: %w", err)
	}
	if len(resp) >= WaitRespStatusOffset+4 {
		waitStatus := binary.BigEndian.Uint32(resp[WaitRespStatusOffset : WaitRespStatusOffset+4])
		if waitStatus != 0 {
			slog.Warn("WaitForScan failed, sending REQUEST SENSE", "waitStatus", waitStatus)
			// Send REQUEST SENSE on same connection to get specific error
			conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := conn.Write(MarshalGetPageMetadata(d.token)); err == nil {
				if senseResp, err := readResponse(conn); err == nil {
					if senseErr := parseSenseError(senseResp); senseErr != nil {
						conn.Close()
						return nil, senseErr
					}
				}
			}
			conn.Close()
			return nil, &ScanError{Kind: ScanErrGeneric, Msg: fmt.Sprintf("WaitForScan returned status=%d (expected 0)", waitStatus)}
		}
	}
	slog.Info("scan started")

	sidesPerSheet := 1
	if cfg.Duplex {
		sidesPerSheet = 2
	}

	return &ScanSession{
		dc:            d,
		conn:          conn,
		token:         d.token,
		sidesPerSheet: sidesPerSheet,
	}, nil
}

// NextPage returns the next scanned page. Returns io.EOF when no more pages
// are available. For duplex, front and back sides are returned as separate pages.
//
// Crucially, the next physical sheet is only fed when NextPage is called for it.
// This enables SelectSinglePage: the client can stop calling NextPage after one
// sheet and Close the session without the scanner feeding additional pages.
func (s *ScanSession) NextPage() (Page, error) {
	if s.done {
		return Page{}, io.EOF
	}

	// Before first side of a new sheet (except the very first), wait for next sheet
	if s.sideIdx == 0 && s.physicalSheet > 0 {
		// Check status
		s.conn.SetDeadline(time.Now().Add(10 * time.Second))
		if _, err := s.conn.Write(MarshalGetStatus(s.token)); err != nil {
			s.done = true
			return Page{}, fmt.Errorf("status check: %w", err)
		}
		statusResp, err := readResponse(s.conn)
		if err != nil {
			s.done = true
			return Page{}, fmt.Errorf("status check recv: %w", err)
		}
		if len(statusResp) >= StatusRespScanStatusOffset+4 {
			scanStatus := binary.BigEndian.Uint32(statusResp[StatusRespScanStatusOffset : StatusRespScanStatusOffset+4])
			slog.Info("scan status", "status", fmt.Sprintf("0x%08X", scanStatus))
			slog.Info("scan status fields", statusFieldAttrs("before_wait", statusResp)...)
		}

		// Check for scanner error (multi-feed, etc.) at offset 44
		if len(statusResp) >= StatusRespErrorOffset+4 {
			errorField := binary.BigEndian.Uint32(statusResp[StatusRespErrorOffset : StatusRespErrorOffset+4])
			if errorCode := uint16(errorField & 0xFFFF); errorCode != 0 {
				s.done = true
				kind := ErrorCodeToKind(errorCode)
				msg := fmt.Sprintf("scanner error 0x%04X", errorCode)
				slog.Warn(msg, "errorCode", fmt.Sprintf("0x%04X", errorCode), "kind", kind)
				return Page{}, &ScanError{Kind: kind, Msg: msg}
			}
		}

		// Wait for next sheet — this is what causes the scanner to feed
		slog.Debug("waiting for next sheet...")
		s.conn.SetDeadline(time.Now().Add(30 * time.Second))
		if _, err := s.conn.Write(MarshalWaitForScan(s.token)); err != nil {
			s.done = true
			return Page{}, fmt.Errorf("wait next sheet: %w", err)
		}
		resp, err := readResponse(s.conn)
		if err != nil {
			s.done = true
			return Page{}, fmt.Errorf("wait next sheet recv: %w", err)
		}
		if len(resp) < WaitRespStatusOffset+4 || string(resp[4:8]) != "VENS" {
			s.done = true
			return Page{}, fmt.Errorf("short terminal wait response")
		}
		if len(resp) >= WaitRespStatusOffset+4 {
			waitStatus := binary.BigEndian.Uint32(resp[WaitRespStatusOffset : WaitRespStatusOffset+4])
			if waitStatus != 0 {
				s.done = true
				if waitStatus != 2 {
					return Page{}, fmt.Errorf("unknown terminal wait status %d", waitStatus)
				}
				// Status 2 is ambiguous (complete OR error). It cannot alone
				// certify EOF: recheck no-paper and the error/sense response.
				if err := s.confirmDocumentEnd(); err != nil {
					return Page{}, err
				}
				return Page{}, io.EOF
			}
		}
	}

	// Transfer this page side
	backSide := s.sideIdx == 1
	jpeg, err := s.dc.transferPageChunks(s.conn, s.transferSheet, backSide)
	if err != nil {
		s.done = true
		return Page{}, fmt.Errorf("page transfer: %w", err)
	}

	page := Page{Sheet: s.physicalSheet, Side: s.sideIdx, JPEG: jpeg}
	slog.Info("page received", "sheet", s.physicalSheet, "side", s.sideIdx, "bytes", len(jpeg))

	// Page metadata (REQUEST SENSE — carries SCSI sense data with error info)
	s.conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := s.conn.Write(MarshalGetPageMetadata(s.token)); err != nil {
		s.done = true
		return page, fmt.Errorf("page metadata: %w", err)
	}
	metaResp, err := readResponse(s.conn)
	if err != nil {
		s.done = true
		return page, fmt.Errorf("page metadata recv: %w", err)
	}
	if senseErr := parseSenseError(metaResp); senseErr != nil {
		slog.Warn("scanner error in sense data", "err", senseErr, "kind", senseErr.Kind)
		s.done = true
		return page, senseErr
	}

	// NOTE: READ_PIXELSIZE (SCSI READ DataType=0x80) is NOT sent here.
	// The official app does not issue this command during scan sessions.
	// Sending it causes the scanner firmware to crash after ~3 queries
	// during multi-page duplex scans.

	s.transferSheet++
	s.sideIdx++
	if s.sideIdx >= s.sidesPerSheet {
		s.sideIdx = 0
		s.physicalSheet++
	}

	return page, nil
}

// Close ends the scan session and releases the TCP connection.
// It sends the EndScan command to reset the scanner state.
func (s *ScanSession) Close() error {
	if s.conn == nil {
		return nil
	}
	s.conn.SetDeadline(time.Now().Add(5 * time.Second))
	var protocolErr error
	if _, err := s.conn.Write(MarshalEndScan(s.token)); err != nil {
		protocolErr = err
	} else if _, err := readResponse(s.conn); err != nil {
		protocolErr = err
	}
	err := errors.Join(protocolErr, s.conn.Close())
	s.conn = nil
	s.done = true
	return err
}

// RunScan executes a full scan session and returns all scanned pages.
// This is a convenience wrapper around StartScan + NextPage for callers
// that want all pages at once (e.g. button scan).
func (d *DataChannel) RunScan(cfg ScanConfig, onPage func(Page)) ([]Page, error) {
	session, err := d.StartScan(cfg)
	if err != nil {
		return nil, err
	}
	defer session.Close()

	var pages []Page
	for {
		page, err := session.NextPage()
		if err == io.EOF {
			break
		}
		if err != nil {
			return pages, err
		}
		pages = append(pages, page)
		if onPage != nil {
			onPage(page)
		}
	}

	nonEmpty := 0
	for _, p := range pages {
		if len(p.JPEG) > 0 {
			nonEmpty++
		}
	}
	slog.Info("scan finished", "total_pages", len(pages), "non_empty", nonEmpty)
	return pages, nil
}

// transferPageChunks reads all JPEG chunks for a single page side.
// The scanner sends data in 256KB chunks; page_type=2 marks the final chunk.
func (d *DataChannel) transferPageChunks(conn net.Conn, sheet int, backSide bool) ([]byte, error) {
	var jpegBuf []byte

	for chunk := 0; ; chunk++ {
		conn.SetDeadline(time.Now().Add(30 * time.Second))

		if _, err := conn.Write(MarshalPageTransfer(d.token, sheet, chunk, backSide)); err != nil {
			return nil, fmt.Errorf("chunk %d send: %w", chunk, err)
		}

		// Read length prefix first to detect error responses (< 42 bytes)
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return nil, fmt.Errorf("chunk %d length: %w", chunk, err)
		}
		totalLen := binary.BigEndian.Uint32(lenBuf)
		if totalLen < uint32(PageHeaderSize) {
			// Scanner returned an error/short response, not a page header
			if totalLen > 4 {
				discard := make([]byte, totalLen-4)
				io.ReadFull(conn, discard)
			}
			return nil, &ScanError{Msg: fmt.Sprintf("page transfer error: expected page header, got %d bytes", totalLen)}
		}

		restBuf := make([]byte, PageHeaderSize-4)
		if _, err := io.ReadFull(conn, restBuf); err != nil {
			return nil, fmt.Errorf("chunk %d header: %w", chunk, err)
		}
		headerBuf := make([]byte, PageHeaderSize)
		copy(headerBuf[:4], lenBuf)
		copy(headerBuf[4:], restBuf)
		header, err := ParsePageHeader(headerBuf)
		if err != nil {
			return nil, fmt.Errorf("chunk %d parse: %w", chunk, err)
		}

		jpegSize := header.JPEGSize()
		if jpegSize > 0 {
			jpegChunk := make([]byte, jpegSize)
			if _, err := io.ReadFull(conn, jpegChunk); err != nil {
				return nil, fmt.Errorf("chunk %d data: %w", chunk, err)
			}
			jpegBuf = append(jpegBuf, jpegChunk...)
		}

		slog.Debug("chunk", "sheet", sheet, "chunk", chunk, "pageType", header.PageType, "chunk_bytes", jpegSize, "total_bytes", len(jpegBuf))

		if header.PageType == PageTypeFinal {
			break
		}
	}

	slog.Debug("transfer complete", "sheet", sheet, "bytes", len(jpegBuf), "chunks", len(jpegBuf)/int(PageTransferLen)+1)
	return jpegBuf, nil
}

// parseSenseError extracts error information from a REQUEST SENSE VENS response.
// The 18-byte SCSI Sense Data starts at offset 40. Returns nil if no error.
func parseSenseError(resp []byte) *ScanError {
	if len(resp) < SenseDataOffset+14 {
		return nil
	}
	senseKey := resp[SenseDataOffset+2] & 0x0F
	asc := resp[SenseDataOffset+12]
	ascq := resp[SenseDataOffset+13]

	slog.Debug("sense data", "senseKey", fmt.Sprintf("0x%02X", senseKey),
		"asc", fmt.Sprintf("0x%02X", asc), "ascq", fmt.Sprintf("0x%02X", ascq))

	switch senseKey {
	case SenseKeyNoSense:
		return nil
	case SenseKeyNotReady:
		return &ScanError{Kind: ScanErrGeneric, Msg: "scanner not ready"}
	case SenseKeyMediumError:
		if asc == VendorASC {
			switch ascq {
			case ASCQPaperJam:
				return &ScanError{Kind: ScanErrPaperJam, Msg: "paper jam"}
			case ASCQCoverOpen:
				return &ScanError{Kind: ScanErrCoverOpen, Msg: "ADF cover open"}
			case ASCQMultiFeed:
				return &ScanError{Kind: ScanErrMultiFeed, Msg: "multi-feed detected"}
			case ASCQScanComplete:
				return nil // Not an error — scan complete signal
			}
		}
		return &ScanError{Kind: ScanErrGeneric, Msg: fmt.Sprintf("medium error (ASC=0x%02X, ASCQ=0x%02X)", asc, ascq)}
	}
	return &ScanError{Kind: ScanErrGeneric, Msg: fmt.Sprintf("unknown error (Key=0x%02X, ASC=0x%02X, ASCQ=0x%02X)", senseKey, asc, ascq)}
}

// CheckSenseStatus sends a REQUEST SENSE to probe for scanner error conditions
// (paper jam, cover open, multi-feed, etc.). Returns nil if no error.
func (d *DataChannel) CheckSenseStatus() *ScanError {
	resp, err := d.request(MarshalGetPageMetadata(d.token))
	if err != nil {
		slog.Debug("sense status check failed", "err", err)
		return nil
	}
	return parseSenseError(resp)
}

// ADFStatus holds the result of an ADF status check.
type ADFStatus struct {
	HasPaper     bool   // paper present in ADF
	HasJam       bool   // paper jam detected (bit 15 of scan_status)
	HasCoverOpen bool   // ADF cover open (bit 5 of scan_status)
	ErrorCode    uint16 // error code from GET_STATUS offset 44 (0 = no error)
}

// CheckADFStatus queries the scanner ADF status.
// This method is only called in idle context (not during active scanning),
// so bit 15 (ADFJamMask) reliably indicates a paper jam condition.
func (d *DataChannel) CheckADFStatus() (*ADFStatus, error) {
	slog.Debug("checking ADF status...")
	resp, err := d.request(MarshalGetStatus(d.token))
	if err != nil {
		return nil, err
	}
	if len(resp) < StatusRespScanStatusOffset+4 {
		return nil, errors.New("status response too short for ADF check")
	}
	scanStatus := binary.BigEndian.Uint32(resp[StatusRespScanStatusOffset : StatusRespScanStatusOffset+4])
	result := &ADFStatus{
		HasPaper:     HasPaper(scanStatus),
		HasJam:       scanStatus&ADFJamMask != 0,
		HasCoverOpen: scanStatus&ADFCoverOpenMask != 0,
	}
	if len(resp) >= StatusRespErrorOffset+4 {
		errorField := binary.BigEndian.Uint32(resp[StatusRespErrorOffset : StatusRespErrorOffset+4])
		result.ErrorCode = uint16(errorField & 0xFFFF)
	}
	if unknown := scanStatus & ^adfKnownMask; unknown != 0 {
		slog.Warn("unknown scan status flags detected", "scanStatus", fmt.Sprintf("0x%08X", scanStatus), "unknownBits", fmt.Sprintf("0x%08X", unknown))
	}
	slog.Debug("ADF status check", "scanStatus", fmt.Sprintf("0x%08X", scanStatus), "paper", result.HasPaper, "jam", result.HasJam, "coverOpen", result.HasCoverOpen, "errorCode", fmt.Sprintf("0x%04X", result.ErrorCode))
	return result, nil
}

// endConfirmationTimeout bounds each request of confirmDocumentEnd,
// including the diagnostic requests after a rejection (at most +2x).
var endConfirmationTimeout = 5 * time.Second

// confirmDocumentEnd accepts only an explicit no-paper status, no error and a
// complete normal SCSI sense record. Paper intent still requires human review.
func (s *ScanSession) confirmDocumentEnd() error {
	query := func(request []byte) ([]byte, error) {
		s.conn.SetDeadline(time.Now().Add(endConfirmationTimeout))
		if _, err := s.conn.Write(request); err != nil {
			return nil, fmt.Errorf("end confirmation send: %w", err)
		}
		response, err := readResponse(s.conn)
		if err != nil {
			return nil, fmt.Errorf("end confirmation response: %w", err)
		}
		if len(response) < 8 || string(response[4:8]) != "VENS" {
			return nil, fmt.Errorf("invalid end confirmation header")
		}
		return response, nil
	}
	status, err := query(MarshalGetStatus(s.token))
	if err != nil {
		return err
	}
	if len(status) < StatusRespErrorOffset+4 {
		return fmt.Errorf("short terminal status")
	}
	state := binary.BigEndian.Uint32(status[StatusRespScanStatusOffset : StatusRespScanStatusOffset+4])
	errorField := binary.BigEndian.Uint32(status[StatusRespErrorOffset : StatusRespErrorOffset+4])
	if state != ADFPaperMask || errorField != 0 {
		// Diagnostics only: the decision above is final. Log both fields
		// separately, then what the scanner reports as sense and status
		// after it, so a hardware run shows which field and why.
		slog.Warn("terminal status rejected", statusFieldAttrs("terminal", status)...)
		if sense, serr := query(MarshalGetPageMetadata(s.token)); serr == nil {
			slog.Warn("terminal status rejected: sense", senseAttrs(sense)...)
			if again, aerr := query(MarshalGetStatus(s.token)); aerr == nil {
				slog.Warn("terminal status rejected: status after sense", statusFieldAttrs("after_sense", again)...)
			}
		}
		return &TerminalStatusError{State: state, ErrorField: errorField}
	}
	sense, err := query(MarshalGetPageMetadata(s.token))
	if err != nil {
		return err
	}
	if len(sense) < SenseDataOffset+18 || sense[SenseDataOffset+7] < 10 || len(sense) < SenseDataOffset+8+int(sense[SenseDataOffset+7]) {
		return fmt.Errorf("short terminal sense")
	}
	slog.Info("terminal sense", senseAttrs(sense)...)
	code := sense[SenseDataOffset] & 0x7f
	if code != 0x70 && code != 0x71 {
		return fmt.Errorf("unknown terminal sense format")
	}
	if err := parseSenseError(sense); err != nil {
		return err
	}
	if sense[SenseDataOffset+2]&0x0f == SenseKeyNoSense && (sense[SenseDataOffset+12] != 0 || sense[SenseDataOffset+13] != 0) {
		return fmt.Errorf("ambiguous terminal sense")
	}
	return nil
}

// TerminalStatusError reports a terminal GET_STATUS that is not exactly
// "no paper, no error". Both fields are kept apart for diagnosis.
type TerminalStatusError struct {
	State      uint32 // offset 40; only ADFPaperMask is accepted
	ErrorField uint32 // offset 44; only 0 is accepted (all 32 bits)
}

func (e *TerminalStatusError) Error() string {
	var reasons []string
	if e.State != ADFPaperMask {
		reasons = append(reasons, fmt.Sprintf("scan state 0x%08X (expected 0x%08X, unknown bits 0x%08X)",
			e.State, ADFPaperMask, e.State&^adfKnownMask))
	}
	if e.ErrorField != 0 {
		reasons = append(reasons, fmt.Sprintf("error field 0x%08X (code 0x%04X, upper 0x%04X)",
			e.ErrorField, e.ErrorField&0xFFFF, e.ErrorField>>16))
	}
	return "terminal status is not clean no-paper: " + strings.Join(reasons, "; ")
}

// statusFieldAttrs describes a GET_STATUS response word by word (offsets
// 40-71; the header is never logged). No raw packet is logged (redact.go):
// each 32-bit word is a named field in the form RegisterToken scrubs, so a
// word equal to half of the session token is redacted by the handler.
func statusFieldAttrs(phase string, resp []byte) []any {
	word := func(offset int) (uint32, bool) {
		if len(resp) < offset+4 {
			return 0, false
		}
		return binary.BigEndian.Uint32(resp[offset : offset+4]), true
	}
	attrs := []any{"phase", phase, "bytes", len(resp)}
	if state, ok := word(StatusRespScanStatusOffset); ok {
		attrs = append(attrs, "state", fmt.Sprintf("0x%08X", state),
			"no_paper", state&ADFPaperMask != 0, "cover_open", state&ADFCoverOpenMask != 0,
			"jam", state&ADFJamMask != 0, "unknown_state_bits", fmt.Sprintf("0x%08X", state&^adfKnownMask))
	}
	if field, ok := word(StatusRespErrorOffset); ok {
		attrs = append(attrs, "error_field", fmt.Sprintf("0x%08X", field),
			"error_code", fmt.Sprintf("0x%04X", field&0xFFFF), "error_upper", fmt.Sprintf("0x%04X", field>>16))
	}
	for _, offset := range []int{48, 52, StatusRespDeviceFlagsOffset, 60, 64, 68} {
		name := fmt.Sprintf("reserved_%d", offset)
		if offset == StatusRespDeviceFlagsOffset {
			name = "device_flags"
		}
		if v, ok := word(offset); ok {
			attrs = append(attrs, name, fmt.Sprintf("0x%08X", v))
		}
	}
	return attrs
}

// senseAttrs describes a REQUEST SENSE response (format, key, ASC, ASCQ).
func senseAttrs(resp []byte) []any {
	attrs := []any{"bytes", len(resp)}
	if len(resp) >= SenseDataOffset+14 {
		attrs = append(attrs, "format", fmt.Sprintf("0x%02X", resp[SenseDataOffset]&0x7f),
			"key", fmt.Sprintf("0x%02X", resp[SenseDataOffset+2]&0x0f),
			"asc", fmt.Sprintf("0x%02X", resp[SenseDataOffset+12]),
			"ascq", fmt.Sprintf("0x%02X", resp[SenseDataOffset+13]))
	}
	return attrs
}
