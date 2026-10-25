package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// Control obtains grants from the internal reservation API of ScanSnap
// Control (app/scanner_internal.py):
//
//	GET  /internal/v1/contract                                        -> 200 (contract 2; 404 = 1)
//	POST /internal/v1/reservations                  {"source": "..."} -> 201
//	POST /internal/v1/reservations/{id}/activity                      -> 200
//	POST /internal/v1/reservations/{id}/finish      {"success": bool} -> 200
//
// Every call carries the scanner token (never the browser token) and the
// contract version (X-SSC-Contract). Any answer other than the expected
// one refuses the scan (fail closed).
type Control struct {
	base   *url.URL
	token  string
	client *http.Client

	mu             sync.Mutex
	serverContract int // 0 until negotiated
}

// ContractVersion is the scanner-gateway contract this client speaks
// (ScanSnap Control contracts/scanner-gateway.json, copy in testdata/).
const ContractVersion = 2

const contractName = "scansnap-scanner-gateway"

// ErrRecoveryRequired: ScanSnap Control did not accept a scan reported as
// complete (its browser authority or scan window was gone); the
// reservation stays blocked until an operator resolves it. Contract 2.
var ErrRecoveryRequired = errors.New("scan not accepted by ScanSnap Control: recovery required")

// RecoveryRequiredError carries Control's reason for ErrRecoveryRequired.
type RecoveryRequiredError struct{ Reason string }

func (e *RecoveryRequiredError) Error() string {
	return ErrRecoveryRequired.Error() + " (" + e.Reason + ")"
}

func (e *RecoveryRequiredError) Unwrap() error { return ErrRecoveryRequired }

var reasonPattern = regexp.MustCompile(`\A[a-z_]{1,40}\z`)

// MinTokenLength matches ScanSnap Control, which refuses shorter tokens.
const MinTokenLength = 32

const requestTimeout = 5 * time.Second

var (
	reservationPattern = regexp.MustCompile(`\A[0-9a-f]{32}\z`)
	printablePattern   = regexp.MustCompile(`\A[\x21-\x7e]{1,64}\z`)
)

// NewControl validates the configuration. baseURL is the internal API
// root, e.g. http://127.0.0.1:18082.
func NewControl(baseURL, token string, client *http.Client) (*Control, error) {
	base, err := url.Parse(baseURL)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") ||
		base.Host == "" || base.User != nil || base.RawQuery != "" || base.Fragment != "" {
		return nil, errors.New("invalid ScanSnap Control URL")
	}
	// The bearer token and the reservation ids must not cross the network
	// in clear text: plain HTTP only to a loopback address (co-located on
	// the QNAP), otherwise HTTPS with certificate verification.
	if base.Scheme == "http" && !loopbackLiteral(base.Hostname()) {
		return nil, errors.New("plain HTTP to ScanSnap Control only on a loopback address; use https")
	}
	if len(token) < MinTokenLength || strings.ContainsAny(token, " \t\r\n") {
		return nil, fmt.Errorf("scanner token must have at least %d characters", MinTokenLength)
	}
	vens.RegisterSecret(token)
	if client == nil {
		client = &http.Client{Timeout: requestTimeout}
	}
	// Never follow redirects: the token must not reach another host.
	copied := *client
	copied.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	base.Path = strings.TrimRight(base.Path, "/")
	return &Control{base: base, token: token, client: &copied}, nil
}

type reservation struct {
	ReservationID string           `json:"reservation_id"`
	JobID         string           `json:"job_id"`
	Mode          string           `json:"mode"`
	Source        string           `json:"source"`
	Status        string           `json:"status"`
	Scan          *json.RawMessage `json:"scan"`
}

// scanSettings decodes the job's settings strictly: all four fields, no
// others, supported values only.
func (r reservation) scanSettings() (ScanSettings, bool) {
	var s ScanSettings
	if r.Scan == nil {
		return s, false
	}
	decoder := json.NewDecoder(bytes.NewReader(*r.Scan))
	decoder.DisallowUnknownFields()
	var fields map[string]json.RawMessage
	if json.Unmarshal(*r.Scan, &fields) != nil || len(fields) != 4 || decoder.Decode(&s) != nil {
		return s, false
	}
	return s, s.Valid()
}

// ServerContract is the contract version ScanSnap Control announced (0
// before the first successful negotiation).
func (c *Control) ServerContract() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.serverContract
}

// negotiate learns the server's contract once. A server without the
// contract endpoint (404) speaks version 1. A server that requires a newer
// client refuses every scan (fail closed).
func (c *Control) negotiate(ctx context.Context) error {
	if c.ServerContract() != 0 {
		return nil
	}
	body, status, err := c.request(ctx, http.MethodGet, "/internal/v1/contract", nil)
	version := 1
	switch {
	case err != nil:
		return err
	case status == http.StatusNotFound || status == http.StatusMethodNotAllowed:
	case status == http.StatusOK:
		var info struct {
			Name      string `json:"name"`
			Version   int    `json:"version"`
			MinClient int    `json:"min_client"`
		}
		if json.Unmarshal(body, &info) != nil || info.Name != contractName || info.Version < 2 || info.MinClient < 1 {
			return errors.New("ScanSnap Control contract unreadable")
		}
		if info.MinClient > ContractVersion {
			return fmt.Errorf("ScanSnap Control requires scanner contract %d or later (this AirScap speaks %d)",
				info.MinClient, ContractVersion)
		}
		version = info.Version
	default:
		return errors.New(refusal(status, body))
	}
	c.mu.Lock()
	c.serverContract = version
	c.mu.Unlock()
	slog.Info("ScanSnap Control contract", "server", version, "client", ContractVersion)
	return nil
}

// Authorize implements Authorizer.
func (c *Control) Authorize(ctx context.Context, source Source) (Grant, error) {
	if !source.Valid() {
		return nil, fmt.Errorf("%w: unknown source", ErrNotAuthorized)
	}
	if err := c.negotiate(ctx); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAuthorized, err)
	}
	body, status, err := c.post(ctx, "/internal/v1/reservations",
		map[string]string{"source": string(source)})
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNotAuthorized, err)
	}
	if status != http.StatusCreated {
		return nil, fmt.Errorf("%w: %s", ErrNotAuthorized, refusal(status, body))
	}

	var r reservation
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("%w: invalid reservation response", ErrNotAuthorized)
	}
	settings, settingsOK := r.scanSettings()
	if !reservationPattern.MatchString(r.ReservationID) || !printablePattern.MatchString(r.JobID) ||
		r.Status != "reserved" || r.Source != string(source) ||
		(r.Mode != "" && !printablePattern.MatchString(r.Mode)) || !settingsOK {
		// A reservation we cannot reference safely is released if possible.
		if reservationPattern.MatchString(r.ReservationID) {
			c.post(ctx, "/internal/v1/reservations/"+r.ReservationID+"/finish",
				map[string]bool{"success": false})
		}
		return nil, fmt.Errorf("%w: unexpected reservation response", ErrNotAuthorized)
	}
	return &controlGrant{control: c, r: r, settings: settings}, nil
}

func (c *Control) post(ctx context.Context, path string, payload any) ([]byte, int, error) {
	return c.request(ctx, http.MethodPost, path, payload)
}

func (c *Control) request(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	var data io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, 0, err
		}
		data = bytes.NewReader(encoded)
	}
	endpoint := *c.base
	endpoint.Path = c.base.Path + path
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), data)
	if err != nil {
		return nil, 0, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-SSC-Contract", strconv.Itoa(ContractVersion))
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, 0, errors.New("ScanSnap Control unreachable")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, resp.StatusCode, errors.New("ScanSnap Control response unreadable")
	}
	return body, resp.StatusCode, nil
}

// refusal turns a ScanSnap Control error into a short, printable reason.
func refusal(status int, body []byte) string {
	var detail struct {
		Detail any `json:"detail"`
	}
	reason := fmt.Sprintf("HTTP %d", status)
	if json.Unmarshal(body, &detail) == nil {
		if text, ok := detail.Detail.(string); ok && text != "" {
			reason += ": " + strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return ' '
				}
				return r
			}, text[:min(len(text), 120)])
		}
	}
	return vens.ScrubSecrets(reason)
}

type controlGrant struct {
	control  *Control
	r        reservation
	settings ScanSettings
	once     sync.Once
	finished error
}

func (g *controlGrant) ScanSettings() ScanSettings { return g.settings }

func (g *controlGrant) ReservationID() string { return g.r.ReservationID }
func (g *controlGrant) JobID() string         { return g.r.JobID }
func (g *controlGrant) Mode() string          { return g.r.Mode }
func (g *controlGrant) Source() Source        { return Source(g.r.Source) }

func (g *controlGrant) Activity(ctx context.Context) error {
	body, status, err := g.control.post(ctx,
		"/internal/v1/reservations/"+g.r.ReservationID+"/activity", map[string]string{})
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New(refusal(status, body))
	}
	var ack struct {
		Status string `json:"status"`
	}
	if json.Unmarshal(body, &ack) != nil || ack.Status != "recorded" {
		return errors.New("activity acknowledgement unavailable")
	}
	return nil
}

func (g *controlGrant) Finish(ctx context.Context, success bool) error {
	g.once.Do(func() {
		// Release the reservation even if the request context has ended
		// (e.g. the eSCL client went away); otherwise it would block the
		// scanner until ScanSnap Control restarts.
		ctx := context.WithoutCancel(ctx)
		body, status, err := g.control.post(ctx,
			"/internal/v1/reservations/"+g.r.ReservationID+"/finish",
			map[string]bool{"success": success})
		switch {
		case err != nil:
			g.finished = err
		case status != http.StatusOK:
			g.finished = errors.New(refusal(status, body))
		default:
			var ack struct {
				Status string `json:"status"`
				Reason string `json:"reason"`
			}
			switch {
			case json.Unmarshal(body, &ack) != nil:
				g.finished = errors.New("finish acknowledgement unavailable")
			case success && ack.Status == "finished", !success && ack.Status == "recovery_required":
			case success && ack.Status == "recovery_required":
				// Contract 2: the scan is not accepted, the reservation is
				// blocked for an operator. Nothing may be staged.
				reason := ack.Reason
				if !reasonPattern.MatchString(reason) {
					reason = "unspecified"
				}
				g.finished = &RecoveryRequiredError{Reason: reason}
			default:
				g.finished = errors.New("finish acknowledgement unavailable")
			}
		}
	})
	return g.finished
}

func (g *controlGrant) RecordIntake(ctx context.Context, manifest map[string]any) error {
	body, status, err := g.control.post(ctx, "/internal/v1/scan-receipts", manifest)
	if err != nil {
		return err
	}
	var ack struct {
		Status   string `json:"status"`
		Released *bool  `json:"released"`
	}
	if status != http.StatusOK || json.Unmarshal(body, &ack) != nil || ack.Status != "staged_not_released" || ack.Released == nil || *ack.Released {
		return errors.New("intake acknowledgement unavailable")
	}
	return nil
}

// loopbackLiteral accepts IP literals only: a name could resolve elsewhere.
func loopbackLiteral(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
