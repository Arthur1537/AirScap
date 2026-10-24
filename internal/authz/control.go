package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/mzyy94/airscap/internal/vens"
)

// Control obtains grants from the internal reservation API of ScanSnap
// Control (app/scanner_internal.py):
//
//	POST /internal/v1/reservations                  {"source": "..."} -> 201
//	POST /internal/v1/reservations/{id}/activity                      -> 200
//	POST /internal/v1/reservations/{id}/finish      {"success": bool} -> 200
//
// Every call carries the scanner token (never the browser token). Any
// answer other than the expected one refuses the scan (fail closed).
type Control struct {
	base   *url.URL
	token  string
	client *http.Client
}

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
	ReservationID string `json:"reservation_id"`
	JobID         string `json:"job_id"`
	Mode          string `json:"mode"`
	Source        string `json:"source"`
	Status        string `json:"status"`
}

// Authorize implements Authorizer.
func (c *Control) Authorize(ctx context.Context, source Source) (Grant, error) {
	if !source.Valid() {
		return nil, fmt.Errorf("%w: unknown source", ErrNotAuthorized)
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
	if !reservationPattern.MatchString(r.ReservationID) || !printablePattern.MatchString(r.JobID) ||
		r.Status != "reserved" || r.Source != string(source) ||
		(r.Mode != "" && !printablePattern.MatchString(r.Mode)) {
		// A reservation we cannot reference safely is released if possible.
		if reservationPattern.MatchString(r.ReservationID) {
			c.post(ctx, "/internal/v1/reservations/"+r.ReservationID+"/finish",
				map[string]bool{"success": false})
		}
		return nil, fmt.Errorf("%w: unexpected reservation response", ErrNotAuthorized)
	}
	return &controlGrant{control: c, r: r}, nil
}

func (c *Control) post(ctx context.Context, path string, payload any) ([]byte, int, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	endpoint := *c.base
	endpoint.Path = c.base.Path + path
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
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
	once     sync.Once
	finished error
}

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
		}
	})
	return g.finished
}
