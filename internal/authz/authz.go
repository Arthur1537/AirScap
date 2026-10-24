// Package authz gates every physical scan behind a reservation from
// ScanSnap Control (QNAP).
//
// Scanner.StartScan asks an Authorizer for a Grant before it sends the
// first scan command; Scanner.Scan, the eSCL adapter, the Web UI preview
// and the button handler all go through it. Without a Grant no scan
// command reaches the scanner. A Grant is bound to the single armed job in
// ScanSnap Control and to the scan source; it reports activity before every
// page (the session must still be active) and its outcome at the end.
//
// The default is Deny: an AirScap without configured authorization does
// not scan at all.
package authz

import (
	"context"
	"errors"
	"fmt"
)

// Source names the entry point that wants to scan.
type Source string

const (
	SourceButton  Source = "button"  // physical scan button
	SourceESCL    Source = "escl"    // eSCL/AirScan client
	SourcePreview Source = "preview" // Web UI preview
)

// Valid reports whether s is a known source.
func (s Source) Valid() bool {
	switch s {
	case SourceButton, SourceESCL, SourcePreview:
		return true
	}
	return false
}

var (
	// ErrNotAuthorized means no scan command may be sent.
	ErrNotAuthorized = errors.New("scan not authorized")
	// ErrAuthorizationLost means a running scan lost its grant (session
	// ended or expired); pages scanned so far must be discarded.
	ErrAuthorizationLost = fmt.Errorf("%w: authorization lost during scan", ErrNotAuthorized)
)

// Grant is the permission for exactly one scan.
type Grant interface {
	ReservationID() string
	JobID() string
	Mode() string
	Source() Source
	// Activity confirms that the session is still active before the next
	// page; an error means the scan must stop.
	Activity(ctx context.Context) error
	// Finish reports the outcome and releases the reservation. Only the
	// first call has an effect.
	Finish(ctx context.Context, success bool) error
}

// Authorizer issues grants.
type Authorizer interface {
	Authorize(ctx context.Context, source Source) (Grant, error)
}

// Deny refuses every scan.
type Deny struct {
	Reason string
}

// Authorize implements Authorizer.
func (d Deny) Authorize(context.Context, Source) (Grant, error) {
	reason := d.Reason
	if reason == "" {
		reason = "no scan authorization configured"
	}
	return nil, fmt.Errorf("%w: %s", ErrNotAuthorized, reason)
}

// IntakeRecorder acknowledges private intake only; it grants no publication.
type IntakeRecorder interface {
	RecordIntake(context.Context, map[string]any) error
}
