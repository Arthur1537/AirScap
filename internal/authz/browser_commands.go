package authz

// The browser never calls AirScap. This opt-in client pulls one-use commands
// from Control's private, scanner-authenticated API. There is no new listener.
import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
)

type BrowserCommand struct {
	ID    string `json:"id"`
	JobID string `json:"job_id"`
}

type commandKey struct{}

func WithBrowserCommand(ctx context.Context, command BrowserCommand) context.Context {
	return context.WithValue(ctx, commandKey{}, command)
}

func requestedCommand(ctx context.Context) (BrowserCommand, bool) {
	c, ok := ctx.Value(commandKey{}).(BrowserCommand)
	return c, ok
}

// RequestedJob is also checked by Scanner before any feed command, independent
// of the HTTP client's validation. A stale command cannot select another job.
func RequestedJob(ctx context.Context) (string, bool) {
	c, ok := requestedCommand(ctx)
	return c.JobID, ok
}

func (c *Control) NextBrowserCommand(ctx context.Context) (*BrowserCommand, error) {
	body, status, err := c.post(ctx, "/internal/v1/emergency/next", map[string]string{})
	if err != nil {
		return nil, err
	}
	if status == http.StatusNoContent {
		return nil, nil
	}
	var command BrowserCommand
	if status != http.StatusOK || json.Unmarshal(body, &command) != nil ||
		!reservationPattern.MatchString(command.ID) || !reservationPattern.MatchString(command.JobID) {
		return nil, errors.New("browser scan command unavailable")
	}
	return &command, nil
}

func (c *Control) CompleteBrowserCommand(ctx context.Context, id, code string) error {
	if !reservationPattern.MatchString(id) {
		return errors.New("invalid command identity")
	}
	body, status, err := c.post(ctx, "/internal/v1/emergency/commands/"+id+"/complete", map[string]string{"result": code})
	var ack struct {
		Status string `json:"status"`
	}
	if err != nil {
		return err
	}
	if status != http.StatusOK || json.Unmarshal(body, &ack) != nil || ack.Status != "recorded" {
		return errors.New("browser command outcome unconfirmed; never retry scan")
	}
	return nil
}
