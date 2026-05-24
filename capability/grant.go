package capability

import (
	"path/filepath"
	"strings"
	"time"

	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/subject"
)

type Grant struct {
	ID         string         `json:"id"`
	Session    string         `json:"session"`
	Capability string         `json:"capability"`
	Scope      map[string]any `json:"scope,omitempty"`
	Reason     string         `json:"reason,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	ExpiresAt  time.Time      `json:"expires_at"`
	RevokedAt  time.Time      `json:"revoked_at,omitempty"`
	Renewals   []GrantRenewal `json:"renewals,omitempty"`
}

type GrantRenewal struct {
	RenewedAt         time.Time `json:"renewed_at"`
	PreviousExpiresAt time.Time `json:"previous_expires_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	Reason            string    `json:"reason"`
}

func (g Grant) Expired(now time.Time) bool {
	return !g.ExpiresAt.IsZero() && !now.Before(g.ExpiresAt)
}

func (g Grant) Active(now time.Time) bool {
	return g.RevokedAt.IsZero() && !g.Expired(now)
}

func (g Grant) Fact(subj subject.Subject) arbiterx.Fact {
	fields := map[string]any{
		"id":         g.ID,
		"session":    g.Session,
		"capability": g.Capability,
		"reason":     g.Reason,
	}
	for key, value := range g.Scope {
		fields[key] = value
	}
	if !g.ExpiresAt.IsZero() {
		fields["expires_at"] = g.ExpiresAt.Format(time.RFC3339)
	}
	return arbiterx.NewFact(arbiterx.FactCapabilityGrant, subj, fields)
}

func (g Grant) MatchesNetwork(session, host string, port int, now time.Time) bool {
	if !g.Active(now) || g.Session != session {
		return false
	}
	if g.Capability != "network.connect" && g.Capability != "kernel.network.connect.grant" {
		return false
	}
	scopeHost, _ := g.Scope["host"].(string)
	scopePort := scopeInt(g.Scope["port"])
	return scopeHost == host && (scopePort == 0 || scopePort == port)
}

func (g Grant) MatchesFile(session, path, op string, now time.Time) bool {
	if !g.Active(now) || g.Session != session {
		return false
	}
	if g.Capability != "file.access" && g.Capability != "file."+op {
		return false
	}
	scopeOp := scopeString(g.Scope["op"])
	if scopeOp != "" && scopeOp != op {
		return false
	}
	if scopePath := scopeString(g.Scope["path"]); scopePath != "" {
		return samePath(scopePath, path)
	}
	if prefix := scopeString(g.Scope["path_prefix"]); prefix != "" {
		return pathInside(prefix, path)
	}
	return false
}

func (g Grant) MatchesProcess(session, comm, argvText string, now time.Time) bool {
	if !g.Active(now) || g.Session != session {
		return false
	}
	if g.Capability != "process.exec" {
		return false
	}
	if scopeComm := scopeString(g.Scope["comm"]); scopeComm != "" && scopeComm != comm && filepath.Base(scopeComm) != filepath.Base(comm) {
		return false
	}
	if scopeArgv := scopeString(g.Scope["argv_text"]); scopeArgv != "" && scopeArgv != argvText {
		return false
	}
	if prefix := scopeString(g.Scope["argv_prefix"]); prefix != "" && !strings.HasPrefix(argvText, prefix) {
		return false
	}
	return scopeString(g.Scope["comm"]) != "" || scopeString(g.Scope["argv_text"]) != "" || scopeString(g.Scope["argv_prefix"]) != ""
}

func scopeString(value any) string {
	v, _ := value.(string)
	return v
}

func scopeInt(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func pathInside(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if root == "." || root == "" {
		return false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(filepath.ToSlash(rel), "../"))
}
