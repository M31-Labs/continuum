package arbiterx

import (
	"context"
	"path/filepath"
	"regexp"
	"strings"
)

type Decision struct {
	BundleID  string    `json:"bundle_id,omitempty"`
	Outcomes  []Outcome `json:"outcomes,omitempty"`
	Selected  *Outcome  `json:"selected,omitempty"`
	Arbitrace []Step    `json:"arbitrace,omitempty"`
}

func Evaluate(_ context.Context, bundle *Bundle, facts []Fact) (Decision, error) {
	decision := Decision{}
	if bundle != nil {
		decision.BundleID = bundle.ID
	}
	input := collectInput(facts)
	if input.behavior != nil || (bundle != nil && bundle.Kind == "airlock") {
		return evaluateAirlock(decision, input), nil
	}
	return evaluateAgentGuard(decision, input), nil
}

type normalizedInput struct {
	agent    map[string]any
	file     map[string]any
	net      map[string]any
	process  map[string]any
	grants   []map[string]any
	behavior map[string]any
}

func collectInput(facts []Fact) normalizedInput {
	var in normalizedInput
	for _, fact := range facts {
		switch fact.Type {
		case FactAgentContext:
			in.agent = merge(in.agent, fact.Fields)
		case FactFileAccess:
			in.file = merge(in.file, fact.Fields)
		case FactNetworkConnect:
			in.net = merge(in.net, fact.Fields)
		case FactProcessExec:
			in.process = merge(in.process, fact.Fields)
		case FactCapabilityGrant:
			in.grants = append(in.grants, merge(nil, fact.Fields))
		case FactBehavior:
			in.behavior = merge(in.behavior, fact.Fields)
		}
		if !fact.Subject.Empty() {
			if in.agent == nil {
				in.agent = map[string]any{}
			}
			if fact.Subject.Session != "" {
				in.agent["session"] = fact.Subject.Session
			}
			if fact.Subject.AgentName != "" {
				in.agent["name"] = fact.Subject.AgentName
			}
			if fact.Subject.RepoRoot != "" {
				in.agent["repo_root"] = fact.Subject.RepoRoot
			}
			if fact.Subject.Task != "" {
				in.agent["task"] = fact.Subject.Task
			}
		}
	}
	return in
}

func merge(dst map[string]any, src map[string]any) map[string]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]any, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func evaluateAgentGuard(decision Decision, in normalizedInput) Decision {
	path := stringField(in.file, "path")
	op := stringField(in.file, "op")
	repo := stringField(in.agent, "repo_root")
	ip := stringField(in.net, "ip")
	cwd := stringField(in.process, "cwd")

	if path != "" && hostSecretPath(path) {
		return selectOutcome(decision, NewOutcome(OutcomeDeny, "DenyHostSecrets", map[string]any{
			"reason": "agent cannot access host credential material",
		}))
	}
	if ip == "169.254.169.254" {
		return selectOutcome(decision, NewOutcome(OutcomeDeny, "DenyCloudMetadata", map[string]any{
			"reason": "cloud metadata service is blocked",
		}))
	}
	if grantID := matchingNetworkGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits network connection",
			"grant":  grantID,
		}))
	}
	if grantID := matchingFileGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits file access",
			"grant":  grantID,
		}))
	}
	if grantID := matchingProcessGrant(in); grantID != "" {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowTemporaryGrant", map[string]any{
			"reason": "temporary grant permits process execution",
			"grant":  grantID,
		}))
	}
	if path != "" && op == "write" && strings.Contains(filepath.ToSlash(path), "/.github/workflows/") {
		return selectOutcome(decision, NewOutcome(OutcomeAskHuman, "AskOnCIWrites", map[string]any{
			"question": "Agent wants to modify CI workflow",
			"risk":     "CI workflow changes can create persistence or exfiltration paths",
		}))
	}
	if path != "" && repo != "" && pathInside(repo, path) {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowInsideRepo", map[string]any{
			"reason": "inside declared repository root",
		}))
	}
	if cwd != "" && repo != "" && pathInside(repo, cwd) {
		return selectOutcome(decision, NewOutcome(OutcomeAllow, "AllowInsideRepo", map[string]any{
			"reason": "inside declared repository root",
		}))
	}
	return selectOutcome(decision, NewOutcome(OutcomeAudit, "NoMatchingRule", map[string]any{
		"severity": "info",
		"reason":   "no matching policy rule",
	}))
}

func matchingNetworkGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.net == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	host := stringField(in.net, "host")
	port := numberField(in.net, "port")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session {
			continue
		}
		capability := stringField(grant, "capability")
		if capability != "network.connect" && capability != "kernel.network.connect.grant" {
			continue
		}
		if stringField(grant, "host") != host {
			continue
		}
		grantPort := numberField(grant, "port")
		if grantPort != 0 && grantPort != port {
			continue
		}
		id := stringField(grant, "id")
		if id == "" {
			id = "grant"
		}
		return id
	}
	return ""
}

func matchingFileGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.file == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	path := stringField(in.file, "path")
	op := stringField(in.file, "op")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session {
			continue
		}
		capability := stringField(grant, "capability")
		if capability != "file.access" && capability != "file."+op {
			continue
		}
		if scopeOp := stringField(grant, "op"); scopeOp != "" && scopeOp != op {
			continue
		}
		if grantPath := stringField(grant, "path"); grantPath != "" && samePath(grantPath, path) {
			return grantID(grant)
		}
		if prefix := stringField(grant, "path_prefix"); prefix != "" && pathInside(prefix, path) {
			return grantID(grant)
		}
	}
	return ""
}

func matchingProcessGrant(in normalizedInput) string {
	if len(in.grants) == 0 || in.process == nil {
		return ""
	}
	session := stringField(in.agent, "session")
	comm := stringField(in.process, "comm")
	argvText := stringField(in.process, "argv_text")
	for _, grant := range in.grants {
		if stringField(grant, "session") != session || stringField(grant, "capability") != "process.exec" {
			continue
		}
		scopeComm := stringField(grant, "comm")
		scopeArgv := stringField(grant, "argv_text")
		scopePrefix := stringField(grant, "argv_prefix")
		if scopeComm != "" && scopeComm != comm && filepath.Base(scopeComm) != filepath.Base(comm) {
			continue
		}
		if scopeArgv != "" && scopeArgv != argvText {
			continue
		}
		if scopePrefix != "" && !strings.HasPrefix(argvText, scopePrefix) {
			continue
		}
		if scopeComm != "" || scopeArgv != "" || scopePrefix != "" {
			return grantID(grant)
		}
	}
	return ""
}

func grantID(grant map[string]any) string {
	id := stringField(grant, "id")
	if id == "" {
		id = "grant"
	}
	return id
}

func evaluateAirlock(decision Decision, in normalizedInput) Decision {
	execCount := numberField(in.behavior, "exec_count")
	targets := numberField(in.behavior, "unique_network_targets")
	rewritten := numberField(in.behavior, "rewritten_files")
	entropy := numberField(in.behavior, "entropy_increase_score")
	subj := stringField(in.behavior, "subject")

	if targets > 50 && execCount > 20 {
		return selectOutcome(decision, NewOutcome(OutcomeEnterAirlock, "DetectWormLikeFanout", map[string]any{
			"subject": subj,
			"reason":  "worm-like process/network fanout",
		}))
	}
	if rewritten > 100 && entropy > 0.8 {
		return selectOutcome(decision, NewOutcome(OutcomeEnterAirlock, "DetectRansomwareLikeRewrite", map[string]any{
			"subject": subj,
			"reason":  "ransomware-like rewrite/encryption pattern",
		}))
	}
	return selectOutcome(decision, NewOutcome(OutcomeAudit, "AirlockNoMatch", map[string]any{
		"severity": "info",
		"reason":   "behavior did not cross airlock thresholds",
	}))
}

func selectOutcome(decision Decision, outcome Outcome) Decision {
	decision.Outcomes = append(decision.Outcomes, outcome)
	decision.Selected = &decision.Outcomes[len(decision.Outcomes)-1]
	decision.Arbitrace = append(decision.Arbitrace, Step{
		Rule:    outcome.Rule,
		Result:  "matched",
		Message: outcome.Reason(),
	})
	return decision
}

var hostSecretRE = regexp.MustCompile(`(^|/)\.(ssh|aws|kube)(/|$)`)

func hostSecretPath(path string) bool {
	return hostSecretRE.MatchString(filepath.ToSlash(path))
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

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

func stringField(fields map[string]any, key string) string {
	if fields == nil {
		return ""
	}
	switch v := fields[key].(type) {
	case string:
		return v
	default:
		return ""
	}
}

func numberField(fields map[string]any, key string) float64 {
	if fields == nil {
		return 0
	}
	switch v := fields[key].(type) {
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case float64:
		return v
	case float32:
		return float64(v)
	case jsonNumber:
		n, _ := v.Float64()
		return n
	default:
		return 0
	}
}

type jsonNumber interface {
	Float64() (float64, error)
}
