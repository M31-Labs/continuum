package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/audit"
	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
	"m31labs.dev/continuum/policy"
	"m31labs.dev/continuum/subject"
)

const (
	DefaultPolicyPath        = "examples/agent-workdir/policies/main.arb"
	DefaultAirlockPolicyPath = "examples/airlock/policies/main.arb"
)

type IngestOptions struct {
	PolicyPath    string
	PolicyStore   string
	GrantStore    string
	DeliveryStore string
	AuditPath     string
	Registry      *capability.Registry
	Now           func() time.Time
	NewID         func() string
	Airlock       AirlockOptions
	EnableAirlock bool
}

type IngestResult struct {
	Ingested int             `json:"ingested"`
	Policy   string          `json:"policy"`
	Audit    string          `json:"audit"`
	Records  []audit.Event   `json:"records"`
	Airlocks []AirlockResult `json:"airlocks,omitempty"`
}

func IngestEvents(ctx context.Context, events []event.Event, opts IngestOptions) (IngestResult, error) {
	if opts.AuditPath == "" {
		opts.AuditPath = ".continuum/audit.jsonl"
	}
	policyPath, err := ResolvePolicyPath(opts.PolicyPath, opts.PolicyStore, DefaultPolicyPath)
	if err != nil {
		return IngestResult{}, err
	}
	bundle, err := arbiterx.CompileFile(policyPath)
	if err != nil {
		return IngestResult{}, err
	}
	sink, err := audit.NewJSONLSink(opts.AuditPath)
	if err != nil {
		return IngestResult{}, err
	}
	defer sink.Close()
	engine := NewEngine(bundle, sink)
	engine.Registry = opts.Registry
	if engine.Registry == nil {
		engine.Registry = capability.NewRegistry()
		for _, cap := range capability.BuiltIns() {
			_ = engine.Registry.Register(cap)
		}
	}
	if opts.Now != nil {
		engine.Now = opts.Now
	}
	if opts.NewID != nil {
		engine.NewID = opts.NewID
	}
	if opts.GrantStore != "" {
		grants, err := capability.LoadGrantStore(opts.GrantStore)
		if err == nil {
			engine.Grants = grants.Active(engine.now())
		} else if !errors.Is(err, os.ErrNotExist) {
			return IngestResult{}, err
		}
	}
	if opts.DeliveryStore != "" {
		queue, err := LoadDeliveryStore(opts.DeliveryStore)
		if err != nil {
			return IngestResult{}, err
		}
		engine.Queue = queue
	}
	records := make([]audit.Event, 0, len(events))
	for _, evt := range events {
		record, _, err := engine.DecideEvent(ctx, evt)
		if err != nil {
			return IngestResult{}, err
		}
		records = append(records, record)
	}
	if err := sink.Close(); err != nil {
		return IngestResult{}, err
	}
	result := IngestResult{
		Ingested: len(events),
		Policy:   policyPath,
		Audit:    opts.AuditPath,
		Records:  records,
	}
	if opts.EnableAirlock {
		airlockOpts := opts.Airlock
		if airlockOpts.PolicyPath == "" {
			airlockOpts.PolicyPath = DefaultAirlockPolicyPath
		}
		if airlockOpts.AuditPath == "" {
			airlockOpts.AuditPath = opts.AuditPath
		}
		if airlockOpts.Now == nil {
			airlockOpts.Now = opts.Now
		}
		if airlockOpts.NewID == nil {
			airlockOpts.NewID = opts.NewID
		}
		airlocks, err := EvaluateAirlockForEvents(ctx, events, airlockOpts)
		if err != nil {
			return IngestResult{}, err
		}
		result.Airlocks = airlocks
	}
	return result, nil
}

func ResolvePolicyPath(explicitPath, storePath, fallback string) (string, error) {
	if explicitPath != "" {
		return explicitPath, nil
	}
	if storePath != "" {
		store, err := policy.LoadStore(storePath)
		if err != nil {
			return "", err
		}
		if active, ok := store.ActiveBundle(); ok {
			return active.Path, nil
		}
	}
	if fallback != "" {
		return fallback, nil
	}
	return "", fmt.Errorf("policy path is required")
}

type AirlockOptions struct {
	PolicyPath string
	StorePath  string
	AuditPath  string
	Now        func() time.Time
	NewID      func() string
}

type AirlockResult struct {
	Behavior airlock.Behavior  `json:"behavior"`
	Record   audit.Event       `json:"record"`
	Decision arbiterx.Decision `json:"decision"`
	Session  *airlock.Session  `json:"session,omitempty"`
}

func EvaluateAirlockForEvents(ctx context.Context, events []event.Event, opts AirlockOptions) ([]AirlockResult, error) {
	accumulators := map[string]*airlock.Accumulator{}
	for _, evt := range events {
		key := evt.Subject.String()
		if key == "" {
			key = "unknown"
		}
		acc := accumulators[key]
		if acc == nil {
			acc = airlock.NewAccumulator(key)
			accumulators[key] = acc
		}
		acc.Observe(evt)
	}
	candidates := make([]airlock.Behavior, 0, len(accumulators))
	for _, acc := range accumulators {
		behavior := acc.Behavior()
		if behavior.Subject == "" {
			behavior.Subject = "unknown"
		}
		if shouldEvaluateAirlock(behavior) {
			candidates = append(candidates, behavior)
		}
	}
	if len(candidates) == 0 {
		return nil, nil
	}
	policyPath := opts.PolicyPath
	if policyPath == "" {
		policyPath = DefaultAirlockPolicyPath
	}
	bundle, err := arbiterx.CompileFile(policyPath)
	if err != nil {
		return nil, err
	}
	sink, err := audit.NewJSONLSink(opts.AuditPath)
	if err != nil {
		return nil, err
	}
	defer sink.Close()
	engine := NewEngine(bundle, sink)
	if opts.Now != nil {
		engine.Now = opts.Now
	}
	if opts.NewID != nil {
		engine.NewID = opts.NewID
	}
	var store *airlock.Store
	if opts.StorePath != "" {
		store, err = airlock.LoadStore(opts.StorePath)
		if err != nil {
			return nil, err
		}
	}
	results := make([]AirlockResult, 0, len(candidates))
	for i, behavior := range candidates {
		now := engine.now()
		input := event.Event{
			ID:      fmt.Sprintf("evt_airlock_%d_%d", now.UnixNano(), i),
			Kind:    "behavior.summary",
			Subject: subject.NewProcessTree(behavior.Subject, 0),
			Fields: map[string]any{
				"exec_count":             behavior.ExecCount,
				"unique_network_targets": behavior.UniqueNetworkTargets,
				"touched_secret_paths":   behavior.TouchedSecretPaths,
				"rewritten_files":        behavior.RewrittenFiles,
				"entropy_increase_score": behavior.EntropyIncreaseScore,
			},
		}
		record, decision, err := engine.DecideFacts(ctx, input, []arbiterx.Fact{behavior.Fact()})
		if err != nil {
			return nil, err
		}
		result := AirlockResult{Behavior: behavior, Record: record, Decision: decision}
		if decision.Selected != nil && decision.Selected.Name == arbiterx.OutcomeEnterAirlock && store != nil {
			session, err := store.Enter(fmt.Sprintf("airlock-%d-%d", now.UnixNano(), i), subject.NewProcessTree(behavior.Subject, 0), decision.Selected.Reason(), now)
			if err != nil {
				return nil, err
			}
			result.Session = &session
		}
		results = append(results, result)
	}
	if store != nil {
		if err := store.Save(opts.StorePath); err != nil {
			return nil, err
		}
	}
	return results, nil
}

func shouldEvaluateAirlock(behavior airlock.Behavior) bool {
	return behavior.UniqueNetworkTargets > 50 && behavior.ExecCount > 20 ||
		behavior.RewrittenFiles > 100 && behavior.EntropyIncreaseScore > 0.8
}
