package capability

func BuiltIns() []Capability {
	return []Capability{
		{Name: "observe.audit", Kind: KindSink, Owner: "continuum", Input: "Decision", Danger: DangerObserve, Backend: "observe", Description: "record decisions without enforcement"},
		{Name: "noop.enforcement", Kind: KindWorker, Owner: "continuum", Input: "Outcome", Output: "NoopResult", Danger: DangerObserve, Backend: "noop", Description: "accepts actions and does nothing"},
		{Name: "approval.cli.ask", Kind: KindSink, Owner: "continuum", Input: "AskHuman", Danger: DangerSoftControl, Backend: "cli", Description: "ask a human to approve a governed outcome"},
		{Name: "continuum.airlock.enter", Kind: KindWorker, Owner: "continuum", Input: "EnterAirlock", Output: "AirlockState", Danger: DangerSoftControl, Backend: "observe", Description: "record airlock containment intent"},
		{Name: "kernel.file.open.deny", Kind: KindWorker, Owner: "continuum", Input: "Deny", Danger: DangerEnforcement, Backend: "observe", Description: "deny file open through the configured file backend"},
		{Name: "kernel.network.connect.deny", Kind: KindWorker, Owner: "continuum", Input: "Deny", Danger: DangerEnforcement, Backend: "observe", Description: "deny network connect through the configured network backend"},
		{Name: "kernel.network.connect.grant", Kind: KindWorker, Owner: "continuum", Input: "GrantNetwork", Danger: DangerSoftControl, Backend: "observe", Description: "grant a scoped network connect permission"},
		{Name: "kernel.process.exec.allow", Kind: KindSink, Owner: "continuum", Input: "Allow", Danger: DangerObserve, Backend: "observe", Description: "record allowed process execution"},
		{Name: "kernel.process.exec.deny", Kind: KindWorker, Owner: "continuum", Input: "Deny", Danger: DangerEnforcement, Backend: "observe", Description: "deny process execution through the configured process backend"},
		{Name: "kernel.process.kill", Kind: KindWorker, Owner: "continuum", Input: "KillProcess", Danger: DangerDestructive, Backend: "observe", Description: "kill a process through the configured process backend", Requires: []Requirement{{Name: "explicit-enable", Reason: "destructive process control must be deliberately enabled"}}},
		{Name: "continuum.outcome.deny", Kind: KindSink, Owner: "continuum", Input: "Deny", Danger: DangerObserve, Backend: "observe", Description: "record an unrouted denial outcome"},
	}
}
