package capability

type Danger string

const (
	DangerObserve     Danger = "observe"
	DangerSoftControl Danger = "soft-control"
	DangerEnforcement Danger = "enforcement"
	DangerDestructive Danger = "destructive"
	DangerPrivileged  Danger = "privileged"
)
