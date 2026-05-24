package probes

type ExecEvent struct {
	PID  uint32
	PPID uint32
	Comm [16]byte
}
