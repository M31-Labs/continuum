package event

import "m31labs.dev/continuum/subject"

const (
	KindProcessExec = "process.exec"
	KindProcessExit = "process.exit"
)

func NewProcessExec(subj subject.Subject, fields map[string]any) Event {
	return Event{Kind: KindProcessExec, Subject: subj, Fields: fields}
}

func NewProcessExit(subj subject.Subject, fields map[string]any) Event {
	return Event{Kind: KindProcessExit, Subject: subj, Fields: fields}
}
