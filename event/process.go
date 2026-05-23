package event

import "m31labs.dev/continuum/subject"

const KindProcessExec = "process.exec"

func NewProcessExec(subj subject.Subject, fields map[string]any) Event {
	return Event{Kind: KindProcessExec, Subject: subj, Fields: fields}
}
