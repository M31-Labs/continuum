package event

import "m31labs.dev/continuum/subject"

const (
	KindFileAccess = "file.access"
	KindFileOpen   = "file.open"
)

func NewFileAccess(subj subject.Subject, path, op string) Event {
	return Event{
		Kind:    KindFileAccess,
		Subject: subj,
		Fields: map[string]any{
			"path": path,
			"op":   op,
		},
	}
}
