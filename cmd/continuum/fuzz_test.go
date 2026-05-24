package main

import (
	"testing"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

func FuzzEventFromRawJSON(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"id":"evt_file","kind":"file.open","subject":{"kind":"agent","session":"agent-42","repo_root":"/repo","agent_name":"claude"},"fields":{"path":"/repo/main.go","op":"read"}}`),
		[]byte(`{"id":"audit_1","input_event":{"id":"evt_net","kind":"network.connect","subject":{"kind":"agent","session":"agent-42"},"fields":{"host":"github.com","ip":"140.82.112.3","port":443}}}`),
		[]byte(`{"id":"hzn_1","capability":"kernel.process.exec.observe","subject":{"kind":"agent","session":"agent-42","repo_root":"/repo"},"fields":{"pid":123,"comm":"go","argv_text":"go test ./..."}}`),
		[]byte(`[]`),
		[]byte(`{}`),
		[]byte(`not-json`),
	} {
		f.Add(seed)
	}
	caps := map[string]capability.Capability{
		"kernel.process.exec.observe": {
			Name:   "kernel.process.exec.observe",
			Kind:   capability.KindSource,
			Output: "ExecEvent",
		},
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		evt, err := eventFromRawJSON(data, caps)
		if err != nil {
			return
		}
		_ = event.Normalize(evt)
	})
}
