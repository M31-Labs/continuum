package horizon

import (
	"testing"

	"m31labs.dev/continuum/capability"
	"m31labs.dev/continuum/event"
)

func FuzzParseEventEnvelope(f *testing.F) {
	for _, seed := range [][]byte{
		[]byte(`{"id":"hzn_exec","capability":"kernel.process.exec.observe","output":"ExecEvent","subject":{"kind":"agent","session":"agent-42"},"fields":{"pid":42,"comm":"go","argv_text":"go test ./..."}}`),
		[]byte(`{"capability":"kernel.file.open.observe","output":"FileAccessEvent","fields":{"path":"/repo/main.go","op":"read"}}`),
		[]byte(`{"capability":"kernel.network.connect.observe","output":"NetworkConnectEvent","fields":{"host":"github.com","ip":"140.82.112.3","port":443}}`),
		[]byte(`{"capability":""}`),
		[]byte(`{}`),
		[]byte(`not-json`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		envelope, ok, err := ParseEventEnvelope(data)
		if err != nil || !ok {
			return
		}
		capabilityDecl := capability.Capability{
			Name:   envelope.Capability,
			Kind:   capability.KindSource,
			Output: envelope.Output,
		}
		evt, err := ConvertEventEnvelope(envelope, capabilityDecl)
		if err != nil {
			t.Fatalf("convert parsed envelope: %v", err)
		}
		_ = event.Normalize(evt)
	})
}
