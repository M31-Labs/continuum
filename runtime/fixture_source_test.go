package runtime

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"m31labs.dev/continuum/event"
)

func TestFixtureSourceEmitsInlineAndFileEvents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(path, []byte(`{"id":"evt_file","kind":"network.connect","fields":{"host":"github.com","port":443}}`+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	src := FixtureSource{
		NameValue: "synthetic",
		Path:      path,
		Events: []event.Event{{
			ID:   "evt_inline",
			Kind: event.KindProcessExec,
		}},
	}
	var got []event.Event
	if err := RunSource(context.Background(), src, func(_ context.Context, evt event.Event) error {
		got = append(got, evt)
		return nil
	}); err != nil {
		t.Fatalf("RunSource: %v", err)
	}
	if len(got) != 2 || got[0].ID != "evt_inline" || got[1].ID != "evt_file" {
		t.Fatalf("events = %+v", got)
	}
}
