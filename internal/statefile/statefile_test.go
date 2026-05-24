package statefile

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestWriteJSONIsAtomicAndPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "store.json")
	if err := WriteJSON(path, map[string]any{"value": "first"}); err != nil {
		t.Fatalf("WriteJSON first: %v", err)
	}
	if err := WriteJSON(path, map[string]any{"value": "second"}); err != nil {
		t.Fatalf("WriteJSON second: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var got map[string]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("json: %v data=%s", err, string(data))
	}
	if got["value"] != "second" {
		t.Fatalf("value = %q", got["value"])
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat file: %v", err)
	}
	if got := info.Mode().Perm(); got != FileMode {
		t.Fatalf("file mode = %v, want %v", got, FileMode)
	}
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got&0077 != 0 {
		t.Fatalf("dir mode allows group/other access: %v", got)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "store.json", ".store.json.lock":
		default:
			t.Fatalf("unexpected temp file left behind: %s", entry.Name())
		}
	}
}

func TestOpenAppendCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit", "audit.jsonl")
	f, err := OpenAppend(path)
	if err != nil {
		t.Fatalf("OpenAppend: %v", err)
	}
	if _, err := f.WriteString("{}\n"); err != nil {
		t.Fatalf("WriteString: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := info.Mode().Perm(); got != FileMode {
		t.Fatalf("file mode = %v, want %v", got, FileMode)
	}
}

func TestWriteTightensExistingStateDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	path := filepath.Join(dir, "store.json")
	if err := WriteJSON(path, map[string]string{"ok": "true"}); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("Stat dir: %v", err)
	}
	if got := info.Mode().Perm(); got != DirMode {
		t.Fatalf("dir mode = %v, want %v", got, DirMode)
	}
}

func TestWithLockSerializesStateWrites(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("state file locking is advisory on unix-like targets only")
	}
	path := filepath.Join(t.TempDir(), "state", "store.json")
	locked := make(chan struct{})
	release := make(chan struct{})
	heldDone := make(chan error, 1)
	go func() {
		heldDone <- WithLock(path, func() error {
			close(locked)
			<-release
			return nil
		})
	}()
	<-locked

	writeDone := make(chan error, 1)
	go func() {
		writeDone <- WriteJSON(path, map[string]string{"value": "after"})
	}()

	select {
	case err := <-writeDone:
		t.Fatalf("WriteJSON completed while lock was held: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	if err := <-heldDone; err != nil {
		t.Fatalf("WithLock: %v", err)
	}
	select {
	case err := <-writeDone:
		if err != nil {
			t.Fatalf("WriteJSON: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WriteJSON did not complete after lock release")
	}
}
