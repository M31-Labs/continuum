package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestAuditSchemaDocCoversEventJSONFields(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "docs", "audit-schema.json"))
	if err != nil {
		t.Fatalf("read audit schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatalf("parse audit schema: %v", err)
	}
	if got, _ := schema["$id"].(string); got != "https://m31labs.dev/continuum/schemas/audit-event-v1.json" {
		t.Fatalf("schema $id = %q", got)
	}

	props := objectAt(t, schema, "properties")
	for _, field := range jsonFieldNames[Event]() {
		if _, ok := props[field]; !ok {
			t.Fatalf("schema missing audit.Event JSON field %q", field)
		}
	}

	required := stringSliceAt(t, schema, "required")
	wantRequired := []string{"decision", "id", "input_event", "outcome", "subject", "time"}
	slices.Sort(required)
	if !slices.Equal(required, wantRequired) {
		t.Fatalf("required fields = %+v, want %+v", required, wantRequired)
	}
}

func TestAuditSchemaDocIsPackagedForRelease(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("..", "docs", "audit-schema.md"))
	if err != nil {
		t.Fatalf("read audit schema docs: %v", err)
	}
	text := string(doc)
	for _, want := range []string{
		"audit-schema-docs-$VERSION.tar.gz",
		"audit-schema-docs-$VERSION.sha256",
		"audit-schema-docs-$VERSION.sha256.sigstore.json",
		"cosign verify-blob",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("audit schema docs missing %q", want)
		}
	}
}

func jsonFieldNames[T any]() []string {
	var zero T
	typ := reflect.TypeOf(zero)
	out := make([]string, 0, typ.NumField())
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		tag := field.Tag.Get("json")
		if tag == "" || tag == "-" {
			continue
		}
		name, _, _ := strings.Cut(tag, ",")
		if name != "" {
			out = append(out, name)
		}
	}
	slices.Sort(out)
	return out
}

func objectAt(t *testing.T, object map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := object[key].(map[string]any)
	if !ok {
		t.Fatalf("schema key %q is %T, want object", key, object[key])
	}
	return value
}

func stringSliceAt(t *testing.T, object map[string]any, key string) []string {
	t.Helper()
	values, ok := object[key].([]any)
	if !ok {
		t.Fatalf("schema key %q is %T, want array", key, object[key])
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		item, ok := value.(string)
		if !ok {
			t.Fatalf("schema key %q item is %T, want string", key, value)
		}
		out = append(out, item)
	}
	return out
}
