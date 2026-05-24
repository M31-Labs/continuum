package audit

import "fmt"

type Filter struct {
	Decision string
	Subject  string
	Kind     string
	Limit    int
	Offset   int
}

func Find(events []Event, id string) (Event, bool) {
	for _, evt := range events {
		if evt.ID == id {
			return evt, true
		}
	}
	return Event{}, false
}

func LoadAndFind(path, id string) (Event, error) {
	events, err := ReadJSONL(path)
	if err != nil {
		return Event{}, err
	}
	if evt, ok := Find(events, id); ok {
		return evt, nil
	}
	return Event{}, fmt.Errorf("audit event %q not found", id)
}

func Query(events []Event, filter Filter) []Event {
	out := make([]Event, 0, len(events))
	for _, evt := range events {
		if filter.Decision != "" && evt.Decision != filter.Decision {
			continue
		}
		if filter.Subject != "" && evt.Subject.String() != filter.Subject && evt.Subject.Session != filter.Subject && evt.Subject.ID != filter.Subject {
			continue
		}
		if filter.Kind != "" && evt.InputEvent.Kind != filter.Kind {
			continue
		}
		out = append(out, evt)
	}
	if filter.Offset > 0 {
		if filter.Offset >= len(out) {
			return nil
		}
		out = out[filter.Offset:]
		if filter.Limit > 0 && len(out) > filter.Limit {
			return out[:filter.Limit]
		}
		return out
	}
	if filter.Limit > 0 && len(out) > filter.Limit {
		return out[len(out)-filter.Limit:]
	}
	return out
}
