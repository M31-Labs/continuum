package replay

type Diff struct {
	EventID string `json:"event_id"`
	Before  string `json:"before"`
	After   string `json:"after"`
}

func Compare(before, after []Result) []Diff {
	byID := map[string]string{}
	for _, item := range before {
		if item.Decision.Selected != nil {
			byID[item.Event.ID] = item.Decision.Selected.Decision()
		}
	}
	var diffs []Diff
	for _, item := range after {
		afterDecision := ""
		if item.Decision.Selected != nil {
			afterDecision = item.Decision.Selected.Decision()
		}
		if beforeDecision := byID[item.Event.ID]; beforeDecision != afterDecision {
			diffs = append(diffs, Diff{EventID: item.Event.ID, Before: beforeDecision, After: afterDecision})
		}
	}
	return diffs
}
