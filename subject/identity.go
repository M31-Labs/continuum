package subject

func SameSession(a, b Subject) bool {
	return a.Session != "" && a.Session == b.Session
}

func Matches(want, got Subject) bool {
	if want.ID != "" && got.ID != "" {
		return want.ID == got.ID
	}
	if want.Session != "" && got.Session != "" {
		return want.Session == got.Session
	}
	if want.PID != 0 && got.PID != 0 {
		return want.PID == got.PID
	}
	return want.Kind != "" && want.Kind == got.Kind
}
