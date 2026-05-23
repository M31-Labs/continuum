package subject

import "testing"

func TestParseCgroupDataPrefersUnifiedOrMostSpecificPath(t *testing.T) {
	if got := ParseCgroupData("0::/user.slice/user-1000.slice/session-2.scope\n"); got != "/user.slice/user-1000.slice/session-2.scope" {
		t.Fatalf("cgroup v2 path = %q", got)
	}
	data := "11:memory:/user.slice\n10:cpu,cpuacct:/user.slice/user-1000.slice/session-2.scope\n"
	if got := ParseCgroupData(data); got != "/user.slice/user-1000.slice/session-2.scope" {
		t.Fatalf("cgroup v1 path = %q", got)
	}
}
