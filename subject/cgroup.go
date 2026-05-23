package subject

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func NewCgroup(path string) Subject {
	return Subject{
		Kind:   string(KindCgroup),
		ID:     "cgroup:" + path,
		Cgroup: path,
	}
}

func CgroupForPID(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("pid must be positive")
	}
	data, err := os.ReadFile(filepath.Join("/proc", fmt.Sprintf("%d", pid), "cgroup"))
	if err != nil {
		return "", err
	}
	return ParseCgroupData(string(data)), nil
}

func ParseCgroupData(data string) string {
	best := ""
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		if path == "" {
			path = "/"
		}
		if best == "" || len(path) > len(best) {
			best = path
		}
	}
	return best
}
