package runtime

import (
	"m31labs.dev/continuum/airlock"
	"m31labs.dev/continuum/arbiterx"
	"m31labs.dev/continuum/capability"
)

type ReadinessStatus struct {
	Ready  bool             `json:"ready"`
	Checks []ReadinessCheck `json:"checks"`
}

type ReadinessCheck struct {
	Name  string `json:"name"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func CheckReadiness(daemon *Daemon, paths StatePaths) ReadinessStatus {
	status := ReadinessStatus{Ready: true}
	status.add("registry", daemon != nil && daemon.Registry != nil && len(daemon.Registry.List()) > 0, "daemon registry is empty")
	policyPath, err := ResolvePolicyPath(paths.PolicyBundle, paths.PolicyStore, DefaultPolicyPath)
	if err != nil {
		status.add("policy", false, err.Error())
	} else if _, err := arbiterx.CompileFile(policyPath); err != nil {
		status.add("policy", false, err.Error())
	} else {
		status.add("policy", true, "")
	}
	if _, err := LoadSessionStore(paths.Sessions); err != nil {
		status.add("sessions", false, err.Error())
	} else {
		status.add("sessions", true, "")
	}
	if _, err := capability.LoadGrantStore(paths.Grants); err != nil {
		status.add("grants", false, err.Error())
	} else {
		status.add("grants", true, "")
	}
	if _, err := LoadDeliveryStore(paths.Deliveries); err != nil {
		status.add("deliveries", false, err.Error())
	} else {
		status.add("deliveries", true, "")
	}
	if _, err := airlock.LoadStore(paths.Airlock); err != nil {
		status.add("airlock", false, err.Error())
	} else {
		status.add("airlock", true, "")
	}
	return status
}

func (s *ReadinessStatus) add(name string, ok bool, message string) {
	check := ReadinessCheck{Name: name, OK: ok}
	if !ok {
		s.Ready = false
		check.Error = message
	}
	s.Checks = append(s.Checks, check)
}
