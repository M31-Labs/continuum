package runtime

import (
	"fmt"
	"strings"

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
	paths = paths.withDefaults()
	status := ReadinessStatus{Ready: true}
	status.add("registry", daemon != nil && daemon.Registry != nil && len(daemon.Registry.List()) > 0, "daemon registry is empty")
	policyPath, err := ResolvePolicyPath(paths.PolicyBundle, paths.PolicyStore, DefaultPolicyPath)
	if err != nil {
		status.add("policy", false, err.Error())
	} else if bundle, err := arbiterx.CompileFile(policyPath); err != nil {
		status.add("policy", false, err.Error())
	} else if _, err := arbiterx.ValidatePolicyInputs(bundle); err != nil {
		status.add("policy inputs", false, err.Error())
	} else if _, err := ValidateOutcomeRoutes(bundle, daemon.Registry); err != nil {
		status.add("policy routes", false, err.Error())
	} else {
		status.add("policy", true, "")
		status.add("policy inputs", true, "")
		status.add("policy routes", true, "")
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

func (s ReadinessStatus) Err() error {
	if s.Ready {
		return nil
	}
	var failures []string
	for _, check := range s.Checks {
		if check.OK {
			continue
		}
		failures = append(failures, fmt.Sprintf("%s: %s", check.Name, check.Error))
	}
	if len(failures) == 0 {
		return fmt.Errorf("daemon readiness failed")
	}
	return fmt.Errorf("daemon readiness failed: %s", strings.Join(failures, "; "))
}

func (s *ReadinessStatus) add(name string, ok bool, message string) {
	check := ReadinessCheck{Name: name, OK: ok}
	if !ok {
		s.Ready = false
		check.Error = message
	}
	s.Checks = append(s.Checks, check)
}
