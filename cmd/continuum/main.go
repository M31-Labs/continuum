package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const commandList = "run, ingest, sessions, agent, status, capabilities, policy, grant, audit, explain, replay, airlock"

type usageError string

func (e usageError) Error() string { return string(e) }

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		var usage usageError
		if errors.As(err, &usage) {
			fmt.Fprintln(os.Stderr, usage.Error())
		} else {
			fmt.Fprintln(os.Stderr, "continuum:", err)
		}
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usageError("Usage: continuum <command>\nCommands: " + commandList)
	}
	switch args[0] {
	case "run":
		return runRun(args[1:], stdout, stderr)
	case "ingest":
		return runIngest(args[1:], stdout, stderr)
	case "sessions":
		return runSessions(args[1:], stdout, stderr)
	case "agent":
		return runAgent(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "capabilities":
		return runCapabilities(args[1:], stdout, stderr)
	case "policy":
		return runPolicy(args[1:], stdout, stderr)
	case "grant":
		return runGrant(args[1:], stdout, stderr)
	case "audit":
		return runAudit(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "replay":
		return runReplay(args[1:], stdout, stderr)
	case "airlock":
		return runAirlock(args[1:], stdout, stderr)
	default:
		return usageError(fmt.Sprintf("Unknown command: %s\nCommands: %s", args[0], commandList))
	}
}
