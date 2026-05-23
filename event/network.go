package event

import "m31labs.dev/continuum/subject"

const KindNetworkConnect = "network.connect"

func NewNetworkConnect(subj subject.Subject, host, ip string, port int) Event {
	return Event{
		Kind:    KindNetworkConnect,
		Subject: subj,
		Fields: map[string]any{
			"host": host,
			"ip":   ip,
			"port": port,
		},
	}
}
