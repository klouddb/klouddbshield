package reportstore

import "strings"

// NormalizeHost maps loopback aliases to localhost for stable target_id.
func NormalizeHost(host string) string {
	h := strings.TrimSpace(strings.ToLower(host))
	if h == "" || h == "127.0.0.1" || h == "::1" {
		return "localhost"
	}
	return strings.TrimSpace(host)
}

// Collectors often set [postgres] host = "localhost" / "127.0.0.1".
func IsLoopbackHost(host string) bool {
	h := strings.TrimSpace(strings.ToLower(host))
	return h == "" || h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// ([app] hostname, which defaults to os.Hostname) so multiple collectors
func ResolveTargetHost(pgHost, agentHostname string) string {
	agent := strings.ToLower(strings.TrimSpace(agentHostname))
	if IsLoopbackHost(pgHost) {
		if agent != "" {
			return agent
		}
		return "localhost"
	}
	return NormalizeHost(pgHost)
}
