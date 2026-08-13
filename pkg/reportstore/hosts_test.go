package reportstore

import "testing"

func TestIsLoopbackHost(t *testing.T) {
	for _, h := range []string{"", "localhost", "LOCALHOST", "127.0.0.1", "::1", " 127.0.0.1 "} {
		if !IsLoopbackHost(h) {
			t.Fatalf("expected loopback %q", h)
		}
	}
	for _, h := range []string{"db1", "10.0.0.5", "postgres.internal"} {
		if IsLoopbackHost(h) {
			t.Fatalf("expected non-loopback %q", h)
		}
	}
}

func TestResolveTargetHost(t *testing.T) {
	tests := []struct {
		name  string
		pg    string
		agent string
		want  string
	}{
		{name: "loopback uses agent", pg: "localhost", agent: "LAPTOP-F3DNR67K", want: "laptop-f3dnr67k"},
		{name: "127 uses agent", pg: "127.0.0.1", agent: "postgreshost1", want: "postgreshost1"},
		{name: "ipv6 loopback uses agent", pg: "::1", agent: "node-a", want: "node-a"},
		{name: "loopback no agent stays localhost", pg: "localhost", agent: "", want: "localhost"},
		{name: "real host unchanged", pg: "10.0.0.5", agent: "laptop", want: "10.0.0.5"},
		{name: "hostname unchanged", pg: "db.prod.local", agent: "collector-1", want: "db.prod.local"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveTargetHost(tt.pg, tt.agent); got != tt.want {
				t.Fatalf("ResolveTargetHost(%q,%q)=%q want %q", tt.pg, tt.agent, got, tt.want)
			}
		})
	}
}
