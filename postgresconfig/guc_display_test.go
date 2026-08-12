package postgresconfig

import "testing"

func TestFormatGucDisplay(t *testing.T) {
	tests := []struct {
		name    string
		setting string
		unit    string
		want    string
	}{
		{name: "block multiplier scales to kB", setting: "16", unit: "8kB", want: "128kB"},
		{name: "block multiplier normalizes to MB", setting: "16384", unit: "8kB", want: "128MB"},
		{name: "block multiplier normalizes to GB", setting: "131072", unit: "8kB", want: "1GB"},
		{name: "plain kB stays as written", setting: "4096", unit: "kB", want: "4096kB"},
		{name: "plain MB stays as written", setting: "64", unit: "MB", want: "64MB"},
		{name: "no unit returns setting", setting: "200", unit: "", want: "200"},
		{name: "empty setting returns empty", setting: "", unit: "8kB", want: ""},
		{name: "time unit untouched", setting: "5000", unit: "ms", want: "5000ms"},
		{name: "negative sentinel drops unit", setting: "-1", unit: "8kB", want: "-1"},
		{name: "negative with plain unit unchanged", setting: "-1", unit: "ms", want: "-1ms"},
		{name: "non numeric with unit unchanged", setting: "auto", unit: "8kB", want: "auto8kB"},
		{name: "zero blocks", setting: "0", unit: "8kB", want: "0B"},
		{name: "string value no unit", setting: "worker", unit: "", want: "worker"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FormatGucDisplay(tt.setting, tt.unit); got != tt.want {
				t.Fatalf("FormatGucDisplay(%q,%q)=%q want %q", tt.setting, tt.unit, got, tt.want)
			}
		})
	}
}

func TestSplitUnitMultiplier(t *testing.T) {
	tests := []struct {
		name     string
		unit     string
		wantMult int64
		wantBase string
		wantOK   bool
	}{
		{name: "8kB blocks", unit: "8kB", wantMult: 8, wantBase: "kB", wantOK: true},
		{name: "16MB blocks", unit: "16MB", wantMult: 16, wantBase: "MB", wantOK: true},
		{name: "plain kB", unit: "kB", wantMult: 1, wantBase: "kB", wantOK: true},
		{name: "plain ms", unit: "ms", wantMult: 1, wantBase: "ms", wantOK: true},
		{name: "empty invalid", unit: "", wantOK: false},
		{name: "digits only invalid", unit: "8", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mult, base, ok := splitUnitMultiplier(tt.unit)
			if ok != tt.wantOK {
				t.Fatalf("ok=%v want %v", ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if mult != tt.wantMult || base != tt.wantBase {
				t.Fatalf("got (%d,%q) want (%d,%q)", mult, base, tt.wantMult, tt.wantBase)
			}
		})
	}
}

func TestHumanByteSize(t *testing.T) {
	tests := []struct {
		name  string
		bytes int64
		want  string
	}{
		{name: "zero", bytes: 0, want: "0B"},
		{name: "exact kB", bytes: 131072, want: "128kB"},
		{name: "exact MB", bytes: 134217728, want: "128MB"},
		{name: "exact GB", bytes: 1073741824, want: "1GB"},
		{name: "odd byte count", bytes: 1234, want: "1234B"},
		{name: "negative", bytes: -131072, want: "-128kB"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := humanByteSize(tt.bytes); got != tt.want {
				t.Fatalf("humanByteSize(%d)=%q want %q", tt.bytes, got, tt.want)
			}
		})
	}
}
