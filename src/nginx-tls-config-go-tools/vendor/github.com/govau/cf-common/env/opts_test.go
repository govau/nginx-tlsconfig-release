package env

import (
	"fmt"
	"os"
	"testing"
)

func TestWithOSLookup(t *testing.T) {
	osEnv := map[string]string{
		fmt.Sprintf("%s_%s", t.Name(), "A"): "a",
	}

	tests := []struct {
		testName string
		name     string
		def      string
		want     string
	}{
		{
			testName: "exists",
			name:     fmt.Sprintf("%s_%s", t.Name(), "A"),
			want:     "a",
		},
		{
			testName: "not exists",
			name:     fmt.Sprintf("%s_%s", t.Name(), "Z"),
			def:      "z",
			want:     "z",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			for k, v := range osEnv {
				os.Setenv(k, v)
				defer os.Unsetenv(k)
			}
			vs := NewVarSet(WithOSLookup())
			if got := vs.String(tt.name, tt.def); got != tt.want {
				t.Errorf("String(%q, %q) = %q, want %q", tt.name, tt.def, got, tt.want)
			}
		})
	}
}

func TestWithMapLookup(t *testing.T) {
	const lookupName = "A"

	tests := []struct {
		name string
		m    map[string]string
		want string
	}{
		{name: "exists", m: map[string]string{"A": "a"}, want: "a"},
		{name: "not exists", m: map[string]string{"Z": "z"}, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vs := NewVarSet(WithMapLookup(tt.m))
			if got := vs.String(lookupName, ""); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", lookupName, got, tt.want)
			}
		})
	}
}
