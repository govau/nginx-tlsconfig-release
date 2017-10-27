package env

import (
	"testing"

	"github.com/cloudfoundry-community/go-cfenv"
)

func TestWithUPSLookup(t *testing.T) {
	services := cfenv.Services{"service-a-label": []cfenv.Service{
		{
			Name: "service-1",
			Credentials: map[string]interface{}{
				"A":     "a",
				"Int":   1,
				"Bool":  true,
				"Float": 0.42,
			},
		},
	}}

	tests := []struct {
		testName    string
		app         *cfenv.App
		serviceName string
		name        string
		want        string
	}{
		{
			testName:    "app nil",
			app:         nil,
			serviceName: "service-1",
			name:        "A",
			want:        "",
		},
		{
			testName:    "service name empty",
			app:         &cfenv.App{},
			serviceName: "",
			name:        "A",
			want:        "",
		},
		{
			testName: "service not found",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-z",
			name:        "A",
			want:        "",
		},
		{
			testName: "service found, environment variable not found",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-1",
			name:        "Z",
			want:        "",
		},
		{
			testName: "service found, environment variable found",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-1",
			name:        "A",
			want:        "a",
		},
		{
			testName: "service found, environment variable found, value not castable to string (1)",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-1",
			name:        "Int",
			want:        "1",
		},
		{
			testName: "service found, environment variable found, value not castable to string (2)",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-1",
			name:        "Bool",
			want:        "true",
		},
		{
			testName: "service found, environment variable found, value not castable to string (3)",
			app: &cfenv.App{
				Services: services,
			},
			serviceName: "service-1",
			name:        "Float",
			want:        "0.42",
		},
	}
	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			vs := NewVarSet(WithUPSLookup(tt.app, tt.serviceName))
			if got := vs.String(tt.name, ""); got != tt.want {
				t.Errorf("String(%q) = %q, want %q", tt.name, got, tt.want)
			}
		})
	}
}
