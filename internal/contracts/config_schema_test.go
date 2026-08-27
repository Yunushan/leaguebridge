package contracts

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/Yunushan/leaguebridge/internal/config"
)

const configSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/config.schema.json"

func TestGeneratedConfigurationsConformToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/config.schema.json", configSchemaID)
	for _, route := range []config.Route{config.RouteWindows, config.RouteMacOS} {
		route := route
		t.Run(string(route), func(t *testing.T) {
			data, err := config.MarshalExampleForRoute(route)
			if err != nil {
				t.Fatal(err)
			}
			var document any
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(document); err != nil {
				t.Fatalf("schema rejected generated %s configuration: %v", route, err)
			}
		})
	}
}

func TestPublicConfigurationSchemaRetainsOnlyStrictLegacyV1Compatibility(t *testing.T) {
	schema := compileOffline(t, "schemas/config.schema.json", configSchemaID)
	legacy := map[string]any{
		"schema_version": json.Number("1"),
		"backend":        "remote-physical-windows",
		"remote_windows": map[string]any{
			"host":                    "gaming-pc.local",
			"app":                     "League of Legends",
			"client":                  "auto",
			"physical_host_confirmed": true,
		},
	}
	if err := schema.Validate(legacy); err != nil {
		t.Fatalf("schema rejected strict legacy v1 configuration: %v", err)
	}

	legacy["backend"] = "remote-physical-macos"
	if err := schema.Validate(legacy); err == nil {
		t.Fatal("schema accepted a legacy macOS backend")
	}
	legacy["backend"] = "remote-physical-windows"
	legacy["remote_macos"] = legacy["remote_windows"]
	if err := schema.Validate(legacy); err == nil {
		t.Fatal("schema accepted an unknown parallel host field")
	}
}

func TestPublicConfigurationSchemaRejectsSecurityRelevantShapeDrift(t *testing.T) {
	schema := compileOffline(t, "schemas/config.schema.json", configSchemaID)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "legacy alias in v2",
			body: `{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true},"backend":"remote-physical-windows"}`,
		},
		{
			name: "nested credential",
			body: `{"schema_version":2,"route_id":"physical-windows-remote","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true,"password":"secret"}}`,
		},
		{
			name: "unsupported route",
			body: `{"schema_version":2,"route_id":"wine","remote_host":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true}}`,
		},
		{
			name: "unsupported client",
			body: `{"schema_version":2,"route_id":"physical-macos-remote","remote_host":{"host":"mac.local","app":"League","client":"shell","physical_host_confirmed":true}}`,
		},
		{
			name: "missing required app",
			body: `{"schema_version":2,"route_id":"physical-macos-remote","remote_host":{"host":"mac.local","client":"auto","physical_host_confirmed":true}}`,
		},
		{
			name: "legacy nested unknown field",
			body: `{"schema_version":1,"backend":"remote-physical-windows","remote_windows":{"host":"pc.local","app":"League","client":"auto","physical_host_confirmed":true,"token":"secret"}}`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var document any
			decoder := json.NewDecoder(bytes.NewBufferString(test.body))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatal(err)
			}
			if err := schema.Validate(document); err == nil {
				t.Fatal("schema accepted invalid configuration shape")
			}
		})
	}
}
