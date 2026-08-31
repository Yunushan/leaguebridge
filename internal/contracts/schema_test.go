// Package contracts verifies public JSON documents against their pinned,
// offline Draft 2020-12 schemas. Runtime parsers add stricter safety invariants.
package contracts

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Yunushan/leaguebridge/internal/evidence"
	"github.com/Yunushan/leaguebridge/internal/nativepackage"
	"github.com/Yunushan/leaguebridge/internal/packageinfo"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	compatibilitySchemaID = "https://leaguebridge.dev/schemas/compatibility-manifest.schema.json"
	evidenceSchemaID      = "https://leaguebridge.dev/schemas/validation-evidence.schema.json"
	readinessSchemaID     = "https://github.com/Yunushan/leaguebridge/schemas/readiness-scorecard.schema.json"
	packageSchemaID       = "https://github.com/Yunushan/leaguebridge/schemas/package-manifest.schema.json"
	nativePackageSchemaID = "https://github.com/Yunushan/leaguebridge/schemas/native-package-staging.schema.json"
)

func TestRepositoryDocumentsConformToDraft202012Schemas(t *testing.T) {
	tests := []struct {
		name      string
		schema    string
		schemaID  string
		documents []string
	}{
		{
			name:     "compatibility",
			schema:   "schemas/compatibility-manifest.schema.json",
			schemaID: compatibilitySchemaID,
			documents: []string{
				"compatibility/manifest.json",
				"internal/compat/data/manifest.json",
			},
		},
		{
			name:     "readiness",
			schema:   "schemas/readiness-scorecard.schema.json",
			schemaID: readinessSchemaID,
			documents: []string{
				"readiness/scorecard.json",
				"internal/readiness/data/scorecard.json",
			},
		},
		{
			name:     "validation evidence",
			schema:   "schemas/validation-evidence.schema.json",
			schemaID: evidenceSchemaID,
			documents: []string{
				"docs/evidence/examples/host-windows-unverified.json",
				"docs/evidence/examples/host-macos-unverified.json",
				"docs/evidence/examples/client-linux-unverified.json",
				"docs/evidence/examples/session-linux-unverified.json",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			schema := compileOffline(t, test.schema, test.schemaID)
			for _, document := range test.documents {
				document := document
				t.Run(document, func(t *testing.T) {
					instance := decodeRepositoryJSON(t, document)
					if err := schema.Validate(instance); err != nil {
						t.Fatalf("validate %s: %v", document, err)
					}
				})
			}
			if test.name == "validation evidence" {
				record, err := evidence.NewTemplateWithRoute(evidence.RecordHost, "darwin", "arm64", "schema-test", evidence.RoutePhysicalMacOSRemote, time.Date(2026, 8, 30, 12, 0, 0, 0, time.UTC))
				if err != nil {
					t.Fatal(err)
				}
				data, err := json.Marshal(record)
				if err != nil {
					t.Fatal(err)
				}
				instance := decodeJSONBytes(t, data)
				if err := schema.Validate(instance); err != nil {
					t.Fatalf("validation evidence schema rejected a valid macOS host record: %v", err)
				}
			}
		})
	}
}

func TestGeneratedPackageManifestsConformToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/package-manifest.schema.json", packageSchemaID)
	commit := "0123456789abcdef0123456789abcdef01234567"
	tree := "89abcdef0123456789abcdef0123456789abcdef"
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"freebsd", "amd64"}, {"openbsd", "amd64"},
		{"netbsd", "amd64"}, {"dragonfly", "amd64"},
	}
	for _, target := range targets {
		target := target
		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			names, err := packageinfo.ExpectedPayloadNames(target.goos, target.goarch)
			if err != nil {
				t.Fatal(err)
			}
			bodies := make(map[string][]byte, len(names))
			for _, name := range names {
				bodies[name] = []byte("schema fixture for " + name)
			}
			manifest, err := packageinfo.Build("v1.2.3", target.goos, target.goarch, 1787702400, commit, tree, "go1.27.0", bodies)
			if err != nil {
				t.Fatal(err)
			}
			data, err := packageinfo.Marshal(manifest)
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
				t.Fatalf("schema rejected generated %s/%s package manifest: %v", target.goos, target.goarch, err)
			}
		})
	}
}

func TestPackageManifestSchemaRejectsRuntimeAndBuilderOverclaims(t *testing.T) {
	schema := compileOffline(t, "schemas/package-manifest.schema.json", packageSchemaID)
	names, err := packageinfo.ExpectedPayloadNames("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte(name)
	}
	manifest, err := packageinfo.Build("v1.2.3", "linux", "amd64", 1787702400, "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef", "go1.27.0", bodies)
	if err != nil {
		t.Fatal(err)
	}
	data, err := packageinfo.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	document["validation_scope"] = "runtime-validated"
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted a runtime-support claim")
	}
	document["validation_scope"] = packageinfo.ValidationScope
	document["target"].(map[string]any)["required_kernel"] = "OpenBSD"
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted a GOOS/kernel mismatch")
	}
	document["target"].(map[string]any)["required_kernel"] = "Linux"
	payload := document["payload"].([]any)
	payload[0], payload[1] = payload[1], payload[0]
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted reordered payload inventory")
	}
	payload[0], payload[1] = payload[1], payload[0]
	document["provenance"].(map[string]any)["builder_go_version"] = "go1.24.13"
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted a non-production release builder")
	}
	document["provenance"].(map[string]any)["builder_go_version"] = packageinfo.ProductionBuilderGoVersion
	document["target"].(map[string]any)["goarch"] = "arm64"
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted an unsupported linux/arm64 pair")
	}
	document["target"].(map[string]any)["goarch"] = "amd64"
	document["provenance"].(map[string]any)["source_tree"] = strings.Repeat("A", 40)
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted a non-canonical source tree ID")
	}
	document["provenance"].(map[string]any)["source_tree"] = "89abcdef0123456789abcdef0123456789abcdef"
	document["provenance"].(map[string]any)["build_environment"].(map[string]any)["goamd64"] = "v3"
	if err := schema.Validate(document); err == nil {
		t.Fatal("package manifest schema accepted non-canonical amd64 tuning")
	}
}

func TestGeneratedNativePackageStagingManifestsConformToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/native-package-staging.schema.json", nativePackageSchemaID)
	targets := []struct{ goos, goarch string }{
		{"linux", "amd64"}, {"freebsd", "amd64"}, {"openbsd", "amd64"},
		{"netbsd", "amd64"}, {"dragonfly", "amd64"},
	}
	for _, target := range targets {
		target := target
		t.Run(target.goos+"_"+target.goarch, func(t *testing.T) {
			names, err := packageinfo.ExpectedPayloadNames(target.goos, target.goarch)
			if err != nil {
				t.Fatal(err)
			}
			bodies := make(map[string][]byte, len(names))
			for _, name := range names {
				bodies[name] = []byte("native package schema fixture for " + name)
			}
			source, err := packageinfo.Build("v1.2.3", target.goos, target.goarch, 1787702400, "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef", "go1.27.0", bodies)
			if err != nil {
				t.Fatal(err)
			}
			sourceData, err := packageinfo.Marshal(source)
			if err != nil {
				t.Fatal(err)
			}
			for _, family := range nativepackage.PackageFamiliesForTarget(target.goos, target.goarch) {
				family := family
				t.Run(string(family), func(t *testing.T) {
					manifest, err := nativepackage.Build(source, sourceData, strings.Repeat("a", 64), family)
					if err != nil {
						t.Fatal(err)
					}
					data, err := nativepackage.Marshal(manifest)
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
						t.Fatalf("schema rejected %s/%s %s staging manifest: %v", target.goos, target.goarch, family, err)
					}
				})
			}
		})
	}
}

func TestNativePackageStagingSchemaRejectsCrossTargetFamily(t *testing.T) {
	schema := compileOffline(t, "schemas/native-package-staging.schema.json", nativePackageSchemaID)
	names, err := packageinfo.ExpectedPayloadNames("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	bodies := make(map[string][]byte, len(names))
	for _, name := range names {
		bodies[name] = []byte(name)
	}
	source, err := packageinfo.Build("v1.2.3", "linux", "amd64", 1787702400, "0123456789abcdef0123456789abcdef01234567", "89abcdef0123456789abcdef0123456789abcdef", "go1.27.0", bodies)
	if err != nil {
		t.Fatal(err)
	}
	sourceData, err := packageinfo.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := nativepackage.Build(source, sourceData, strings.Repeat("a", 64), nativepackage.FamilyDebian)
	if err != nil {
		t.Fatal(err)
	}
	document := decodeJSONBytes(t, mustMarshalNativePackage(t, manifest))
	document.(map[string]any)["package"].(map[string]any)["family"] = "freebsd-pkg"
	if err := schema.Validate(document); err == nil {
		t.Fatal("native package schema accepted a cross-target family")
	}
}

func mustMarshalNativePackage(t *testing.T, manifest nativepackage.Manifest) []byte {
	t.Helper()
	data, err := nativepackage.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func decodeJSONBytes(t *testing.T, data []byte) any {
	t.Helper()
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestSchemasRejectCriticalPolicyViolations(t *testing.T) {
	compatibility := compileOffline(t, "schemas/compatibility-manifest.schema.json", compatibilitySchemaID)
	compatibilityDocument := decodeRepositoryJSON(t, "compatibility/manifest.json").(map[string]any)
	compatibilityDocument["policy"].(map[string]any)["defaultVerdict"] = "allow"
	if err := compatibility.Validate(compatibilityDocument); err == nil {
		t.Fatal("compatibility schema accepted an allow-by-default policy")
	}

	t.Run("physical macOS remote route cannot self-promote", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "compatibility/manifest.json").(map[string]any)
		for _, raw := range document["backends"].([]any) {
			backend := raw.(map[string]any)
			if backend["id"] != "physical-macos-remote" {
				continue
			}
			backend["state"] = "supported"
			backend["launchVerdict"] = "allow"
			backend["authorization"] = "official"
			if err := compatibility.Validate(document); err == nil {
				t.Fatal("compatibility schema accepted promotion of the unvalidated macOS handoff")
			}
			return
		}
		t.Fatal("physical-macos-remote backend is missing")
	})

	readiness := compileOffline(t, "schemas/readiness-scorecard.schema.json", readinessSchemaID)
	readinessDocument := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
	readinessDocument["local_gameplay"].(map[string]any)["score"] = json.Number("1")
	if err := readiness.Validate(readinessDocument); err == nil {
		t.Fatal("readiness schema accepted a blocked outcome with nonzero score")
	}
	readinessDocument = decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
	readinessDocument["local_gameplay"].(map[string]any)["state"] = "candidate"
	if err := readiness.Validate(readinessDocument); err == nil {
		t.Fatal("readiness schema accepted a non-blocked local gameplay state")
	}
	readinessDocument = decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
	readinessDocument["local_gameplay"].(map[string]any)["reason"] = "League is supported locally through Wine"
	if err := readiness.Validate(readinessDocument); err == nil {
		t.Fatal("readiness schema accepted a misleading local gameplay reason")
	}

	t.Run("remote route is fixed", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		document["remote_handoffs"].([]any)[0].(map[string]any)["route_id"] = "wine"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted a different remote route")
		}
	})

	t.Run("remote route order and limitations are fixed", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		routes := document["remote_handoffs"].([]any)
		routes[0], routes[1] = routes[1], routes[0]
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted reordered remote routes")
		}
		document = decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		document["remote_handoffs"].([]any)[1].(map[string]any)["reason"] = "unvalidated"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted removal of macOS experimental/no-gamepad limitations")
		}
	})

	t.Run("remote platform order is fixed", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		platforms := document["remote_handoffs"].([]any)[0].(map[string]any)["platforms"].([]any)
		platforms[0].(map[string]any)["platform"] = "freebsd"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted a reordered remote platform matrix")
		}
	})

	t.Run("remote score and state are derived only", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		remote := document["remote_handoffs"].([]any)[0].(map[string]any)
		remote["score"] = json.Number("100")
		remote["state"] = "candidate"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted mutable remote score/state fields")
		}
	})

	t.Run("remote gate pass fields are forbidden", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		platform := document["remote_handoffs"].([]any)[0].(map[string]any)["platforms"].([]any)[0].(map[string]any)
		platform["gates"] = []any{map[string]any{"id": "physical-host", "passed": true}}
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted a mutable remote gate")
		}
	})

	t.Run("schema v1 manual evidence cannot promote", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		platform := document["remote_handoffs"].([]any)[0].(map[string]any)["platforms"].([]any)[0].(map[string]any)
		platform["evidence_sets"] = []any{map[string]any{
			"evidence_type":  "validation-evidence-v1",
			"schema_version": json.Number("1"),
			"path":           "docs/evidence/examples/client-linux-unverified.json",
			"sha256":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted schema-v1 manual promotion evidence")
		}
	})

	t.Run("plausible schema v2 evidence remains locked", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		platform := document["remote_handoffs"].([]any)[0].(map[string]any)["platforms"].([]any)[0].(map[string]any)
		platform["evidence_sets"] = []any{map[string]any{
			"evidence_type":  "validation-evidence-v2",
			"schema_version": json.Number("2"),
			"path":           "docs/evidence/reviewed.json",
			"sha256":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema v3 accepted v2 evidence without a derived v4 promotion result")
		}
	})

	t.Run("macOS schema v2 evidence remains locked", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		platform := document["remote_handoffs"].([]any)[1].(map[string]any)["platforms"].([]any)[0].(map[string]any)
		platform["evidence_sets"] = []any{map[string]any{
			"evidence_type":  "validation-evidence-v2",
			"schema_version": json.Number("2"),
			"path":           "docs/evidence/macos-reviewed.json",
			"sha256":         "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema v3 promoted macOS evidence without a derived v4 promotion result")
		}
	})

	t.Run("category earned input is forbidden", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		document["engineering"].([]any)[0].(map[string]any)["earned"] = json.Number("100")
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted mutable earned points")
		}
	})

	t.Run("category and subcriterion order are fixed", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		categories := document["engineering"].([]any)
		categories[0], categories[1] = categories[1], categories[0]
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted reordered categories")
		}
		document = decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		criteria := document["engineering"].([]any)[0].(map[string]any)["subcriteria"].([]any)
		criteria[0], criteria[1] = criteria[1], criteria[0]
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted reordered subcriteria")
		}
	})

	t.Run("fixed criterion contract cannot be relabeled", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		criterion := document["engineering"].([]any)[0].(map[string]any)["subcriteria"].([]any)[0].(map[string]any)
		criterion["verifier_id"] = "self-asserted-v1"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted a substituted verifier")
		}
	})

	t.Run("repository criterion cannot point at an arbitrary file", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		criterion := document["engineering"].([]any)[0].(map[string]any)["subcriteria"].([]any)[0].(map[string]any)
		criterion["evidence"].([]any)[0].(map[string]any)["path"] = "CHANGELOG.md"
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted arbitrary repository evidence")
		}
	})

	t.Run("repository evidence inventory is exact and ordered", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		criterion := document["engineering"].([]any)[1].(map[string]any)["subcriteria"].([]any)[0].(map[string]any)
		references := criterion["evidence"].([]any)
		references[0], references[1] = references[1], references[0]
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted reordered repository evidence")
		}
	})

	t.Run("unsupported authenticated evidence class is locked", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "readiness/scorecard.json").(map[string]any)
		criterion := document["engineering"].([]any)[2].(map[string]any)["subcriteria"].([]any)[3].(map[string]any)
		criterion["evidence"] = []any{map[string]any{
			"path":   "docs/evidence/authorization.json",
			"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		}}
		if err := readiness.Validate(document); err == nil {
			t.Fatal("readiness schema accepted unauthenticated vendor evidence")
		}
	})

	evidence := compileOffline(t, "schemas/validation-evidence.schema.json", evidenceSchemaID)
	t.Run("evidence is scoped to the supported physical-host routes", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/client-linux-unverified.json").(map[string]any)
		document["route_id"] = "wine"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted an unsupported route")
		}
		document = decodeRepositoryJSON(t, "docs/evidence/examples/host-windows-unverified.json").(map[string]any)
		document["route_id"] = "physical-macos-remote"
		document["subject"].(map[string]any)["platform"] = "macos"
		document["subject"].(map[string]any)["architecture"] = "arm64"
		if err := evidence.Validate(document); err != nil {
			t.Fatalf("evidence schema rejected a valid macOS route: %v", err)
		}
	})

	t.Run("evidence requires a privacy-safe validation run id", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/client-linux-unverified.json").(map[string]any)
		document["validation_run_id"] = "customer@example.com"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted an invalid validation run id")
		}
	})

	t.Run("host route and platform must agree", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/host-windows-unverified.json").(map[string]any)
		document["subject"].(map[string]any)["platform"] = "macos"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a macOS host for the physical Windows route")
		}
		document = decodeRepositoryJSON(t, "docs/evidence/examples/host-windows-unverified.json").(map[string]any)
		document["route_id"] = "physical-macos-remote"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a Windows host for the physical macOS route")
		}
	})

	t.Run("evidence is bound to the canonical embedded manifest content", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/client-linux-unverified.json").(map[string]any)
		document["manifest_sha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a different compatibility manifest digest")
		}
	})

	t.Run("unverified check cannot claim observation", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/host-windows-unverified.json").(map[string]any)
		check := document["checks"].([]any)[0].(map[string]any)
		check["observed_at"] = "2026-08-26T00:01:00Z"
		check["artifacts"] = []any{"lab/host-physical-machine.txt"}
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted observations on an unverified check")
		}
	})

	t.Run("session requires record bindings", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		delete(document, "bindings")
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted session evidence without host/client bindings")
		}
	})

	t.Run("session requires versioned measurement methodology", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		delete(document, "measurement_methodology")
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted session evidence without measurement methodology")
		}
	})

	t.Run("session rejects unknown measurement methodology", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		document["measurement_methodology"].(map[string]any)["version"] = "session-metrics-v2"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted an unknown measurement methodology")
		}
	})

	t.Run("reviewed attestation requires review evidence", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/client-linux-unverified.json").(map[string]any)
		document["attestation"].(map[string]any)["level"] = "independent-review"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted independent review without reviewer, time, and artifacts")
		}
	})

	t.Run("record type cannot borrow another check inventory", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/client-linux-unverified.json").(map[string]any)
		document["checks"].([]any)[0].(map[string]any)["id"] = "host.physical-machine"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a foreign or incomplete check inventory")
		}
	})

	t.Run("session requires exact latency units", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		document["measurements"].([]any)[2].(map[string]any)["unit"] = "seconds"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a session latency measurement with the wrong unit")
		}
	})

	t.Run("session requires the complete measurement inventory", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		document["measurements"].([]any)[3].(map[string]any)["id"] = "optional-jitter"
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a session without the required network latency measurement")
		}
	})

	t.Run("dropped frames is a bounded percentage", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		measurements := document["measurements"].([]any)
		measurements[len(measurements)-1].(map[string]any)["value"] = json.Number("101")
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted dropped frames above 100 percent")
		}
	})

	t.Run("stream profile has plausible structural ceilings", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		document["stream_profile"].(map[string]any)["target_frame_rate"] = json.Number("241")
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a target frame rate above 240 fps")
		}
	})

	t.Run("session duration has a plausible structural ceiling", func(t *testing.T) {
		document := decodeRepositoryJSON(t, "docs/evidence/examples/session-linux-unverified.json").(map[string]any)
		document["measurements"].([]any)[0].(map[string]any)["value"] = json.Number("28801")
		if err := evidence.Validate(document); err == nil {
			t.Fatal("evidence schema accepted a session duration above eight hours")
		}
	})
}

func TestValidationEvidenceExamplesPassRuntimeParser(t *testing.T) {
	examples := []string{
		"docs/evidence/examples/host-windows-unverified.json",
		"docs/evidence/examples/client-linux-unverified.json",
		"docs/evidence/examples/session-linux-unverified.json",
	}
	for _, example := range examples {
		example := example
		t.Run(example, func(t *testing.T) {
			data, err := os.ReadFile(repositoryFile(t, example))
			if err != nil {
				t.Fatalf("read %s: %v", example, err)
			}
			record, err := evidence.Parse(data)
			if err != nil {
				t.Fatalf("parse %s with runtime evidence contract: %v", example, err)
			}
			evaluation, err := evidence.EvaluateAt(record, time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("evaluate %s: %v", example, err)
			}
			if evaluation.State != evidence.StatePending || evaluation.PromotionSafe {
				t.Fatalf("example %s evaluated as state=%s promotion_safe=%t; want pending and false", example, evaluation.State, evaluation.PromotionSafe)
			}
		})
	}
}

func TestGeneratedEvidenceTemplatesConformToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/validation-evidence.schema.json", evidenceSchemaID)
	tests := []struct {
		recordType   evidence.RecordType
		platform     string
		architecture string
	}{
		{recordType: evidence.RecordHost, platform: "windows", architecture: "amd64"},
		{recordType: evidence.RecordClient, platform: "freebsd", architecture: "amd64"},
		{recordType: evidence.RecordSession, platform: "dragonflybsd", architecture: "amd64"},
	}
	for _, test := range tests {
		test := test
		t.Run(string(test.recordType)+"/"+test.platform, func(t *testing.T) {
			record, err := evidence.NewTemplate(test.recordType, test.platform, test.architecture, "contract-test", time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC))
			if err != nil {
				t.Fatalf("create template: %v", err)
			}
			data, err := json.Marshal(record)
			if err != nil {
				t.Fatalf("marshal template: %v", err)
			}
			var document any
			decoder := json.NewDecoder(bytes.NewReader(data))
			decoder.UseNumber()
			if err := decoder.Decode(&document); err != nil {
				t.Fatalf("decode generated template: %v", err)
			}
			if err := schema.Validate(document); err != nil {
				t.Fatalf("public schema rejected generated template: %v", err)
			}
		})
	}
}

func TestReviewedEvidenceArtifactMetadataConformsToPublicSchema(t *testing.T) {
	schema := compileOffline(t, "schemas/validation-evidence.schema.json", evidenceSchemaID)
	created := time.Date(2026, time.August, 30, 12, 0, 0, 0, time.UTC)
	record, err := evidence.NewTemplate(evidence.RecordClient, "openbsd", "amd64", "contract-test", created)
	if err != nil {
		t.Fatalf("create template: %v", err)
	}
	artifact := evidence.Artifact{
		Name:      "review.json",
		SHA256:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SizeBytes: 128,
		MediaType: "application/json",
	}
	record.Attestation = evidence.Attestation{
		Level:      evidence.AttestationIndependent,
		Reviewer:   "contract-test-reviewer",
		ReviewedAt: created.Add(2 * time.Hour).Format(time.RFC3339),
		Artifacts:  []evidence.Artifact{artifact},
		Notes:      "Synthetic schema test only.",
	}
	for index := range record.Checks {
		checkArtifact := artifact
		checkArtifact.Name = record.Checks[index].ID + ".json"
		record.Checks[index].Status = evidence.StatusPass
		record.Checks[index].ObservedAt = created.Add(time.Hour).Format(time.RFC3339)
		record.Checks[index].Artifacts = []evidence.Artifact{checkArtifact}
	}
	if err := evidence.Validate(record); err != nil {
		t.Fatalf("runtime rejected reviewed record: %v", err)
	}
	data, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("marshal reviewed record: %v", err)
	}
	var document any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&document); err != nil {
		t.Fatalf("decode reviewed record: %v", err)
	}
	if err := schema.Validate(document); err != nil {
		t.Fatalf("public schema rejected reviewed artifact metadata: %v", err)
	}
}

func compileOffline(t *testing.T, schemaPath, schemaID string) *jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.AssertFormat()
	if err := compiler.AddResource(schemaID, decodeRepositoryJSON(t, schemaPath)); err != nil {
		t.Fatalf("add schema resource %s: %v", schemaPath, err)
	}
	compiled, err := compiler.Compile(schemaID)
	if err != nil {
		t.Fatalf("compile schema %s: %v", schemaPath, err)
	}
	return compiled
}

func decodeRepositoryJSON(t *testing.T, relative string) any {
	t.Helper()
	data, err := os.ReadFile(repositoryFile(t, relative))
	if err != nil {
		t.Fatalf("read %s: %v", relative, err)
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatalf("decode %s: %v", relative, err)
	}
	return value
}

func repositoryFile(t *testing.T, relative string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	return filepath.Join(root, filepath.FromSlash(relative))
}
