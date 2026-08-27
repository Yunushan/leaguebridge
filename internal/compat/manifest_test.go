package compat

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestEmbeddedManifestIsCompleteAndFailClosed(t *testing.T) {
	t.Parallel()

	manifest, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded() error = %v", err)
	}
	if manifest.AsOf != AuthoritativeAsOf {
		t.Fatalf("AsOf = %q, want %q", manifest.AsOf, AuthoritativeAsOf)
	}
	if manifest.Policy.DefaultVerdict != DecisionDeny {
		t.Fatalf("default verdict = %q, want deny", manifest.Policy.DefaultVerdict)
	}
	if !manifest.Policy.RequireOfficialAuthorization {
		t.Fatal("official authorization requirement is false")
	}
	if len(manifest.Backends) != len(BackendIDs()) {
		t.Fatalf("backends = %d, want %d", len(manifest.Backends), len(BackendIDs()))
	}
	for _, id := range BackendIDs() {
		backend, ok := findBackend(manifest, id)
		if !ok {
			t.Errorf("missing backend %q", id)
			continue
		}
		if backend.LaunchVerdict != DecisionDeny {
			t.Errorf("backend %q verdict = %q, want deny", id, backend.LaunchVerdict)
		}
		if len(backend.SourceIDs) == 0 {
			t.Errorf("backend %q has no sources", id)
		}
	}
}

func TestEmbeddedUsesCurrentPrimarySources(t *testing.T) {
	t.Parallel()

	manifest := mustEmbedded(t)
	want := map[string]string{
		"riot-system-requirements":     "https://support.riotgames.com/en-us/league-of-legends/performance/minimum-and-recommended-system-requirements-league-of-legends",
		"riot-macos-embedded-vanguard": "https://www.leagueoflegends.com/en-ph/news/game-updates/patch-25-s1-2-notes/",
		"riot-vm-policy":               "https://support-leagueoflegends.riotgames.com/hc/en-us/articles/26932165816851-Vanguard-Error-Codes-and-Solutions-LoL",
		"valve-proton":                 "https://partner.steamgames.com/doc/steamhardware/proton",
		"dockur-environment":           "https://github.com/dockur/windows/blob/master/docs/environment.md",
		"sunshine-docs":                "https://docs.lizardbyte.dev/projects/sunshine/latest/",
		"moonlight-qt":                 "https://github.com/moonlight-stream/moonlight-qt",
		"microsoft-bcdboot":            "https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdboot-command-line-options-techref-di?view=windows-11",
	}
	got := make(map[string]string, len(manifest.Sources))
	for _, source := range manifest.Sources {
		got[source.ID] = source.URL
	}
	for id, wantURL := range want {
		if got[id] != wantURL {
			t.Errorf("source %q URL = %q, want %q", id, got[id], wantURL)
		}
	}
	macOSRoute, ok := findBackend(manifest, BackendPhysicalMacOSRemote)
	if !ok {
		t.Fatal("physical macOS route is missing")
	}
	if !slices.Contains(macOSRoute.SourceIDs, "riot-macos-embedded-vanguard") {
		t.Fatal("physical macOS route is not bound to Riot's Embedded Vanguard source")
	}
}

func TestPublicManifestMatchesEmbeddedSemantically(t *testing.T) {
	t.Parallel()

	embedded, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	publicBytes, err := os.ReadFile(repositoryFile(t, "compatibility", "manifest.json"))
	if err != nil {
		t.Fatalf("read public manifest: %v", err)
	}
	public, err := Parse(publicBytes)
	if err != nil {
		t.Fatalf("parse public manifest: %v", err)
	}
	embeddedDigest, err := CanonicalSHA256(embedded)
	if err != nil {
		t.Fatalf("digest embedded manifest: %v", err)
	}
	publicDigest, err := CanonicalSHA256(public)
	if err != nil {
		t.Fatalf("digest public manifest: %v", err)
	}
	if embeddedDigest != publicDigest {
		t.Fatalf("canonical digests differ: embedded=%s public=%s", embeddedDigest, publicDigest)
	}

	// Relative schema links necessarily differ because the documents live at
	// different depths. All compatibility evidence and policy must be equal.
	embedded.Schema = public.Schema
	if !reflect.DeepEqual(embedded, public) {
		t.Fatal("public and embedded manifests differ beyond their relative $schema link")
	}
}

func TestCanonicalSHA256IgnoresLineEndings(t *testing.T) {
	t.Parallel()

	raw := EmbeddedJSON()
	lf := bytes.ReplaceAll(raw, []byte("\r\n"), []byte("\n"))
	crlf := bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
	if bytes.Equal(lf, crlf) {
		t.Fatal("line-ending fixtures unexpectedly match")
	}
	lfManifest, err := Parse(lf)
	if err != nil {
		t.Fatalf("parse LF manifest: %v", err)
	}
	crlfManifest, err := Parse(crlf)
	if err != nil {
		t.Fatalf("parse CRLF manifest: %v", err)
	}
	lfDigest, err := CanonicalSHA256(lfManifest)
	if err != nil {
		t.Fatalf("digest LF manifest: %v", err)
	}
	crlfDigest, err := CanonicalSHA256(crlfManifest)
	if err != nil {
		t.Fatalf("digest CRLF manifest: %v", err)
	}
	if lfDigest != crlfDigest {
		t.Fatalf("line endings changed canonical digest: LF=%s CRLF=%s", lfDigest, crlfDigest)
	}
	const want = "211cb4440f7529bb9498dc5439ee9728f8cb88440ef096a9620f5a0e399eebf1"
	if lfDigest != want {
		t.Fatalf("canonical digest = %s, want %s", lfDigest, want)
	}
}

func TestSchemaIsWellFormedAndPublicManifestReferencesIt(t *testing.T) {
	t.Parallel()

	schemaBytes, err := os.ReadFile(repositoryFile(t, "schemas", "compatibility-manifest.schema.json"))
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatalf("schema is not valid JSON: %v", err)
	}
	if got := schema["$schema"]; got != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("schema dialect = %v", got)
	}
	publicBytes, err := os.ReadFile(repositoryFile(t, "compatibility", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	public, err := Parse(publicBytes)
	if err != nil {
		t.Fatal(err)
	}
	if public.Schema != "../schemas/compatibility-manifest.schema.json" {
		t.Fatalf("public $schema = %q", public.Schema)
	}
}

func TestParseRejectsMalformedOrUnsafeManifests(t *testing.T) {
	t.Parallel()

	valid := string(EmbeddedJSON())
	tests := map[string]string{
		"empty":                 "   \n\t",
		"duplicate top key":     strings.Replace(valid, `"schemaVersion": "1.0.0",`, `"schemaVersion": "1.0.0", "schemaVersion": "1.0.0",`, 1),
		"duplicate nested key":  strings.Replace(valid, `"id": "riot-system-requirements",`, `"id": "riot-system-requirements", "id": "duplicate",`, 1),
		"unknown top field":     strings.Replace(valid, `"manifestId":`, `"unexpected": true, "manifestId":`, 1),
		"case variant field":    strings.Replace(valid, `"schemaVersion":`, `"SchemaVersion":`, 1),
		"unknown nested field":  strings.Replace(valid, `"publisher": "Riot Games"`, `"publisher": "Riot Games", "owner": "nobody"`, 1),
		"null published date":   strings.Replace(valid, `"publishedAt": "2024-04-11"`, `"publishedAt": null`, 1),
		"empty published date":  strings.Replace(valid, `"publishedAt": "2024-04-11"`, `"publishedAt": ""`, 1),
		"trailing value":        valid + ` {}`,
		"invalid state":         strings.Replace(valid, `"state": "blocked"`, `"state": "probably"`, 1),
		"unknown backend":       strings.Replace(valid, `"id": "native-linux"`, `"id": "mystery-runtime"`, 1),
		"duplicate backend":     strings.Replace(valid, `"id": "native-bsd"`, `"id": "native-linux"`, 1),
		"unsafe default allow":  strings.Replace(valid, `"defaultVerdict": "deny"`, `"defaultVerdict": "allow"`, 1),
		"unknown schema":        strings.Replace(valid, `"../../../schemas/compatibility-manifest.schema.json"`, `"https://attacker.invalid/schema.json"`, 1),
		"invalid source URL":    strings.Replace(valid, `"https://www.winehq.org/about/"`, `"http://www.winehq.org/about/"`, 1),
		"source after manifest": strings.Replace(valid, `"checkedAt": "2026-08-26"`, `"checkedAt": "2026-08-27"`, 1),
		"unknown source ref":    strings.Replace(valid, `"winehq-about"]`, `"missing-source"]`, 1),
		"identity mismatch": strings.Replace(valid, `"id": "proton",
      "displayName": "Proton",
      "kind": "translation"`, `"id": "proton",
      "displayName": "Proton",
      "kind": "native"`, 1),
		"handoff local": strings.Replace(valid, `"launchMode": "remote",
      "hostPlatforms"`, `"launchMode": "local",
      "hostPlatforms"`, 1),
	}
	for name, input := range tests {
		name, input := name, input
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := Parse([]byte(input)); err == nil {
				t.Fatal("Parse() error = nil, want rejection")
			}
		})
	}
}

func TestParseRejectsOversizeInput(t *testing.T) {
	t.Parallel()

	if _, err := Parse(bytes.Repeat([]byte{' '}, MaxManifestBytes+1)); err == nil {
		t.Fatal("Parse() accepted oversized input")
	}
}

func TestCopiesDoNotExposeEmbeddedState(t *testing.T) {
	t.Parallel()

	jsonCopy := EmbeddedJSON()
	jsonCopy[0] = 'x'
	if EmbeddedJSON()[0] == 'x' {
		t.Fatal("EmbeddedJSON returned shared storage")
	}

	ids := BackendIDs()
	ids[0] = "attacker-backend"
	if BackendIDs()[0] == "attacker-backend" {
		t.Fatal("BackendIDs returned shared storage")
	}

	first, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	first.Backends[0].LaunchVerdict = DecisionAllow
	second, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if second.Backends[0].LaunchVerdict != DecisionDeny {
		t.Fatal("Embedded returned shared manifest storage")
	}
}

func TestValidateAllowsOnlySemanticallyCompletePromotion(t *testing.T) {
	t.Parallel()

	manifest := mustEmbedded(t)
	backend := &manifest.Backends[0]
	backend.State = StateSupported
	backend.Authorization = AuthorizationOfficial
	backend.LaunchVerdict = DecisionAllow
	if err := Validate(manifest); err != nil {
		t.Fatalf("complete official promotion rejected: %v", err)
	}

	backend.Authorization = AuthorizationUnverified
	if err := Validate(manifest); err == nil {
		t.Fatal("allow without official authorization accepted")
	}
}

func TestPhysicalMacOSRemoteCannotBePromotedWithoutANewContract(t *testing.T) {
	t.Parallel()
	manifest := mustEmbedded(t)
	for i := range manifest.Backends {
		backend := &manifest.Backends[i]
		if backend.ID != BackendPhysicalMacOSRemote {
			continue
		}
		if backend.Kind != KindRemotePhysicalMacOS || backend.LaunchMode != LaunchRemote || backend.State != StateHandoffOnly || backend.LaunchVerdict != DecisionDeny || backend.Authorization != AuthorizationUnverified {
			t.Fatalf("embedded macOS route = %+v", *backend)
		}
		backend.State = StateSupported
		backend.LaunchVerdict = DecisionAllow
		backend.Authorization = AuthorizationOfficial
		if err := Validate(manifest); err == nil || !strings.Contains(err.Error(), "must remain handoff-only") {
			t.Fatalf("promotion error = %v", err)
		}
		return
	}
	t.Fatal("physical macOS remote route is missing")
}

func FuzzParseNeverPanics(f *testing.F) {
	f.Add(EmbeddedJSON())
	f.Add([]byte(`{"schemaVersion":"1.0.0","schemaVersion":"1.0.0"}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, input []byte) {
		if len(input) > MaxManifestBytes+1 {
			input = input[:MaxManifestBytes+1]
		}
		_, _ = Parse(input)
	})
}

func mustEmbedded(t *testing.T) Manifest {
	t.Helper()
	manifest, err := Embedded()
	if err != nil {
		t.Fatalf("Embedded() error = %v", err)
	}
	return manifest
}

func mustJSON(t *testing.T, manifest Manifest) []byte {
	t.Helper()
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}

func repositoryFile(t *testing.T, elements ...string) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(filename), "..", ".."))
	return filepath.Join(append([]string{root}, elements...)...)
}
