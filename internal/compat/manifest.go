// Package compat provides the authoritative LeagueBridge compatibility manifest
// and strict parsing and validation for informational external manifests.
//
// Launch authorization is deliberately kept in policy.go. Parsing a manifest
// does not make that manifest authoritative.
package compat

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// SchemaVersion is the only manifest schema version accepted by this package.
	SchemaVersion = "1.0.0"
	// SchemaID is the canonical public identifier for schema version 1.0.0.
	SchemaID = "https://leaguebridge.dev/schemas/compatibility-manifest.schema.json"
	// AuthoritativeAsOf is the evidence date of the compiled-in manifest.
	AuthoritativeAsOf = "2026-08-30"
	// MaxManifestBytes limits untrusted external manifest input.
	MaxManifestBytes = 1 << 20
)

//go:embed data/manifest.json
var embeddedManifestJSON []byte

// BackendID is a stable compatibility backend identifier.
type BackendID string

const (
	BackendNativeLinux           BackendID = "native-linux"
	BackendNativeBSD             BackendID = "native-bsd"
	BackendWine                  BackendID = "wine"
	BackendProton                BackendID = "proton"
	BackendDockurQEMU            BackendID = "dockur-qemu"
	BackendBhyve                 BackendID = "bhyve"
	BackendPhysicalWindowsRemote BackendID = "physical-windows-remote"
	BackendPhysicalMacOSRemote   BackendID = "physical-macos-remote"
	BackendDualBoot              BackendID = "dual-boot"
)

var knownBackendIDs = [...]BackendID{
	BackendNativeLinux,
	BackendNativeBSD,
	BackendWine,
	BackendProton,
	BackendDockurQEMU,
	BackendBhyve,
	BackendPhysicalWindowsRemote,
	BackendPhysicalMacOSRemote,
	BackendDualBoot,
}

// BackendIDs returns the complete backend inventory for schema version 1.0.0.
func BackendIDs() []BackendID {
	ids := make([]BackendID, len(knownBackendIDs))
	copy(ids, knownBackendIDs[:])
	return ids
}

// Platform identifies the LeagueBridge host operating system.
type Platform string

const (
	PlatformLinux        Platform = "linux"
	PlatformFreeBSD      Platform = "freebsd"
	PlatformOpenBSD      Platform = "openbsd"
	PlatformNetBSD       Platform = "netbsd"
	PlatformDragonFlyBSD Platform = "dragonflybsd"
)

// Architecture identifies the LeagueBridge host CPU architecture.
type Architecture string

const ArchitectureAMD64 Architecture = "amd64"

// BackendKind describes where or how Windows API execution would occur.
type BackendKind string

const (
	KindNative                BackendKind = "native"
	KindTranslation           BackendKind = "translation"
	KindVirtualMachine        BackendKind = "virtual-machine"
	KindRemotePhysicalWindows BackendKind = "remote-physical-windows"
	KindRemotePhysicalMacOS   BackendKind = "remote-physical-macos"
	KindDualBoot              BackendKind = "dual-boot"
)

// LaunchMode distinguishes local execution from a remote or reboot handoff.
type LaunchMode string

const (
	LaunchLocal   LaunchMode = "local"
	LaunchRemote  LaunchMode = "remote"
	LaunchHandoff LaunchMode = "handoff"
)

// CompatibilityState is an evidence state, not by itself an authorization.
type CompatibilityState string

const (
	StateBlocked     CompatibilityState = "blocked"
	StateHandoffOnly CompatibilityState = "handoff-only"
	StateSupported   CompatibilityState = "supported"
)

// LaunchDecision is the machine-readable launch gate result.
type LaunchDecision string

const (
	DecisionDeny  LaunchDecision = "deny"
	DecisionAllow LaunchDecision = "allow"
)

// Authorization records the strength of upstream authorization evidence.
type Authorization string

const (
	AuthorizationNone       Authorization = "none"
	AuthorizationUnverified Authorization = "unverified"
	AuthorizationOfficial   Authorization = "official"
)

// Manifest is the public compatibility document.
type Manifest struct {
	Schema        string         `json:"$schema"`
	SchemaVersion string         `json:"schemaVersion"`
	ManifestID    string         `json:"manifestId"`
	AsOf          string         `json:"asOf"`
	Game          Game           `json:"game"`
	Policy        ManifestPolicy `json:"policy"`
	Sources       []Source       `json:"sources"`
	Backends      []Backend      `json:"backends"`
}

// Game identifies the software to which the manifest applies.
type Game struct {
	Name      string `json:"name"`
	Publisher string `json:"publisher"`
}

// ManifestPolicy contains declarative policy invariants. Runtime policy still
// uses the compiled-in copy and never trusts these fields from external input.
type ManifestPolicy struct {
	DefaultVerdict               LaunchDecision `json:"defaultVerdict"`
	MaxAgeDays                   int            `json:"maxAgeDays"`
	RequireOfficialAuthorization bool           `json:"requireOfficialAuthorization"`
}

// Source is a dated public evidence reference.
type Source struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Publisher   string `json:"publisher"`
	URL         string `json:"url"`
	PublishedAt string `json:"publishedAt,omitempty"`
	CheckedAt   string `json:"checkedAt"`
}

// Backend is one compatibility route and its fail-closed launch status.
type Backend struct {
	ID                BackendID          `json:"id"`
	DisplayName       string             `json:"displayName"`
	Kind              BackendKind        `json:"kind"`
	LaunchMode        LaunchMode         `json:"launchMode"`
	HostPlatforms     []Platform         `json:"hostPlatforms"`
	HostArchitectures []Architecture     `json:"hostArchitectures"`
	State             CompatibilityState `json:"state"`
	LaunchVerdict     LaunchDecision     `json:"launchVerdict"`
	Authorization     Authorization      `json:"authorization"`
	ReasonCode        string             `json:"reasonCode"`
	Summary           string             `json:"summary"`
	SourceIDs         []string           `json:"sourceIds"`
	SafetyNotes       []string           `json:"safetyNotes"`
}

var (
	idPattern     = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	reasonPattern = regexp.MustCompile(`^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*$`)
)

// Embedded returns a newly decoded copy of the authoritative manifest.
// Mutating the result cannot mutate the bytes or policy embedded in the binary.
func Embedded() (Manifest, error) {
	m, err := Parse(embeddedManifestJSON)
	if err != nil {
		return Manifest{}, fmt.Errorf("embedded compatibility manifest: %w", err)
	}
	if m.AsOf != AuthoritativeAsOf {
		return Manifest{}, fmt.Errorf("embedded compatibility manifest: asOf %q does not match compiled authority date %q", m.AsOf, AuthoritativeAsOf)
	}
	return m, nil
}

// EmbeddedJSON returns a copy of the exact compiled-in JSON document.
func EmbeddedJSON() []byte {
	return bytes.Clone(embeddedManifestJSON)
}

// CanonicalSHA256 returns the lowercase SHA-256 of a validated manifest's
// deterministic JSON representation. Known relative schema references are
// normalized to SchemaID, so formatting and checkout line endings do not alter
// the semantic content binding.
func CanonicalSHA256(manifest Manifest) (string, error) {
	if err := Validate(manifest); err != nil {
		return "", fmt.Errorf("canonical manifest SHA-256: %w", err)
	}
	canonical := manifest
	canonical.Schema = SchemaID
	data, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("canonical manifest SHA-256: encode manifest: %w", err)
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest), nil
}

// Parse strictly decodes and validates a manifest. It rejects duplicate keys,
// unknown fields (including case variants), trailing values, invalid states,
// incomplete backend inventories, and inconsistent safety state.
func Parse(data []byte) (Manifest, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return Manifest{}, errors.New("manifest is empty")
	}
	if len(data) > MaxManifestBytes {
		return Manifest{}, fmt.Errorf("manifest exceeds %d-byte limit", MaxManifestBytes)
	}
	if err := checkJSONStructure(data); err != nil {
		return Manifest{}, err
	}
	if err := checkExactFields(data); err != nil {
		return Manifest{}, err
	}

	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := expectEOF(dec); err != nil {
		return Manifest{}, err
	}
	if err := Validate(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// Validate checks the schema and all cross-field policy invariants.
func Validate(m Manifest) error {
	if !knownSchemaReference(m.Schema) {
		return fmt.Errorf("validate manifest: unknown $schema reference %q", m.Schema)
	}
	if m.SchemaVersion != SchemaVersion {
		return fmt.Errorf("validate manifest: unsupported schemaVersion %q", m.SchemaVersion)
	}
	if len(m.ManifestID) > 128 || !idPattern.MatchString(m.ManifestID) {
		return fmt.Errorf("validate manifest: invalid manifestId %q", m.ManifestID)
	}
	manifestDate, err := parseDate("asOf", m.AsOf)
	if err != nil {
		return fmt.Errorf("validate manifest: %w", err)
	}
	if !validText(m.Game.Name, 200) || !validText(m.Game.Publisher, 200) {
		return errors.New("validate manifest: game name and publisher are required")
	}
	if m.Policy.DefaultVerdict != DecisionDeny {
		return errors.New("validate manifest: policy.defaultVerdict must be deny")
	}
	if m.Policy.MaxAgeDays < 1 || m.Policy.MaxAgeDays > 365 {
		return errors.New("validate manifest: policy.maxAgeDays must be between 1 and 365")
	}
	if !m.Policy.RequireOfficialAuthorization {
		return errors.New("validate manifest: policy.requireOfficialAuthorization must be true")
	}
	if len(m.Sources) == 0 {
		return errors.New("validate manifest: at least one source is required")
	}
	if len(m.Sources) > 512 {
		return errors.New("validate manifest: no more than 512 sources are allowed")
	}

	sourceIDs := make(map[string]struct{}, len(m.Sources))
	for i, source := range m.Sources {
		path := fmt.Sprintf("sources[%d]", i)
		if len(source.ID) > 128 || !idPattern.MatchString(source.ID) {
			return fmt.Errorf("validate manifest: %s has invalid id %q", path, source.ID)
		}
		if _, exists := sourceIDs[source.ID]; exists {
			return fmt.Errorf("validate manifest: duplicate source id %q", source.ID)
		}
		sourceIDs[source.ID] = struct{}{}
		if !validText(source.Title, 4096) || !validText(source.Publisher, 4096) {
			return fmt.Errorf("validate manifest: %s title and publisher are required", path)
		}
		if err := validateSourceURL(source.URL); err != nil {
			return fmt.Errorf("validate manifest: %s: %w", path, err)
		}
		checked, err := parseDate(path+".checkedAt", source.CheckedAt)
		if err != nil {
			return fmt.Errorf("validate manifest: %w", err)
		}
		if checked.After(manifestDate) {
			return fmt.Errorf("validate manifest: %s.checkedAt is after asOf", path)
		}
		if source.PublishedAt != "" {
			published, err := parseDate(path+".publishedAt", source.PublishedAt)
			if err != nil {
				return fmt.Errorf("validate manifest: %w", err)
			}
			if published.After(checked) {
				return fmt.Errorf("validate manifest: %s.publishedAt is after checkedAt", path)
			}
		}
	}

	if len(m.Backends) != len(knownBackendIDs) {
		return fmt.Errorf("validate manifest: expected exactly %d backends, got %d", len(knownBackendIDs), len(m.Backends))
	}
	known := make(map[BackendID]struct{}, len(knownBackendIDs))
	for _, id := range knownBackendIDs {
		known[id] = struct{}{}
	}
	seen := make(map[BackendID]struct{}, len(m.Backends))
	for i, backend := range m.Backends {
		path := fmt.Sprintf("backends[%d]", i)
		if _, ok := known[backend.ID]; !ok {
			return fmt.Errorf("validate manifest: %s has unknown backend id %q", path, backend.ID)
		}
		if _, exists := seen[backend.ID]; exists {
			return fmt.Errorf("validate manifest: duplicate backend id %q", backend.ID)
		}
		seen[backend.ID] = struct{}{}
		if err := validateBackend(path, backend, sourceIDs); err != nil {
			return fmt.Errorf("validate manifest: %w", err)
		}
	}
	for _, id := range knownBackendIDs {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("validate manifest: missing backend %q", id)
		}
	}
	return nil
}

func validateBackend(path string, b Backend, sourceIDs map[string]struct{}) error {
	if !validText(b.DisplayName, 4096) {
		return fmt.Errorf("%s.displayName is required", path)
	}
	if !oneOfBackendKind(b.Kind) {
		return fmt.Errorf("%s has invalid kind %q", path, b.Kind)
	}
	if !oneOfLaunchMode(b.LaunchMode) {
		return fmt.Errorf("%s has invalid launchMode %q", path, b.LaunchMode)
	}
	if !oneOfState(b.State) {
		return fmt.Errorf("%s has invalid state %q", path, b.State)
	}
	if b.LaunchVerdict != DecisionDeny && b.LaunchVerdict != DecisionAllow {
		return fmt.Errorf("%s has invalid launchVerdict %q", path, b.LaunchVerdict)
	}
	if !oneOfAuthorization(b.Authorization) {
		return fmt.Errorf("%s has invalid authorization %q", path, b.Authorization)
	}
	if len(b.HostPlatforms) == 0 {
		return fmt.Errorf("%s.hostPlatforms must not be empty", path)
	}
	platforms := make(map[Platform]struct{}, len(b.HostPlatforms))
	for _, platform := range b.HostPlatforms {
		if !knownPlatform(platform) {
			return fmt.Errorf("%s has unknown host platform %q", path, platform)
		}
		if _, duplicate := platforms[platform]; duplicate {
			return fmt.Errorf("%s has duplicate host platform %q", path, platform)
		}
		platforms[platform] = struct{}{}
	}
	if len(b.HostArchitectures) == 0 {
		return fmt.Errorf("%s.hostArchitectures must not be empty", path)
	}
	architectures := make(map[Architecture]struct{}, len(b.HostArchitectures))
	for _, architecture := range b.HostArchitectures {
		if architecture != ArchitectureAMD64 {
			return fmt.Errorf("%s has unknown host architecture %q", path, architecture)
		}
		if _, duplicate := architectures[architecture]; duplicate {
			return fmt.Errorf("%s has duplicate host architecture %q", path, architecture)
		}
		architectures[architecture] = struct{}{}
	}
	if len(b.ReasonCode) > 160 || !reasonPattern.MatchString(b.ReasonCode) {
		return fmt.Errorf("%s has invalid reasonCode %q", path, b.ReasonCode)
	}
	if !validText(b.Summary, 4096) {
		return fmt.Errorf("%s.summary is required", path)
	}
	if len(b.SourceIDs) == 0 {
		return fmt.Errorf("%s.sourceIds must not be empty", path)
	}
	if len(b.SourceIDs) > 64 {
		return fmt.Errorf("%s.sourceIds has more than 64 entries", path)
	}
	refs := make(map[string]struct{}, len(b.SourceIDs))
	for _, id := range b.SourceIDs {
		if _, ok := sourceIDs[id]; !ok {
			return fmt.Errorf("%s references unknown source %q", path, id)
		}
		if _, duplicate := refs[id]; duplicate {
			return fmt.Errorf("%s has duplicate source reference %q", path, id)
		}
		refs[id] = struct{}{}
	}
	if len(b.SafetyNotes) == 0 {
		return fmt.Errorf("%s.safetyNotes must not be empty", path)
	}
	if len(b.SafetyNotes) > 64 {
		return fmt.Errorf("%s.safetyNotes has more than 64 entries", path)
	}
	notes := make(map[string]struct{}, len(b.SafetyNotes))
	for _, note := range b.SafetyNotes {
		note = strings.TrimSpace(note)
		if !validText(note, 4096) {
			return fmt.Errorf("%s has an empty safety note", path)
		}
		if _, duplicate := notes[note]; duplicate {
			return fmt.Errorf("%s has a duplicate safety note", path)
		}
		notes[note] = struct{}{}
	}

	if b.State != StateSupported && b.LaunchVerdict != DecisionDeny {
		return fmt.Errorf("%s must deny launch unless state is supported", path)
	}
	if b.Authorization != AuthorizationOfficial && b.LaunchVerdict != DecisionDeny {
		return fmt.Errorf("%s must deny launch without official authorization", path)
	}
	if b.LaunchVerdict == DecisionAllow && (b.State != StateSupported || b.Authorization != AuthorizationOfficial) {
		return fmt.Errorf("%s allow verdict lacks supported state and official authorization", path)
	}
	if b.Kind == KindVirtualMachine && b.Authorization != AuthorizationOfficial && b.LaunchVerdict != DecisionDeny {
		return fmt.Errorf("%s virtual machine must deny launch without official authorization", path)
	}
	if b.State == StateHandoffOnly && b.LaunchMode == LaunchLocal {
		return fmt.Errorf("%s handoff-only state cannot use local launch mode", path)
	}
	if err := validateBackendIdentity(path, b); err != nil {
		return err
	}
	return nil
}

func validateBackendIdentity(path string, b Backend) error {
	var wantKind BackendKind
	var wantMode LaunchMode
	var wantPlatforms []Platform
	switch b.ID {
	case BackendNativeLinux:
		wantKind, wantMode = KindNative, LaunchLocal
		wantPlatforms = []Platform{PlatformLinux}
	case BackendNativeBSD:
		wantKind, wantMode = KindNative, LaunchLocal
		wantPlatforms = bsdPlatforms()
	case BackendWine:
		wantKind, wantMode = KindTranslation, LaunchLocal
		wantPlatforms = allHostPlatforms()
	case BackendProton:
		wantKind, wantMode = KindTranslation, LaunchLocal
		wantPlatforms = []Platform{PlatformLinux}
	case BackendDockurQEMU:
		wantKind, wantMode = KindVirtualMachine, LaunchLocal
		wantPlatforms = []Platform{PlatformLinux}
	case BackendBhyve:
		wantKind, wantMode = KindVirtualMachine, LaunchLocal
		wantPlatforms = []Platform{PlatformFreeBSD}
	case BackendPhysicalWindowsRemote:
		wantKind, wantMode = KindRemotePhysicalWindows, LaunchRemote
		wantPlatforms = allHostPlatforms()
	case BackendPhysicalMacOSRemote:
		wantKind, wantMode = KindRemotePhysicalMacOS, LaunchRemote
		wantPlatforms = allHostPlatforms()
	case BackendDualBoot:
		wantKind, wantMode = KindDualBoot, LaunchHandoff
		wantPlatforms = allHostPlatforms()
	default:
		return fmt.Errorf("%s has unknown backend id %q", path, b.ID)
	}
	if b.Kind != wantKind {
		return fmt.Errorf("%s kind %q does not match backend identity (want %q)", path, b.Kind, wantKind)
	}
	if b.LaunchMode != wantMode {
		return fmt.Errorf("%s launchMode %q does not match backend identity (want %q)", path, b.LaunchMode, wantMode)
	}
	if !samePlatformSet(b.HostPlatforms, wantPlatforms) {
		return fmt.Errorf("%s hostPlatforms do not match backend identity", path)
	}
	if len(b.HostArchitectures) != 1 || b.HostArchitectures[0] != ArchitectureAMD64 {
		return fmt.Errorf("%s hostArchitectures must be exactly [amd64]", path)
	}
	if b.ID == BackendPhysicalMacOSRemote && (b.State != StateHandoffOnly || b.LaunchVerdict != DecisionDeny || b.Authorization != AuthorizationUnverified) {
		return fmt.Errorf("%s physical macOS remote route must remain handoff-only, deny, and unverified", path)
	}
	return nil
}

func allHostPlatforms() []Platform {
	return []Platform{PlatformLinux, PlatformFreeBSD, PlatformOpenBSD, PlatformNetBSD, PlatformDragonFlyBSD}
}

func bsdPlatforms() []Platform {
	return []Platform{PlatformFreeBSD, PlatformOpenBSD, PlatformNetBSD, PlatformDragonFlyBSD}
}

func samePlatformSet(got, want []Platform) bool {
	if len(got) != len(want) {
		return false
	}
	set := make(map[Platform]struct{}, len(got))
	for _, value := range got {
		set[value] = struct{}{}
	}
	for _, value := range want {
		if _, ok := set[value]; !ok {
			return false
		}
	}
	return true
}

func checkJSONStructure(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := walkJSONValue(dec, "$", 0); err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	return expectEOF(dec)
}

func walkJSONValue(dec *json.Decoder, path string, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting exceeds 64 levels")
	}
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s: object key is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s: duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			if err := walkJSONValue(dec, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("%s: malformed object", path)
		}
	case '[':
		index := 0
		for dec.More() {
			if err := walkJSONValue(dec, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("%s: malformed array", path)
		}
	default:
		return fmt.Errorf("%s: unexpected delimiter %q", path, delim)
	}
	return nil
}

func checkExactFields(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var raw any
	if err := dec.Decode(&raw); err != nil {
		return fmt.Errorf("decode manifest fields: %w", err)
	}
	top, err := exactObject(raw, "$", "$schema", "schemaVersion", "manifestId", "asOf", "game", "policy", "sources", "backends")
	if err != nil {
		return err
	}
	if _, err := exactObject(top["game"], "$.game", "name", "publisher"); err != nil {
		return err
	}
	if _, err := exactObject(top["policy"], "$.policy", "defaultVerdict", "maxAgeDays", "requireOfficialAuthorization"); err != nil {
		return err
	}
	sources, err := exactArray(top["sources"], "$.sources")
	if err != nil {
		return err
	}
	for i, value := range sources {
		source, err := exactObject(value, fmt.Sprintf("$.sources[%d]", i), "id", "title", "publisher", "url", "publishedAt", "checkedAt")
		if err != nil {
			return err
		}
		if publishedAt, present := source["publishedAt"]; present {
			value, ok := publishedAt.(string)
			if !ok {
				return fmt.Errorf("decode manifest fields: $.sources[%d].publishedAt must be a date string when present", i)
			}
			if _, err := parseDate(fmt.Sprintf("$.sources[%d].publishedAt", i), value); err != nil {
				return fmt.Errorf("decode manifest fields: %w", err)
			}
		}
	}
	backends, err := exactArray(top["backends"], "$.backends")
	if err != nil {
		return err
	}
	for i, value := range backends {
		if _, err := exactObject(value, fmt.Sprintf("$.backends[%d]", i), "id", "displayName", "kind", "launchMode", "hostPlatforms", "hostArchitectures", "state", "launchVerdict", "authorization", "reasonCode", "summary", "sourceIds", "safetyNotes"); err != nil {
			return err
		}
	}
	return nil
}

func exactObject(value any, path string, allowed ...string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("decode manifest fields: %s must be an object", path)
	}
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		allowedSet[key] = struct{}{}
	}
	for key := range object {
		if _, ok := allowedSet[key]; !ok {
			return nil, fmt.Errorf("decode manifest fields: %s has unknown field %q", path, key)
		}
	}
	return object, nil
}

func exactArray(value any, path string) ([]any, error) {
	array, ok := value.([]any)
	if !ok {
		return nil, fmt.Errorf("decode manifest fields: %s must be an array", path)
	}
	return array, nil
}

func expectEOF(dec *json.Decoder) error {
	if _, err := dec.Token(); err == io.EOF {
		return nil
	} else if err != nil {
		return fmt.Errorf("decode manifest: %w", err)
	}
	return errors.New("decode manifest: trailing JSON value")
}

func parseDate(field, value string) (time.Time, error) {
	if len(value) != len("2006-01-02") {
		return time.Time{}, fmt.Errorf("%s must use YYYY-MM-DD", field)
	}
	parsed, err := time.Parse("2006-01-02", value)
	if err != nil || parsed.Format("2006-01-02") != value {
		return time.Time{}, fmt.Errorf("%s must be a valid YYYY-MM-DD date", field)
	}
	return parsed, nil
}

func validateSourceURL(value string) error {
	if len(value) > 2048 {
		return fmt.Errorf("source URL exceeds 2048 characters")
	}
	parsed, err := url.ParseRequestURI(value)
	if err != nil {
		return fmt.Errorf("invalid source URL %q", value)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("source URL must be an absolute HTTPS URL: %q", value)
	}
	if parsed.User != nil {
		return fmt.Errorf("source URL must not contain user information: %q", value)
	}
	return nil
}

func knownSchemaReference(value string) bool {
	switch value {
	case SchemaID, "../schemas/compatibility-manifest.schema.json", "../../../schemas/compatibility-manifest.schema.json":
		return true
	default:
		return false
	}
}

func validText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && strings.TrimSpace(value) != ""
}

func knownPlatform(value Platform) bool {
	switch value {
	case PlatformLinux, PlatformFreeBSD, PlatformOpenBSD, PlatformNetBSD, PlatformDragonFlyBSD:
		return true
	default:
		return false
	}
}

func oneOfBackendKind(value BackendKind) bool {
	switch value {
	case KindNative, KindTranslation, KindVirtualMachine, KindRemotePhysicalWindows, KindRemotePhysicalMacOS, KindDualBoot:
		return true
	default:
		return false
	}
}

func oneOfLaunchMode(value LaunchMode) bool {
	return value == LaunchLocal || value == LaunchRemote || value == LaunchHandoff
}

func oneOfState(value CompatibilityState) bool {
	return value == StateBlocked || value == StateHandoffOnly || value == StateSupported
}

func oneOfAuthorization(value Authorization) bool {
	return value == AuthorizationNone || value == AuthorizationUnverified || value == AuthorizationOfficial
}
