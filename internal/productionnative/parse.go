package productionnative

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/leaguebridge/internal/exactjson"
	"github.com/Yunushan/leaguebridge/internal/releaseversion"
)

const maxJSONDepth = 24

var assertionSets = map[Kind][]string{
	KindNativeIntegration: {"audio-pass", "display-pass", "input-pass", "moonlight-executed", "native-client-executed", "physical-game-host-usable"},
	KindPhysicalBSD:       {"native-cli-smoke-pass", "native-kernel-booted", "physical-machine-witnessed", "release-binary-installed"},
	KindPackageLifecycle:  {"cli-pass", "install-pass", "published-package-current", "uninstall-pass", "unrelated-files-preserved", "upgrade-or-repair-pass"},
}

var artifactSets = map[Kind][]string{
	KindNativeIntegration: {"audio-capture", "client-execution-log", "display-capture", "host-route-proof", "input-capture", "moonlight-execution-log", "native-dependency-record", "review-notes"},
	KindPhysicalBSD:       {"boot-evidence", "install-log", "machine-identity", "native-kernel-evidence", "native-smoke-log", "review-notes"},
	KindPackageLifecycle:  {"cli-log", "index-membership", "install-log", "installed-files-manifest", "package-signature", "publication-proof", "review-notes", "uninstall-log", "unrelated-files-proof", "upgrade-repair-log", "withdrawal-state"},
}

func parseEnvelope(data []byte) (envelope, []byte, observation, error) {
	if len(data) == 0 || len(data) > MaxEnvelopeSize {
		return envelope{}, nil, observation{}, errors.New("envelope size is outside its bound")
	}
	var parsed envelope
	if err := parseCanonicalJSON(data, &parsed); err != nil {
		return envelope{}, nil, observation{}, fmt.Errorf("decode signed envelope: %w", err)
	}
	if parsed.Schema != EnvelopeSchemaID || parsed.EnvelopeVersion != EnvelopeVersion ||
		parsed.PayloadType != PayloadType || parsed.PayloadEncoding != PayloadEncoding || len(parsed.Signatures) != 2 {
		return envelope{}, nil, observation{}, errors.New("signed envelope identity or exact two-signature quorum is invalid")
	}
	for index, item := range parsed.Signatures {
		if item.Algorithm != Algorithm || !strings.HasPrefix(item.KeyID, "lbn1-") ||
			len(item.KeyID) != 69 || !digestPattern.MatchString(strings.TrimPrefix(item.KeyID, "lbn1-")) {
			return envelope{}, nil, observation{}, fmt.Errorf("signature %d identity is invalid", index)
		}
		if _, err := canonicalTime("signature signed_at", item.SignedAt); err != nil {
			return envelope{}, nil, observation{}, err
		}
		if _, err := lowerHex("signature", item.Signature, 64); err != nil {
			return envelope{}, nil, observation{}, err
		}
	}
	if parsed.Signatures[0].KeyID == parsed.Signatures[1].KeyID {
		return envelope{}, nil, observation{}, errors.New("envelope repeats reviewer key")
	}
	payloadData, err := base64.RawURLEncoding.DecodeString(parsed.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payloadData) != parsed.Payload || len(payloadData) == 0 || len(payloadData) > MaxPayloadSize {
		return envelope{}, nil, observation{}, errors.New("payload must be bounded canonical base64url without padding")
	}
	var payload observation
	if err := parseCanonicalJSON(payloadData, &payload); err != nil {
		return envelope{}, nil, observation{}, fmt.Errorf("decode signed payload: %w", err)
	}
	if err := validateObservation(payload); err != nil {
		return envelope{}, nil, observation{}, err
	}
	return parsed, payloadData, payload, nil
}

func parseCanonicalJSON(data []byte, destination any) error {
	if !utf8.Valid(data) {
		return errors.New("JSON is not UTF-8")
	}
	if err := inspectJSON(data); err != nil {
		return err
	}
	if err := exactjson.ValidateKeys(data, reflect.Indirect(reflect.ValueOf(destination)).Interface()); err != nil {
		return err
	}
	if err := json.Unmarshal(data, destination); err != nil {
		return err
	}
	canonical, err := json.MarshalIndent(destination, "", "  ")
	if err != nil {
		return err
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(data, canonical) {
		return errors.New("JSON must use exact canonical encoding")
	}
	return nil
}

// inspectJSON rejects duplicate keys before any decoding can discard them.
func inspectJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, "$", 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON has trailing value")
		}
		return err
	}
	return nil
}

func walkJSON(decoder *json.Decoder, path string, depth int) error {
	if depth > maxJSONDepth {
		return errors.New("JSON nesting exceeds bound")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("%s cannot be null", path)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return fmt.Errorf("%s has duplicate or invalid object key %q", path, key)
			}
			seen[key] = true
			if err := walkJSON(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		for i := 0; decoder.More(); i++ {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
		if end, err := decoder.Token(); err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return errors.New("JSON has unexpected delimiter")
	}
	return nil
}

func validateObservation(value observation) error {
	if value.Schema != PayloadSchemaID || value.SchemaVersion != PayloadVersion || value.ObservationType != PayloadType || value.PolicyID != policyID {
		return errors.New("observation payload identity is invalid")
	}
	if !supportedCell(value.Kind, value.Cell) {
		return errors.New("observation cell is outside the fixed inventory")
	}
	if !observationIDPattern.MatchString(value.ObservationID) || !runIDPattern.MatchString(value.RunID) ||
		!machineIDPattern.MatchString(value.MachineID) || !challengePattern.MatchString(value.Challenge) {
		return errors.New("observation, run, machine, or challenge identifier is invalid")
	}
	start, err := canonicalTime("created_at", value.CreatedAt)
	if err != nil {
		return err
	}
	end, err := canonicalTime("expires_at", value.ExpiresAt)
	if err != nil {
		return err
	}
	if !end.After(start) || end.Sub(start) > 30*24*time.Hour {
		return errors.New("observation validity must be positive and at most 30 days")
	}
	if err := validateReleaseBinding(value.Release, value.Cell); err != nil {
		return err
	}
	if value.Kind == KindPackageLifecycle {
		if !digestPattern.MatchString(value.PackageSHA256) {
			return errors.New("lifecycle package_sha256 is invalid")
		}
	} else if value.PackageSHA256 != "" {
		return errors.New("non-lifecycle observation must not claim a package")
	}
	if value.Kind == KindNativeIntegration {
		if value.HostRoute != "physical-windows-remote" && value.HostRoute != "physical-macos-remote" {
			return errors.New("integration host route is unsupported")
		}
	} else if value.HostRoute != "" {
		return errors.New("non-integration observation must not claim a game host route")
	}
	if value.NativeKernel != nativeKernel(value.Cell.GOOS) {
		return errors.New("native_kernel does not match fixed cell")
	}
	if !reflect.DeepEqual(value.Assertions, assertionSets[value.Kind]) {
		return errors.New("observation assertions do not match the complete fixed kind contract")
	}
	expectedArtifacts := artifactSets[value.Kind]
	if len(value.Artifacts) != len(expectedArtifacts) {
		return errors.New("observation has incomplete artifact inventory")
	}
	var total int64
	for i, item := range value.Artifacts {
		if item.Kind != expectedArtifacts[i] || item.SizeBytes <= 0 || item.SizeBytes > MaxArtifactSize || !digestPattern.MatchString(item.SHA256) {
			return fmt.Errorf("artifact %d identity or size is invalid", i)
		}
		total += item.SizeBytes
		if total > MaxArtifactSet {
			return errors.New("artifact set exceeds total size bound")
		}
	}
	return nil
}

func validateReleaseBinding(value ReleaseBinding, cell Cell) error {
	if !releaseversion.Valid(value.Version) || len(value.Version) > 128 || strings.ContainsAny(value.Version, "+-") ||
		!objectIDPattern.MatchString(value.Commit) || !objectIDPattern.MatchString(value.Tree) || len(value.Commit) != len(value.Tree) || value.ReleaseID <= 0 ||
		!digestPattern.MatchString(value.ArchiveSHA256) || !digestPattern.MatchString(value.ExecutableSHA256) {
		return errors.New("release identity or digest is invalid")
	}
	expectedArchive := "leaguebridge_" + strings.TrimPrefix(value.Version, "v") + "_" + cell.GOOS + "_" + cell.GOARCH + ".tar.gz"
	if value.ArchiveFilename != expectedArchive {
		return errors.New("release archive filename does not match target")
	}
	return nil
}

func nativeKernel(goos string) string {
	switch goos {
	case "linux":
		return "Linux"
	case "freebsd":
		return "FreeBSD"
	case "openbsd":
		return "OpenBSD"
	case "netbsd":
		return "NetBSD"
	case "dragonfly":
		return "DragonFly"
	default:
		return ""
	}
}
