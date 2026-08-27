package evidencev2

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/Yunushan/leaguebridge/internal/evidence"
)

const maxJSONDepth = 32

var (
	setIDPattern = regexp.MustCompile(`^set-[a-f0-9]{32}$`)
	runIDPattern = regexp.MustCompile(`^run-[a-f0-9]{32}$`)
	keyIDPattern = regexp.MustCompile(`^lbk1-[a-f0-9]{64}$`)
	shaPattern   = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

var supportedClientPlatforms = map[string]bool{
	"linux":        true,
	"freebsd":      true,
	"openbsd":      true,
	"netbsd":       true,
	"dragonflybsd": true,
}

func parseEnvelope(data []byte) (signatureEnvelope, []byte, payload, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return signatureEnvelope{}, nil, payload{}, errors.New("signature envelope is empty")
	}
	if len(data) > MaxEnvelopeSize {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("signature envelope exceeds %d bytes", MaxEnvelopeSize)
	}
	if !utf8.Valid(data) {
		return signatureEnvelope{}, nil, payload{}, errors.New("signature envelope is not valid UTF-8")
	}
	if err := inspectJSON(data, "signature envelope"); err != nil {
		return signatureEnvelope{}, nil, payload{}, err
	}
	if err := requireExactKeys(data, "$", "$schema", "envelope_version", "payload_type", "payload_encoding", "payload", "signatures"); err != nil {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("decode signature envelope: %w", err)
	}

	var envelope signatureEnvelope
	if err := decodeStrictJSON(data, &envelope, "signature envelope"); err != nil {
		return signatureEnvelope{}, nil, payload{}, err
	}
	if envelope.Schema != EnvelopeSchemaID {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("unknown signature-envelope $schema %q", envelope.Schema)
	}
	if envelope.EnvelopeVersion != EnvelopeVersion {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("unsupported envelope_version %d", envelope.EnvelopeVersion)
	}
	if envelope.PayloadType != PayloadType {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("unsupported payload_type %q", envelope.PayloadType)
	}
	if envelope.PayloadEncoding != PayloadEncoding {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("unsupported payload_encoding %q", envelope.PayloadEncoding)
	}
	if len(envelope.Signatures) < MinSignatures || len(envelope.Signatures) > MaxSignatures {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("signature envelope must contain between %d and %d signatures", MinSignatures, MaxSignatures)
	}

	top, err := decodeRawObject(data)
	if err != nil {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("decode signature envelope: %w", err)
	}
	var rawSignatures []json.RawMessage
	if err := json.Unmarshal(top["signatures"], &rawSignatures); err != nil {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("decode signature envelope signatures: %w", err)
	}
	for index, raw := range rawSignatures {
		if err := requireExactKeys(raw, fmt.Sprintf("$.signatures[%d]", index), "algorithm", "key_id", "signed_at", "signature"); err != nil {
			return signatureEnvelope{}, nil, payload{}, fmt.Errorf("decode signature envelope: %w", err)
		}
	}

	previousKeyID := ""
	for index, item := range envelope.Signatures {
		if item.Algorithm != Algorithm {
			return signatureEnvelope{}, nil, payload{}, fmt.Errorf("signature %d has unsupported algorithm %q", index, item.Algorithm)
		}
		if !keyIDPattern.MatchString(item.KeyID) {
			return signatureEnvelope{}, nil, payload{}, fmt.Errorf("signature %d has invalid key_id %q", index, item.KeyID)
		}
		if index > 0 && item.KeyID <= previousKeyID {
			return signatureEnvelope{}, nil, payload{}, errors.New("signatures must be strictly sorted by unique key_id")
		}
		previousKeyID = item.KeyID
		if _, err := parseCanonicalTimestamp(fmt.Sprintf("signature %d signed_at", index), item.SignedAt); err != nil {
			return signatureEnvelope{}, nil, payload{}, err
		}
		if _, err := decodeLowerHex(fmt.Sprintf("signature %d signature", index), item.Signature, 64); err != nil {
			return signatureEnvelope{}, nil, payload{}, err
		}
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.RawURLEncoding.EncodeToString(payloadBytes) != envelope.Payload {
		return signatureEnvelope{}, nil, payload{}, errors.New("payload must be canonical base64url without padding")
	}
	if len(payloadBytes) == 0 {
		return signatureEnvelope{}, nil, payload{}, errors.New("decoded payload is empty")
	}
	if len(payloadBytes) > MaxPayloadSize {
		return signatureEnvelope{}, nil, payload{}, fmt.Errorf("decoded payload exceeds %d bytes", MaxPayloadSize)
	}
	parsedPayload, err := parsePayload(payloadBytes)
	if err != nil {
		return signatureEnvelope{}, nil, payload{}, err
	}
	return envelope, payloadBytes, parsedPayload, nil
}

func parsePayload(data []byte) (payload, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return payload{}, errors.New("validation-evidence v2 payload is empty")
	}
	if len(data) > MaxPayloadSize {
		return payload{}, fmt.Errorf("validation-evidence v2 payload exceeds %d bytes", MaxPayloadSize)
	}
	if !utf8.Valid(data) {
		return payload{}, errors.New("validation-evidence v2 payload is not valid UTF-8")
	}
	if err := inspectJSON(data, "validation-evidence v2 payload"); err != nil {
		return payload{}, err
	}
	if err := requireExactKeys(data, "$", "$schema", "schema_version", "set_id", "validation_run_id", "route_id", "test_profile_id", "policy_id", "created_at", "expires_at", "manifest_as_of", "manifest_sha256", "host_platform", "host_architecture", "client_platform", "client_architecture", "host_record_sha256", "client_record_sha256", "session_record_sha256"); err != nil {
		return payload{}, fmt.Errorf("decode validation-evidence v2 payload: %w", err)
	}
	var parsed payload
	if err := decodeStrictJSON(data, &parsed, "validation-evidence v2 payload"); err != nil {
		return payload{}, err
	}
	if parsed.Schema != PayloadSchemaID {
		return payload{}, fmt.Errorf("unknown validation-evidence v2 $schema %q", parsed.Schema)
	}
	if parsed.SchemaVersion != PayloadVersion {
		return payload{}, fmt.Errorf("unsupported validation-evidence schema_version %d", parsed.SchemaVersion)
	}
	if !setIDPattern.MatchString(parsed.SetID) {
		return payload{}, fmt.Errorf("invalid set_id %q", parsed.SetID)
	}
	if !runIDPattern.MatchString(parsed.ValidationRunID) {
		return payload{}, fmt.Errorf("invalid validation_run_id %q", parsed.ValidationRunID)
	}
	if parsed.RouteID != RoutePhysicalWindowsRemote {
		return payload{}, fmt.Errorf("unsupported validation-evidence v2 route_id %q; only %q is implemented", parsed.RouteID, RoutePhysicalWindowsRemote)
	}
	if parsed.TestProfileID != TestProfileRemotePlayV1 {
		return payload{}, fmt.Errorf("unsupported validation-evidence v2 test_profile_id %q", parsed.TestProfileID)
	}
	if !validSlug(parsed.PolicyID, 128) {
		return payload{}, errors.New("policy_id must be a bounded lowercase identifier")
	}
	createdAt, err := parseCanonicalTimestamp("created_at", parsed.CreatedAt)
	if err != nil {
		return payload{}, err
	}
	expiresAt, err := parseCanonicalTimestamp("expires_at", parsed.ExpiresAt)
	if err != nil {
		return payload{}, err
	}
	if !expiresAt.After(createdAt) || expiresAt.Sub(createdAt) > evidence.MaxValidity {
		return payload{}, fmt.Errorf("expires_at must follow created_at by no more than %s", evidence.MaxValidity)
	}
	manifestDate, err := time.Parse("2006-01-02", parsed.ManifestAsOf)
	if err != nil || manifestDate.Format("2006-01-02") != parsed.ManifestAsOf {
		return payload{}, errors.New("manifest_as_of must be a canonical YYYY-MM-DD date")
	}
	createdDate, _ := time.Parse("2006-01-02", createdAt.Format("2006-01-02"))
	if createdDate.Before(manifestDate) {
		return payload{}, errors.New("created_at cannot precede manifest_as_of")
	}
	if !shaPattern.MatchString(parsed.ManifestSHA256) {
		return payload{}, errors.New("manifest_sha256 must be a lowercase SHA-256")
	}
	if parsed.HostPlatform != "windows" || parsed.HostArchitecture != "amd64" {
		return payload{}, errors.New("physical-windows-remote host must be windows/amd64")
	}
	if !supportedClientPlatforms[parsed.ClientPlatform] {
		return payload{}, fmt.Errorf("unsupported client_platform %q", parsed.ClientPlatform)
	}
	if parsed.ClientArchitecture != "amd64" {
		return payload{}, errors.New("client_architecture must be amd64")
	}
	for _, digest := range []struct {
		name  string
		value string
	}{
		{"host_record_sha256", parsed.HostRecordSHA256},
		{"client_record_sha256", parsed.ClientRecordSHA256},
		{"session_record_sha256", parsed.SessionRecordSHA256},
	} {
		if !shaPattern.MatchString(digest.value) {
			return payload{}, fmt.Errorf("%s must be a lowercase SHA-256", digest.name)
		}
	}
	return parsed, nil
}

func parseCanonicalTimestamp(name, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Nanosecond() != 0 || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return time.Time{}, fmt.Errorf("%s must be canonical whole-second UTC RFC3339", name)
	}
	return parsed, nil
}

func inspectJSON(data []byte, name string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := walkJSON(decoder, "$", 0); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", name)
		}
		return fmt.Errorf("decode %s: %w", name, err)
	}
	return nil
}

func walkJSON(decoder *json.Decoder, path string, depth int) error {
	if depth > maxJSONDepth {
		return fmt.Errorf("JSON nesting exceeds %d levels", maxJSONDepth)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("%s must not be null", path)
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("%s has a non-string object key", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := walkJSON(decoder, path+"."+key, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("%s has an invalid object terminator", path)
		}
	case '[':
		index := 0
		for decoder.More() {
			if err := walkJSON(decoder, fmt.Sprintf("%s[%d]", path, index), depth+1); err != nil {
				return err
			}
			index++
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("%s has an invalid array terminator", path)
		}
	default:
		return fmt.Errorf("%s starts with invalid delimiter %q", path, delimiter)
	}
	return nil
}

func requireExactKeys(data []byte, path string, required ...string) error {
	object, err := decodeRawObject(data)
	if err != nil {
		return fmt.Errorf("%s must be an object", path)
	}
	wanted := make(map[string]struct{}, len(required))
	for _, key := range required {
		wanted[key] = struct{}{}
		if _, present := object[key]; !present {
			return fmt.Errorf("missing required field %q at %s", key, path)
		}
	}
	unknown := make([]string, 0)
	for key := range object {
		if _, ok := wanted[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) != 0 {
		sort.Strings(unknown)
		return fmt.Errorf("unknown field %q at %s", unknown[0], path)
	}
	return nil
}

func decodeRawObject(data []byte) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(data, &object); err != nil {
		return nil, err
	}
	if object == nil || bytes.TrimSpace(data)[0] != '{' {
		return nil, errors.New("value is not an object")
	}
	return object, nil
}

func decodeStrictJSON(data []byte, target any, name string) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", name)
		}
		return fmt.Errorf("decode %s: %w", name, err)
	}
	return nil
}
