package exactjson

import (
	"strings"
	"testing"
	"time"
)

type testChild struct {
	ExactName string `json:"exact_name"`
}

type testDocument struct {
	SchemaVersion int                  `json:"schema_version"`
	Child         testChild            `json:"child"`
	Children      []testChild          `json:"children"`
	Dynamic       map[string]testChild `json:"dynamic"`
	ObservedAt    time.Time            `json:"observed_at"`
	Optional      string               `json:"optional,omitempty"`
}

func TestValidateKeysRequiresExactNamesRecursively(t *testing.T) {
	valid := `{"schema_version":1,"child":{"exact_name":"a"},"children":[{"exact_name":"b"}],"dynamic":{"slot":{"exact_name":"c"}},"observed_at":"2026-08-26T00:00:00Z"}`
	if err := ValidateKeys([]byte(valid), &testDocument{}); err != nil {
		t.Fatalf("valid document rejected: %v", err)
	}

	for _, test := range []struct {
		name string
		data string
	}{
		{name: "top-level case variant", data: strings.Replace(valid, `"schema_version"`, `"Schema_Version"`, 1)},
		{name: "nested case variant", data: strings.Replace(valid, `"exact_name":"a"`, `"EXACT_NAME":"a"`, 1)},
		{name: "slice case variant", data: strings.Replace(valid, `"exact_name":"b"`, `"Exact_Name":"b"`, 1)},
		{name: "map-value case variant", data: strings.Replace(valid, `"exact_name":"c"`, `"exactName":"c"`, 1)},
		{name: "unknown", data: strings.Replace(valid, `"child":`, `"other":0,"child":`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateKeys([]byte(test.data), &testDocument{}); err == nil {
				t.Fatal("non-exact object field was accepted")
			}
		})
	}
}

func TestValidateKeysRejectsTrailingValuesAndNilDestination(t *testing.T) {
	if err := ValidateKeys([]byte(`{} {}`), &testDocument{}); err == nil {
		t.Fatal("multiple values were accepted")
	}
	if err := ValidateKeys([]byte(`{}`), nil); err == nil {
		t.Fatal("nil destination was accepted")
	}
}

func TestValidateKeysRejectsNullAndWrongPrimitiveShapes(t *testing.T) {
	valid := `{"schema_version":1,"child":{"exact_name":"a"},"children":[],"dynamic":{},"observed_at":"2026-08-26T00:00:00Z"}`
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "null integer", data: strings.Replace(valid, `"schema_version":1`, `"schema_version":null`, 1)},
		{name: "string integer", data: strings.Replace(valid, `"schema_version":1`, `"schema_version":"1"`, 1)},
		{name: "null string", data: strings.Replace(valid, `"exact_name":"a"`, `"exact_name":null`, 1)},
		{name: "null struct", data: strings.Replace(valid, `"child":{"exact_name":"a"}`, `"child":null`, 1)},
		{name: "null slice", data: strings.Replace(valid, `"children":[]`, `"children":null`, 1)},
		{name: "null map", data: strings.Replace(valid, `"dynamic":{}`, `"dynamic":null`, 1)},
		{name: "null custom unmarshaler", data: strings.Replace(valid, `"observed_at":"2026-08-26T00:00:00Z"`, `"observed_at":null`, 1)},
		{name: "missing required field", data: strings.Replace(valid, `"schema_version":1,`, ``, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateKeys([]byte(test.data), &testDocument{}); err == nil {
				t.Fatal("schema-incompatible JSON shape was accepted")
			}
		})
	}
}
