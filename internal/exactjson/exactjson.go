// Package exactjson validates that JSON object member names exactly match the
// json tags of a destination type. The standard encoding/json decoder accepts
// case-insensitive field-name matches, which is unsuitable for strict public
// schemas and security-sensitive configuration.
package exactjson

import (
	"bytes"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

const maximumDepth = 128

var (
	jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()
	textUnmarshalerType = reflect.TypeOf((*encoding.TextUnmarshaler)(nil)).Elem()
)

// ValidateKeys rejects unknown and case-variant object member names at every
// object represented by destination. It also rejects null and obvious JSON
// shape mismatches for non-pointer Go fields. Every named field is required
// unless its json tag includes omitempty; numeric-range and domain validation
// remain the caller's responsibility.
func ValidateKeys(data []byte, destination any) error {
	destinationType := reflect.TypeOf(destination)
	if destinationType == nil {
		return errors.New("exact JSON destination is nil")
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return fmt.Errorf("decode trailing JSON data: %w", err)
	}
	return validateValue(value, destinationType, "$", 0)
}

func validateValue(value any, destinationType reflect.Type, location string, depth int) error {
	if depth > maximumDepth {
		return fmt.Errorf("%s exceeds %d levels", location, maximumDepth)
	}
	for destinationType.Kind() == reflect.Pointer {
		if value == nil {
			return nil
		}
		destinationType = destinationType.Elem()
	}
	if value == nil {
		return fmt.Errorf("%s cannot be null", location)
	}
	if opaqueType(destinationType) {
		return nil
	}

	switch destinationType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", location)
		}
		fields, err := fieldsFor(destinationType)
		if err != nil {
			return err
		}
		for key, child := range object {
			field, ok := fields[key]
			if !ok {
				return fmt.Errorf("%s has unknown or non-exact field %q", location, key)
			}
			if err := validateValue(child, field.destinationType, location+"."+key, depth+1); err != nil {
				return err
			}
		}
		for name, field := range fields {
			if _, present := object[name]; !present && !field.optional {
				return fmt.Errorf("%s is missing required field %q", location, name)
			}
		}
	case reflect.Slice, reflect.Array:
		if destinationType.Kind() == reflect.Slice && destinationType.Elem().Kind() == reflect.Uint8 {
			if _, ok := value.(string); !ok {
				return fmt.Errorf("%s must be a base64 string", location)
			}
			return nil
		}
		array, ok := value.([]any)
		if !ok {
			return fmt.Errorf("%s must be an array", location)
		}
		for index, child := range array {
			if err := validateValue(child, destinationType.Elem(), fmt.Sprintf("%s[%d]", location, index), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("%s must be an object", location)
		}
		for key, child := range object {
			if err := validateValue(child, destinationType.Elem(), location+"."+key, depth+1); err != nil {
				return err
			}
		}
	case reflect.Bool:
		if _, ok := value.(bool); !ok {
			return fmt.Errorf("%s must be a boolean", location)
		}
	case reflect.String:
		if _, ok := value.(string); !ok {
			return fmt.Errorf("%s must be a string", location)
		}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		if _, ok := value.(json.Number); !ok {
			return fmt.Errorf("%s must be a number", location)
		}
	}
	return nil
}

type fieldDefinition struct {
	destinationType reflect.Type
	optional        bool
}

func fieldsFor(destinationType reflect.Type) (map[string]fieldDefinition, error) {
	fields := make(map[string]fieldDefinition)
	if err := collectFields(destinationType, fields); err != nil {
		return nil, err
	}
	return fields, nil
}

func collectFields(destinationType reflect.Type, fields map[string]fieldDefinition) error {
	for index := 0; index < destinationType.NumField(); index++ {
		field := destinationType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		tag := field.Tag.Get("json")
		parts := strings.Split(tag, ",")
		name := parts[0]
		if name == "-" {
			continue
		}
		if field.Anonymous && name == "" {
			embeddedType := field.Type
			for embeddedType.Kind() == reflect.Pointer {
				embeddedType = embeddedType.Elem()
			}
			if embeddedType.Kind() == reflect.Struct && !opaqueType(embeddedType) {
				if err := collectFields(embeddedType, fields); err != nil {
					return err
				}
				continue
			}
		}
		if name == "" {
			name = field.Name
		}
		optional := false
		for _, option := range parts[1:] {
			if option == "omitempty" {
				optional = true
			}
		}
		if _, duplicate := fields[name]; duplicate {
			return fmt.Errorf("destination type %s has ambiguous JSON field %q", destinationType, name)
		}
		fields[name] = fieldDefinition{destinationType: field.Type, optional: optional}
	}
	return nil
}

func opaqueType(destinationType reflect.Type) bool {
	if destinationType == reflect.TypeOf(json.RawMessage{}) {
		return true
	}
	return destinationType.Implements(jsonUnmarshalerType) ||
		reflect.PointerTo(destinationType).Implements(jsonUnmarshalerType) ||
		destinationType.Implements(textUnmarshalerType) ||
		reflect.PointerTo(destinationType).Implements(textUnmarshalerType)
}
