package app

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
)

type jsonEnvelope struct {
	SchemaVersion int    `json:"schema_version"`
	Command       string `json:"command"`
	OK            bool   `json:"ok"`
	Data          any    `json:"data,omitempty"`
	Error         string `json:"error,omitempty"`
}

func (a *App) writeJSON(command string, data any) int {
	encoder := json.NewEncoder(a.Stdout)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(jsonEnvelope{SchemaVersion: 1, Command: command, OK: true, Data: data}); err != nil {
		fmt.Fprintf(a.Stderr, "leaguebridge: encode output: %v\n", err)
		return ExitInternal
	}
	return ExitOK
}

func (a *App) commandError(command string, asJSON bool, code int, format string, args ...any) int {
	message := fmt.Sprintf(format, args...)
	if asJSON {
		encoder := json.NewEncoder(a.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(jsonEnvelope{SchemaVersion: 1, Command: command, OK: false, Error: message}); err != nil {
			fmt.Fprintf(a.Stderr, "leaguebridge: %s\n", message)
			return ExitInternal
		}
	} else {
		fmt.Fprintf(a.Stderr, "leaguebridge: %s\n", message)
	}
	return code
}

func (a *App) flagSet(name string) *flag.FlagSet {
	set := flag.NewFlagSet(name, flag.ContinueOnError)
	set.SetOutput(a.Stderr)
	set.Usage = func() {}
	return set
}

func parseFlags(set *flag.FlagSet, args []string) error {
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", set.Args())
	}
	return nil
}

func printJSONValue(w io.Writer, value any) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
