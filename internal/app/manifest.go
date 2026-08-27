package app

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/Yunushan/leaguebridge/internal/compat"
	"github.com/Yunushan/leaguebridge/internal/fileinput"
)

func (a *App) runManifest(args []string) int {
	if len(args) == 0 {
		return a.commandError("manifest", false, ExitUsage, "expected show, verify, or validate")
	}
	switch args[0] {
	case "show":
		set := a.flagSet("manifest show")
		if err := parseFlags(set, args[1:]); err != nil {
			return a.commandError("manifest show", false, ExitUsage, "%v", err)
		}
		data := compat.EmbeddedJSON()
		if _, err := a.Stdout.Write(data); err != nil {
			return a.commandError("manifest show", false, ExitInternal, "write manifest: %v", err)
		}
		if len(data) == 0 || data[len(data)-1] != '\n' {
			fmt.Fprintln(a.Stdout)
		}
		return ExitOK
	case "verify":
		return a.runManifestVerify(args[1:])
	case "validate":
		return a.runManifestValidate(args[1:])
	default:
		return a.commandError("manifest", false, ExitUsage, "unknown subcommand %q", args[0])
	}
}

func (a *App) runManifestVerify(args []string) int {
	set := a.flagSet("manifest verify")
	asJSON := set.Bool("json", false, "emit JSON")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("manifest verify", *asJSON, ExitUsage, "%v", err)
	}
	manifest, err := compat.Embedded()
	if err != nil {
		return a.commandError("manifest verify", *asJSON, ExitInternal, "embedded manifest is invalid: %v", err)
	}
	digest, err := compat.CanonicalSHA256(manifest)
	if err != nil {
		return a.commandError("manifest verify", *asJSON, ExitInternal, "compute canonical manifest digest: %v", err)
	}
	freshness, err := manifest.FreshnessAt(a.now())
	if err != nil {
		return a.commandError("manifest verify", *asJSON, ExitInternal, "freshness check failed: %v", err)
	}
	data := struct {
		Valid      bool             `json:"valid"`
		ManifestID string           `json:"manifest_id"`
		SHA256     string           `json:"sha256"`
		Freshness  compat.Freshness `json:"freshness"`
	}{true, manifest.ManifestID, digest, freshness}
	if *asJSON {
		if code := a.writeJSON("manifest verify", data); code != ExitOK {
			return code
		}
	} else {
		fmt.Fprintf(a.Stdout, "Embedded manifest is structurally valid; canonical SHA-256 is %s; evidence is %s (%d/%d days).\n", digest, freshness.State, freshness.AgeDays, freshness.MaxAgeDays)
	}
	if freshness.State != compat.FreshnessFresh {
		return ExitBlocked
	}
	return ExitOK
}

func (a *App) runManifestValidate(args []string) int {
	set := a.flagSet("manifest validate")
	file := set.String("file", "", "manifest JSON file")
	if err := parseFlags(set, args); err != nil {
		return a.commandError("manifest validate", false, ExitUsage, "%v", err)
	}
	if strings.TrimSpace(*file) == "" {
		return a.commandError("manifest validate", false, ExitUsage, "--file is required")
	}
	data, err := readBounded(*file, compat.MaxManifestBytes)
	if err != nil {
		return a.commandError("manifest validate", false, ExitUsage, "read manifest: %v", err)
	}
	manifest, err := compat.Parse(data)
	if err != nil {
		return a.commandError("manifest validate", false, ExitBlocked, "manifest is invalid: %v", err)
	}
	fmt.Fprintf(a.Stdout, "Manifest %s is structurally valid and informational only. It cannot override embedded launch policy.\n", manifest.ManifestID)
	return ExitOK
}

func readBounded(path string, maximum int) ([]byte, error) {
	f, err := fileinput.OpenRegular(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maximum {
		return nil, fmt.Errorf("file exceeds %d bytes", maximum)
	}
	if len(data) == 0 {
		return nil, errors.New("file is empty")
	}
	return data, nil
}
