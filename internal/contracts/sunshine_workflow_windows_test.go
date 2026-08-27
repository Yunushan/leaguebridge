//go:build windows

package contracts

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestSunshineInspectorRefusesBeforeFileAccessWithoutConsent(t *testing.T) {
	script := repositoryFile(t, "scripts/inspect-sunshine-host.ps1")
	command := exec.Command(
		"powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-NonInteractive",
		"-ExecutionPolicy", "Bypass",
		"-File", script,
		"-ArtifactPath", `Z:\does-not-exist\Sunshine-Windows-AMD64-installer.msi`,
		"-LeagueBridgePath", `Z:\does-not-exist\leaguebridge.exe`,
		"-ExpectedLeagueBridgeSha256", strings.Repeat("0", 64),
		"-Json",
	)
	output, err := command.CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 2 {
		t.Fatalf("Sunshine inspector exit = %v, output = %s", err, output)
	}
	var result struct {
		InspectionStatus       string `json:"inspection_status"`
		InstallationAuthorized bool   `json:"installation_authorized"`
		LaunchAuthorized       bool   `json:"launch_authorized"`
	}
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("decode Sunshine inspector consent refusal: %v; output = %s", err, output)
	}
	if result.InspectionStatus != "consent-required" || result.InstallationAuthorized || result.LaunchAuthorized {
		t.Fatalf("Sunshine inspector consent refusal = %s", output)
	}
}
