package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLinuxBSDRemoteSessionScriptIsExplicitAndBounded(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-bsd-remote-session.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"usage: linux-bsd-remote-session.sh BINARY CONFIG --start",
		`if [ "$#" -lt 3 ] || [ "$#" -gt 9 ]; then`,
		"start_flag=$3",
		`if [ "$start_flag" != "--start" ]; then`,
		`if ! "$binary" config validate --file "$config" >/dev/null; then`,
		`"$binary" remote play \`,
		`--dry-run --json --acknowledge-unverified-handoff >/dev/null; then`,
		`--require-configured-app --require-app "League of Legends"`,
		`--acknowledge-unverified-handoff; then`,
		"gameplay remains unverified",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Linux/BSD remote session script is missing contract fragment %q", required)
		}
	}
	if strings.Contains(script, "doctor --profile") {
		t.Fatal("live-session helper must use the exact remote play preflight rather than an unrelated generic doctor selection")
	}
	listIndex := strings.Index(script, `"$binary" remote list`)
	streamIndex := strings.LastIndex(script, `"$binary" remote play`)
	if listIndex < 0 || streamIndex <= listIndex {
		t.Fatal("live-session helper must complete the host application list before starting remote play")
	}
	if strings.Contains(script, `"$binary" remote stream`) {
		t.Fatal("live-session helper must delegate its stream profile to the remote play command")
	}
	wakeListEnd := strings.Index(script[listIndex:], "\nelse")
	if wakeListEnd < 0 || !strings.Contains(script[listIndex:listIndex+wakeListEnd], "--acknowledge-unverified-handoff") {
		t.Fatal("live-session helper must acknowledge the unverified handoff before a Wake-on-LAN list bootstrap")
	}
}

func TestLinuxBSDRemoteSmokeExercisesRemotePlayDefaults(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-bsd-remote-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		`if "$binary" remote play \`,
		`--dry-run --json --acknowledge-unverified-handoff > "$evidence_dir/stream-plan.json"; then`,
		`require_json_success "$evidence_dir/stream-plan.json" "remote play"`,
		`printf '%s\n' "Run remote play separately`,
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Linux/BSD remote smoke script is missing remote-play contract fragment %q", required)
		}
	}
	for _, forbidden := range []string{
		`if "$binary" remote stream \`,
		`--resolution 1080 \`,
		`--fps 60 \`,
		`--bitrate 20000 \`,
		`--packet-size 1392 \`,
		`--codec h264 \`,
	} {
		if strings.Contains(script, forbidden) {
			t.Errorf("Linux/BSD remote smoke script must obtain the default from remote play, but contains %q", forbidden)
		}
	}
}

func TestLinuxBSDClientSmokeScriptIsHostFreeAndBounded(t *testing.T) {
	t.Parallel()
	data, err := os.ReadFile(filepath.Join("..", "..", "scripts", "linux-bsd-client-smoke.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(data)
	for _, required := range []string{
		"usage: linux-bsd-client-smoke.sh BINARY EVIDENCE_DIR",
		`if [ "$#" -ne 2 ]; then`,
		"set -f",
		"umask 077",
		`[ -L "$binary" ] || [ ! -f "$binary" ] || [ ! -x "$binary" ]`,
		`[ -L "$evidence_dir" ]`,
		"runtime_machine=$(uname -m)",
		"sysctl -n hw.machine_arch",
		"uname -p",
		`"$binary" doctor --profile client --json`,
		"client.platform client.graphical-session client.input client.moonlight",
		`--host example.invalid`,
		`--confirm-physical-host`,
		`--acknowledge-unverified-handoff`,
		`--dry-run --json > "$evidence_dir/play-plan.json"`,
		"network=not-used",
		"gameplay=not-tested",
	} {
		if !strings.Contains(script, required) {
			t.Errorf("Linux/BSD client smoke script is missing contract fragment %q", required)
		}
	}
	if strings.Contains(script, `"$binary" remote list`) || strings.Contains(script, `"$binary" remote stream`) {
		t.Fatal("client-only smoke must not contact or start a remote host")
	}
	if strings.Contains(script, "curl ") || strings.Contains(script, "wget ") || strings.Contains(script, "nc ") {
		t.Fatal("client-only smoke must not contain network bootstrap commands")
	}
}
