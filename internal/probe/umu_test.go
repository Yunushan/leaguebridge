package probe

import (
	"context"
	"strings"
	"testing"
)

func TestCompatibilityAuditDetectsUMU(t *testing.T) {
	t.Parallel()
	commands := &fixtureCommands{paths: map[string]bool{"umu-run": true}}
	report := fixtureProber("linux", "amd64", nil, nil, commands).Compatibility(context.Background())
	proton, _ := report.Check("compatibility.proton")
	if !strings.Contains(proton.Summary, "umu-run") {
		t.Fatalf("UMU launcher was not named: %+v", proton)
	}
	if proton.Status != StatusWarn {
		t.Fatalf("UMU launcher must remain non-certifying: %+v", proton)
	}
	if calls := commands.recordedCalls(); len(calls) != 0 {
		t.Fatalf("UMU compatibility audit executed a command: %+v", calls)
	}
}
