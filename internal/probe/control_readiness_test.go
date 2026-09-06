package probe

import "testing"

func TestControlReadinessIgnoresOnlyDisplayAndInputFailures(t *testing.T) {
	report := Report{
		SchemaVersion: SchemaVersion, Profile: ProfileClient, OS: "linux", Architecture: "amd64", Status: StatusFail,
		Checks: []Check{
			{ID: "client.platform", Status: StatusPass},
			{ID: "client.graphical-session", Status: StatusFail},
			{ID: "client.input", Status: StatusFail},
			{ID: "client.moonlight", Status: StatusPass},
			{ID: "client.audio", Status: StatusWarn},
			{ID: "client.decoder-tools", Status: StatusWarn},
		},
	}
	if !report.ReadyForControl() || report.Ready() {
		t.Fatal("headless control readiness must not authorize streaming")
	}
	for _, index := range []int{0, 3, 4, 5} {
		blocked := report
		blocked.Checks = append([]Check(nil), report.Checks...)
		blocked.Checks[index].Status = StatusFail
		if blocked.ReadyForControl() {
			t.Fatalf("control ignored failure in %s", blocked.Checks[index].ID)
		}
	}
}
