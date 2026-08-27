package version

import (
	"runtime/debug"
	"testing"
)

func TestCurrentUsesAvailableBuildFallbacks(t *testing.T) {
	originalVersion, originalCommit, originalDate, originalIdentity := Version, Commit, BuildDate, ReleaseIdentity
	t.Cleanup(func() {
		Version, Commit, BuildDate, ReleaseIdentity = originalVersion, originalCommit, originalDate, originalIdentity
	})
	Version, Commit, BuildDate, ReleaseIdentity = "dev", "unknown", "unknown", ""

	got := Current()
	build, ok := debug.ReadBuildInfo()
	if !ok {
		t.Skip("runtime build information is unavailable")
	}
	if got.GoVersion != build.GoVersion {
		t.Fatalf("GoVersion = %q, want %q", got.GoVersion, build.GoVersion)
	}

	wantVersion := "dev"
	if build.Main.Version != "" && build.Main.Version != "(devel)" {
		wantVersion = build.Main.Version
	}
	wantCommit, wantDate := "unknown", "unknown"
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			wantCommit = setting.Value
		case "vcs.time":
			wantDate = setting.Value
		}
	}
	if got.Version != wantVersion || got.Commit != wantCommit || got.BuildDate != wantDate {
		t.Fatalf("Current() = %+v, want version %q, commit %q, date %q", got, wantVersion, wantCommit, wantDate)
	}
}
