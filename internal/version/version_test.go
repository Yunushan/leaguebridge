package version

import "testing"

func TestCurrentIncludesVersion(t *testing.T) {
	originalVersion, originalCommit, originalDate, originalIdentity, originalVerification := Version, Commit, BuildDate, ReleaseIdentity, RepositoryEvidenceVerification
	t.Cleanup(func() {
		Version, Commit, BuildDate, ReleaseIdentity, RepositoryEvidenceVerification = originalVersion, originalCommit, originalDate, originalIdentity, originalVerification
	})
	Version, Commit, BuildDate, ReleaseIdentity, RepositoryEvidenceVerification = "v1.2.3", "abc", "2026-08-26T00:00:00Z", "leaguebridge-release:v1.2.3:linux:amd64", "leaguebridge-repository-evidence-v1:abc"
	info := Current()
	if info.Version != Version || info.Commit != Commit || info.BuildDate != BuildDate || info.ReleaseIdentity != ReleaseIdentity || info.RepositoryEvidenceVerification != RepositoryEvidenceVerification || info.GoVersion == "" {
		t.Fatalf("unexpected info: %+v", info)
	}
}
