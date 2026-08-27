// Package version exposes build metadata injected by the release workflow.
package version

import "runtime/debug"

var (
	Version         = "dev"
	Commit          = "unknown"
	BuildDate       = "unknown"
	ReleaseIdentity = ""
	// RepositoryEvidenceVerification is injected only by the release builder
	// after it verifies the immutable source snapshot's readiness evidence.
	RepositoryEvidenceVerification = ""
)

type Info struct {
	Version                        string `json:"version"`
	Commit                         string `json:"commit"`
	BuildDate                      string `json:"build_date"`
	GoVersion                      string `json:"go_version"`
	ReleaseIdentity                string `json:"release_identity,omitempty"`
	RepositoryEvidenceVerification string `json:"repository_evidence_verification,omitempty"`
}

func Current() Info {
	info := Info{
		Version:                        Version,
		Commit:                         Commit,
		BuildDate:                      BuildDate,
		ReleaseIdentity:                ReleaseIdentity,
		RepositoryEvidenceVerification: RepositoryEvidenceVerification,
	}
	if build, ok := debug.ReadBuildInfo(); ok {
		info.GoVersion = build.GoVersion
		if info.Version == "dev" && build.Main.Version != "" && build.Main.Version != "(devel)" {
			info.Version = build.Main.Version
		}
		for _, setting := range build.Settings {
			if setting.Key == "vcs.revision" && info.Commit == "unknown" {
				info.Commit = setting.Value
			}
			if setting.Key == "vcs.time" && info.BuildDate == "unknown" {
				info.BuildDate = setting.Value
			}
		}
	}
	return info
}
