package probe

import "context"

const (
	macOSApplicationsDirectory = "/Applications"
	rioClientAppPath           = macOSApplicationsDirectory + "/Riot Client.app"
	leagueAppPath              = macOSApplicationsDirectory + "/League of Legends.app"
	sunshineAppPath            = macOSApplicationsDirectory + "/Sunshine.app"
)

// MacOSHost performs a conservative, read-only inspection of a prospective
// physical Mac streaming host. It never executes a command. Because the probe
// cannot attest physicality, OS version, hardware, or an actual local League
// session, a macOS-host report is never ready even when applications are found.
func (p *Prober) MacOSHost(ctx context.Context) Report {
	_ = ctx
	platform := p.macOSPlatformCheck()
	if platform.Status == StatusFail {
		return p.report(ProfileMacOSHost, []Check{platform})
	}
	checks := []Check{
		platform,
		{
			ID:       "host.macos-version",
			Status:   StatusWarn,
			Summary:  "The macOS version and update state remain unverified.",
			Guidance: "Manually confirm the current Riot requirements and Sunshine's experimental macOS 14.2-or-newer host baseline.",
		},
		{
			ID:       "host.physical-machine",
			Status:   StatusWarn,
			Summary:  "This read-only probe cannot attest that the Mac is physical rather than virtualized.",
			Guidance: "Use a user-owned physical Mac; do not conceal or spoof virtualization or machine identity.",
		},
		{
			ID:       "host.hardware-requirements",
			Status:   StatusWarn,
			Summary:  "CPU, memory, graphics, storage, display, and driver requirements remain unverified.",
			Guidance: "Compare the physical Mac with Riot's current native macOS requirements and Sunshine's host requirements.",
		},
		p.macOSRiotClientCheck(),
		p.macOSLeagueCheck(),
		p.macOSSunshineCheck(),
		{
			ID:       "host.remote-behavior",
			Status:   StatusWarn,
			Summary:  "Sunshine's macOS host path is experimental; capture, audio, keyboard/mouse, and gameplay behavior are unvalidated, and gamepad hosting is unavailable.",
			Guidance: "Treat discovery as inventory only. Validate the exact host and client manually without patching input or Riot software.",
		},
		{
			ID:       "host.local-practice-tool",
			Status:   StatusWarn,
			Summary:  "A successful local Practice Tool session on this Mac has not been observed.",
			Guidance: "Launch League directly through Riot's native macOS client and validate locally before separately authorizing streaming.",
		},
	}
	return p.report(ProfileMacOSHost, checks)
}

func (p *Prober) macOSPlatformCheck() Check {
	if p.goos != "darwin" || p.goarch != "amd64" && p.goarch != "arm64" {
		return Check{
			ID:       "host.platform",
			Status:   StatusFail,
			Summary:  "The streaming host is not macOS on amd64 or arm64.",
			Guidance: "Run this profile on a physical Intel or Apple-silicon Mac supported by Riot and Sunshine.",
		}
	}
	return Check{ID: "host.platform", Status: StatusPass, Summary: "The streaming host reports macOS on an eligible architecture; physicality is not attested."}
}

func (p *Prober) macOSRiotClientCheck() Check {
	if p.directoryExistsAny(rioClientAppPath) {
		return Check{ID: "host.riot-client", Status: StatusPass, Summary: "A Riot Client application directory is present in /Applications; signature and integrity are not verified."}
	}
	return Check{
		ID:       "host.riot-client",
		Status:   StatusFail,
		Summary:  "Riot Client was not detected in the system Applications directory.",
		Guidance: "Install Riot's native macOS client directly from Riot Games; do not copy client components from another operating system.",
	}
}

func (p *Prober) macOSLeagueCheck() Check {
	if p.directoryExistsAny(leagueAppPath) {
		return Check{ID: "host.league", Status: StatusPass, Summary: "A League of Legends application directory is present in /Applications; signature, integrity, and launchability are not verified."}
	}
	return Check{
		ID:       "host.league",
		Status:   StatusFail,
		Summary:  "League of Legends was not detected in the system Applications directory.",
		Guidance: "Install League through Riot's native macOS client on the physical Mac.",
	}
}

func (p *Prober) macOSSunshineCheck() Check {
	if p.directoryExistsAny(sunshineAppPath) {
		return Check{ID: "host.sunshine", Status: StatusPass, Summary: "A Sunshine application directory is present in /Applications; signature, integrity, configuration, and launchability are not verified."}
	}
	if _, ok := p.lookupAny("sunshine"); ok {
		return Check{ID: "host.sunshine", Status: StatusPass, Summary: "A Sunshine executable is discoverable; its origin, integrity, configuration, and launchability are not verified."}
	}
	return Check{
		ID:       "host.sunshine",
		Status:   StatusFail,
		Summary:  "Sunshine was not detected.",
		Guidance: "Obtain Sunshine only from its official project and review its experimental macOS limitations before any separately authorized installation.",
	}
}
