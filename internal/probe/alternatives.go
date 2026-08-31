package probe

import (
	"context"
	"path/filepath"
	"sort"
	"strings"
)

// Compatibility audits the compatibility layers and virtual-machine launchers
// that are commonly suggested for League on Linux/BSD. It only performs
// allowlisted PATH discovery; it never starts, installs, patches, or configures
// any of these programs. Every discovered alternative remains non-certifying
// because Riot's Vanguard requirements are outside these launchers' control.
func (p *Prober) Compatibility(_ context.Context) Report {
	checks := []Check{
		p.compatibilityPlatformCheck(),
		p.wineCompatibilityCheck(),
		p.protonCompatibilityCheck(),
		p.lutrisCompatibilityCheck(),
		p.virtualMachineCompatibilityCheck(),
		p.otherCompatibilityLayerCheck(),
		p.nativeVanguardCompatibilityCheck(),
	}
	return p.report(ProfileCompatibility, checks)
}

func (p *Prober) compatibilityPlatformCheck() Check {
	if _, ok := eligibleClientOS[p.goos]; ok && p.goarch == "amd64" {
		return Check{
			ID:      "compatibility.platform",
			Status:  StatusPass,
			Summary: "This Linux/BSD amd64 machine is in the client audit target.",
		}
	}
	return Check{
		ID:       "compatibility.platform",
		Status:   StatusFail,
		Summary:  "This machine is outside the Linux/BSD amd64 alternatives-audit target.",
		Guidance: "Run this audit on Linux, FreeBSD, OpenBSD, NetBSD, or DragonFly BSD amd64.",
	}
}

func (p *Prober) wineCompatibilityCheck() Check {
	if command, ok := p.lookupAny("wine", "wine64", "crossover", "cxoffice", "bottles", "playonlinux"); ok {
		return Check{
			ID:       "compatibility.wine",
			Status:   StatusWarn,
			Summary:  "Wine or the Wine-compatible frontend " + command + " is present, but Riot states that this class of implementation cannot satisfy Vanguard requirements.",
			Guidance: "Do not treat Wine, CrossOver, Bottles, or PlayOnLinux as local League support; use the physical Windows remote route.",
		}
	}
	if app, ok := p.lookupFlatpakApp(map[string]string{
		"com.usebottles.bottles": "Bottles",
	}); ok {
		return Check{
			ID:       "compatibility.wine",
			Status:   StatusWarn,
			Summary:  "The Flatpak app " + app + " is present, but Riot states that this Wine-compatible implementation cannot satisfy Vanguard requirements.",
			Guidance: "Do not treat Flatpak Wine frontends as local League support; use the physical Windows remote route.",
		}
	}
	return Check{
		ID:       "compatibility.wine",
		Status:   StatusWarn,
		Summary:  "Wine and the common Wine-compatible frontends CrossOver, Bottles, and PlayOnLinux are not present; installing one would not satisfy Riot Vanguard requirements.",
		Guidance: "Do not gather or copy proprietary Riot DLLs or drivers; use an authorized physical Windows host.",
	}
}

func (p *Prober) protonCompatibilityCheck() Check {
	if command, ok := p.lookupAny("proton", "protontricks", "steam", "heroic", "umu-run", "umu"); ok {
		return Check{
			ID:       "compatibility.proton",
			Status:   StatusWarn,
			Summary:  "Proton, UMU, or the Proton-capable launcher " + command + " is present, but kernel-space anti-cheat support is not a supported League path.",
			Guidance: "Do not enable unsupported anti-cheat workarounds; use the physical Windows remote route.",
		}
	}
	if app, ok := p.lookupFlatpakApp(map[string]string{
		"com.valvesoftware.Steam":          "Steam",
		"com.heroicgameslauncher.hgl":      "Heroic",
		"com.github.Matoking.protontricks": "Protontricks",
	}); ok {
		return Check{
			ID:       "compatibility.proton",
			Status:   StatusWarn,
			Summary:  "The Flatpak app " + app + " is present, but kernel-space anti-cheat support is not a supported League path through Proton.",
			Guidance: "Do not enable unsupported anti-cheat workarounds; use the physical Windows remote route.",
		}
	}
	return Check{
		ID:       "compatibility.proton",
		Status:   StatusWarn,
		Summary:  "Proton, UMU, and common Proton-capable launchers are not present; installing one would not provide a supported Vanguard path.",
		Guidance: "Treat Proton as non-certifying until Riot publishes an authorized Linux/BSD path.",
	}
}

func (p *Prober) lutrisCompatibilityCheck() Check {
	if _, ok := p.lookupAny("lutris"); ok {
		return Check{
			ID:       "compatibility.lutris",
			Status:   StatusWarn,
			Summary:  "Lutris is present, but its Wine backend cannot satisfy Riot Vanguard requirements.",
			Guidance: "Do not use Lutris as evidence of local League support; use an authorized physical Windows host.",
		}
	}
	if app, ok := p.lookupFlatpakApp(map[string]string{
		"net.lutris.Lutris": "Lutris",
	}); ok {
		return Check{
			ID:       "compatibility.lutris",
			Status:   StatusWarn,
			Summary:  "The Flatpak app " + app + " is present, but its Wine backend cannot satisfy Riot Vanguard requirements.",
			Guidance: "Do not use Lutris as evidence of local League support; use an authorized physical Windows host.",
		}
	}
	return Check{
		ID:       "compatibility.lutris",
		Status:   StatusWarn,
		Summary:  "Lutris is not present; installing it would not provide a supported Vanguard path.",
		Guidance: "Keep local Linux/BSD gameplay blocked unless Riot authorizes a native anti-cheat integration.",
	}
}

func (p *Prober) virtualMachineCompatibilityCheck() Check {
	if command, ok := p.lookupAny(
		"docker", "podman", "qemu-system-x86_64", "wsl", "winboat", "libvirt",
		"libvirtd", "virsh", "virt-manager", "virt-install", "vboxmanage", "vmrun", "vmware", "bhyve",
	); ok {
		return Check{
			ID:       "compatibility.virtual-machine",
			Status:   StatusWarn,
			Summary:  "The virtual-machine or container launcher " + command + " is present, but it cannot turn a Windows guest into a Riot-approved physical host.",
			Guidance: "Dockur/QEMU/WSL remain VM or container paths; do not use them to bypass Vanguard or physical-host checks.",
		}
	}
	if app, ok := p.lookupFlatpakApp(map[string]string{
		"org.gnome.Boxes": "GNOME Boxes",
	}); ok {
		return Check{
			ID:       "compatibility.virtual-machine",
			Status:   StatusWarn,
			Summary:  "The Flatpak app " + app + " is present, but it launches virtual machines and cannot turn a Windows guest into a Riot-approved physical host.",
			Guidance: "Do not use a VM to bypass Vanguard or physical-host checks; use a directly owned physical Windows host.",
		}
	}
	return Check{
		ID:       "compatibility.virtual-machine",
		Status:   StatusWarn,
		Summary:  "No container or virtual-machine launcher was detected; adding one would remain non-certifying.",
		Guidance: "Use a directly owned physical Windows host for the supported remote route.",
	}
}

func (p *Prober) otherCompatibilityLayerCheck() Check {
	found := make([]string, 0, 2)
	for _, candidate := range []struct {
		name  string
		label string
	}{
		{name: "darling", label: "Darling"},
		{name: "waydroid", label: "Waydroid"},
	} {
		if _, ok := p.lookupAny(candidate.name); ok {
			found = append(found, candidate.label)
		}
	}
	if len(found) > 0 {
		return Check{
			ID:       "compatibility.other-layers",
			Status:   StatusWarn,
			Summary:  strings.Join(found, " and ") + " is present, but it is not an authorized Windows League/Vanguard runtime.",
			Guidance: "Darling and Waydroid are not substitutes for Riot's supported Windows or native macOS client; keep local Linux/BSD gameplay blocked.",
		}
	}
	return Check{
		ID:       "compatibility.other-layers",
		Status:   StatusWarn,
		Summary:  "Darling and Waydroid are not present; adding either would not provide a supported League/Vanguard route.",
		Guidance: "Use a directly owned physical Windows host or the experimental physical Mac handoff instead of an emulation or Android-container path.",
	}
}

func (p *Prober) nativeVanguardCompatibilityCheck() Check {
	return Check{
		ID:       "compatibility.native-vanguard",
		Status:   StatusFail,
		Summary:  "No authorized Linux/BSD Vanguard integration is available for local League gameplay.",
		Guidance: "Keep local gameplay blocked and collect evidence only from an authorized physical-host route.",
	}
}

// lookupFlatpakApp checks only fixed local installation roots and validated
// local environment roots. It never invokes Flatpak, enumerates remotes, or
// reads app metadata; an app directory is advisory evidence only.
func (p *Prober) lookupFlatpakApp(apps map[string]string) (string, bool) {
	paths := make([]string, 0, 5)
	for _, root := range []string{
		filepath.FromSlash("/var/lib/flatpak/app"),
		filepath.FromSlash("/usr/local/share/flatpak/app"),
		filepath.FromSlash("/usr/share/flatpak/app"),
	} {
		paths = append(paths, root)
	}
	if dataHome, ok := p.localEnvironmentRoot(p.envValue("XDG_DATA_HOME")); ok {
		paths = append(paths, filepath.Join(dataHome, "flatpak", "app"))
	}
	if home, ok := p.localEnvironmentRoot(p.envValue("HOME")); ok {
		paths = append(paths, filepath.Join(home, ".local", "share", "flatpak", "app"))
	}
	appIDs := make([]string, 0, len(apps))
	for appID := range apps {
		appIDs = append(appIDs, appID)
	}
	sort.Strings(appIDs)
	for _, appID := range appIDs {
		label := apps[appID]
		for _, root := range uniqueNonEmpty(paths) {
			if p.directoryExistsAny(filepath.Join(root, appID)) {
				return label, true
			}
		}
	}
	return "", false
}
