package probe

import (
	"context"
	"strconv"
	"strings"
)

const (
	windowsVersionKey        = `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`
	windowsBIOSKey           = `HKLM\HARDWARE\DESCRIPTION\System\BIOS`
	windowsDirectXKey        = `HKLM\SOFTWARE\Microsoft\DirectX`
	windowsSecureBootKey     = `HKLM\SYSTEM\CurrentControlSet\Control\SecureBoot\State`
	windowsDeviceGuardKey    = `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard`
	windowsHVCIKey           = `HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity`
	imageFileMachineI386     = uint16(0x014c)
	imageFileMachineARMNT    = uint16(0x01c4)
	imageFileMachineAMD64    = uint16(0x8664)
	imageFileMachineARM64    = uint16(0xaa64)
	vanguardPreCheckGuidance = "Riot's optional Vanguard Pre-Check requires at least Windows 11 25H2 plus UEFI/Secure Boot, TPM 2.0, VBS/HVCI, and IOMMU; use Vanguard's own pre-check or VGTray to verify applicability and active state. Do not spoof or weaken security features."
)

type windowsProcedure interface {
	Find() error
	Query(process uintptr, processMachine, nativeMachine *uint16) bool
}

func queryNativeWindowsArchitecture(procedure windowsProcedure, process uintptr) (string, bool) {
	if procedure == nil || process == 0 {
		return "", false
	}
	// LazyProc.Call panics when the symbol is absent. Unsupported pre-1709
	// Windows must produce a bounded unknown result, not crash doctor.
	if err := procedure.Find(); err != nil {
		return "", false
	}
	var processMachine uint16
	var nativeMachine uint16
	if !procedure.Query(process, &processMachine, &nativeMachine) {
		return "", false
	}
	switch nativeMachine {
	case imageFileMachineAMD64:
		return "amd64", true
	case imageFileMachineARM64:
		return "arm64", true
	case imageFileMachineI386:
		return "386", true
	case imageFileMachineARMNT:
		return "arm", true
	default:
		return "", false
	}
}

// WindowsHost inspects a physical Windows streaming host. It only performs
// bounded registry queries, read-only SCM status checks, and file discovery.
func (p *Prober) WindowsHost(ctx context.Context) Report {
	if ctx == nil {
		ctx = context.Background()
	}
	checks := []Check{
		p.windowsPlatformCheck(),
		p.windowsVersionCheck(ctx),
		p.physicalHostCheck(ctx),
		p.directXCheck(ctx),
		p.hardwareRequirementsCheck(),
		p.windowsSecurityCheck(ctx),
		p.riotClientCheck(),
		p.leagueInstallCheck(),
		p.vanguardServiceCheck(ctx),
		p.sunshineCheck(ctx),
	}
	return p.report(ProfileWindowsHost, checks)
}

func (p *Prober) windowsPlatformCheck() Check {
	if p.goos != "windows" || p.goarch != "amd64" {
		return Check{
			ID:       "host.platform",
			Status:   StatusFail,
			Summary:  "The streaming host is not Windows on amd64.",
			Guidance: "Use a physical amd64 Windows client installation supported by Riot Games.",
		}
	}
	nativeArchitecture, known := p.platform.NativeArchitecture()
	if !known || nativeArchitecture != "amd64" {
		return Check{
			ID:       "host.platform",
			Status:   StatusFail,
			Summary:  "The streaming host native machine architecture is not verified as amd64.",
			Guidance: "Use a physical native-amd64 Windows client installation supported by Riot Games; x64 emulation on Windows Arm is outside this host contract.",
		}
	}
	return Check{ID: "host.platform", Status: StatusPass, Summary: "The streaming host process and native Windows machine are amd64."}
}

func (p *Prober) windowsVersionCheck(ctx context.Context) Check {
	product, productOK := p.registryValue(ctx, windowsVersionKey, "ProductName")
	installType, typeOK := p.registryValue(ctx, windowsVersionKey, "InstallationType")
	buildText, buildOK := p.registryValue(ctx, windowsVersionKey, "CurrentBuildNumber")
	if !buildOK {
		buildText, buildOK = p.registryValue(ctx, windowsVersionKey, "CurrentBuild")
	}
	build, parsedBuild := parseBuild(buildText)
	if !productOK || !typeOK || !buildOK || !parsedBuild {
		return Check{
			ID:       "host.windows-version",
			Status:   StatusFail,
			Summary:  "A supported retail Windows client installation could not be verified.",
			Guidance: "Use an up-to-date, non-Enterprise, non-Server Windows 11 installation supported by Riot Games and the pinned Sunshine release.",
		}
	}

	productLower := strings.ToLower(strings.TrimSpace(product))
	if !strings.EqualFold(strings.TrimSpace(installType), "Client") ||
		strings.Contains(productLower, "server") || strings.Contains(productLower, "enterprise") ||
		build < 22000 {
		return Check{
			ID:       "host.windows-version",
			Status:   StatusFail,
			Summary:  "This Windows edition or build is outside the host eligibility baseline.",
			Guidance: "Use an up-to-date, non-Enterprise, non-Server retail Windows 11 client installation supported by Riot Games and the pinned Sunshine release.",
		}
	}
	return Check{
		ID:       "host.windows-version",
		Status:   StatusPass,
		Summary:  "Registry data reports an eligible Windows client edition and build baseline; activation, servicing state, and authenticity are not verified.",
		Guidance: "Confirm Windows is activated and fully updated and remains supported by Riot before play.",
	}
}

func (p *Prober) directXCheck(ctx context.Context) Check {
	version, ok := p.registryValue(ctx, windowsDirectXKey, "Version")
	if !ok || !isDirectXRuntimeVersion(version) {
		return Check{
			ID:       "host.directx",
			Status:   StatusFail,
			Summary:  "A bounded DirectX runtime registration could not be verified.",
			Guidance: "Install supported Windows and graphics drivers through their publishers, then confirm Riot's current DirectX requirement locally.",
		}
	}
	return Check{
		ID:       "host.directx",
		Status:   StatusPass,
		Summary:  "A DirectX runtime registration was detected; this does not verify the GPU feature level or driver capability.",
		Guidance: "Confirm graphics compatibility against Riot's current requirements on the physical host.",
	}
}

func (p *Prober) hardwareRequirementsCheck() Check {
	return Check{
		ID:       "host.hardware-requirements",
		Status:   StatusWarn,
		Summary:  "CPU, GPU, memory, storage, and graphics-driver requirements remain unverified by this read-only probe.",
		Guidance: "Compare the physical host with Riot's current minimum requirements and complete a local Practice Tool session before streaming.",
	}
}

func (p *Prober) windowsSecurityCheck(ctx context.Context) Check {
	product, ok := p.registryValue(ctx, windowsVersionKey, "ProductName")
	buildText, buildOK := p.registryValue(ctx, windowsVersionKey, "CurrentBuildNumber")
	if !buildOK {
		buildText, buildOK = p.registryValue(ctx, windowsVersionKey, "CurrentBuild")
	}
	build, parsedBuild := parseBuild(buildText)
	if !ok && (!buildOK || !parsedBuild) {
		return Check{
			ID:       "host.windows-security",
			Status:   StatusWarn,
			Summary:  "TPM 2.0, Secure Boot, VBS/HVCI, and IOMMU applicability and active state could not be determined; this probe cannot establish optional Vanguard Pre-Check eligibility.",
			Guidance: vanguardPreCheckGuidance,
		}
	}

	windows11 := strings.Contains(strings.ToLower(product), "windows 11") || parsedBuild && build >= 22000
	if !windows11 {
		return Check{
			ID:       "host.windows-security",
			Status:   StatusWarn,
			Summary:  "This host is not identified as Windows 11; optional Vanguard Pre-Check requires at least Windows 11 25H2, while ordinary League host eligibility remains separately unverified.",
			Guidance: vanguardPreCheckGuidance,
		}
	}

	secureBoot, secureBootKnown := p.registryEnabled(ctx, windowsSecureBootKey, "UEFISecureBootEnabled")
	vbs, vbsKnown := p.registryEnabled(ctx, windowsDeviceGuardKey, "EnableVirtualizationBasedSecurity")
	hvci, hvciKnown := p.registryEnabled(ctx, windowsHVCIKey, "Enabled")
	if secureBootKnown && !secureBoot || vbsKnown && !vbs || hvciKnown && !hvci {
		return Check{
			ID:       "host.windows-security",
			Status:   StatusWarn,
			Summary:  "A Windows 11 Secure Boot, VBS, or HVCI configuration indicator is disabled; this may prevent optional Vanguard Pre-Check, while active state, TPM 2.0, and IOMMU remain unverified.",
			Guidance: vanguardPreCheckGuidance,
		}
	}
	if !secureBootKnown || !vbsKnown || !hvciKnown {
		return Check{
			ID:       "host.windows-security",
			Status:   StatusWarn,
			Summary:  "Windows 11 Secure Boot, VBS, or HVCI configuration could not be fully verified; optional Vanguard Pre-Check also requires at least Windows 11 25H2, and TPM 2.0 and IOMMU remain unverified.",
			Guidance: vanguardPreCheckGuidance,
		}
	}
	return Check{
		ID:       "host.windows-security",
		Status:   StatusWarn,
		Summary:  "Secure Boot, VBS, and HVCI are configured, but optional Vanguard Pre-Check also requires at least Windows 11 25H2 and runtime attestation; active state, TPM 2.0, and IOMMU remain unverified.",
		Guidance: vanguardPreCheckGuidance,
	}
}

func (p *Prober) registryEnabled(ctx context.Context, key, valueName string) (bool, bool) {
	value, ok := p.registryValue(ctx, key, valueName)
	if !ok {
		return false, false
	}
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "1", "0x1", "0x00000001":
		return true, true
	case "0", "0x0", "0x00000000":
		return false, true
	default:
		return false, false
	}
}

func isDirectXRuntimeVersion(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	parts := strings.Split(value, ".")
	if len(parts) != 4 {
		return false
	}
	numbers := make([]int, len(parts))
	for i, part := range parts {
		if part == "" {
			return false
		}
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return false
		}
		numbers[i] = number
	}
	return numbers[0] > 4 || numbers[0] == 4 && numbers[1] >= 9
}

func (p *Prober) physicalHostCheck(ctx context.Context) Check {
	values := make([]string, 0, 4)
	for _, name := range []string{"SystemManufacturer", "SystemProductName", "BaseBoardManufacturer", "BaseBoardProduct"} {
		if value, ok := p.registryValue(ctx, windowsBIOSKey, name); ok {
			values = append(values, value)
		}
	}

	for _, value := range values {
		if containsVMIndicator(value) {
			return Check{
				ID:       "host.physical-machine",
				Status:   StatusFail,
				Summary:  "An obvious virtual-machine firmware indicator was detected.",
				Guidance: "Riot Vanguard requires supported physical hardware; LeagueBridge will not hide virtualization.",
			}
		}
	}

	if root, ok := p.windowsRoot(); ok {
		guestDrivers := []string{
			"VBoxGuest.sys", "VBoxSF.sys", "vmmouse.sys", "vmhgfs.sys",
			"qemupciserial.sys", "xen.sys", "vioser.sys", "viostor.sys", "netkvm.sys",
		}
		paths := make([]string, 0, len(guestDrivers))
		for _, driver := range guestDrivers {
			paths = append(paths, targetPathJoin(p.goos, root, "System32", "drivers", driver))
		}
		if p.regularFileExistsAny(paths...) {
			return Check{
				ID:       "host.physical-machine",
				Status:   StatusWarn,
				Summary:  "A virtual-machine guest-driver file is present, but file-only evidence may be stale and does not prove active virtualization.",
				Guidance: "Manually confirm this is a physical retail Windows PC; do not delete evidence merely to change the probe result or conceal virtualization.",
			}
		}
	}

	if len(values) == 0 {
		return Check{
			ID:       "host.physical-machine",
			Status:   StatusWarn,
			Summary:  "Physical hardware could not be verified from firmware metadata.",
			Guidance: "Confirm this is a physical machine before attempting to use Riot Vanguard.",
		}
	}
	return Check{
		ID:       "host.physical-machine",
		Status:   StatusWarn,
		Summary:  "No obvious virtual-machine indicator was detected, but firmware metadata and a local driver scan that may use process environment do not prove retail physical hardware.",
		Guidance: "Manually confirm this is a physical retail Windows PC; do not alter, conceal, or spoof machine identity.",
	}
}

func (p *Prober) riotClientCheck() Check {
	if p.regularFileExistsAny(p.installCandidates(targetPathJoin(p.goos, "Riot Games", "Riot Client", "RiotClientServices.exe"))...) {
		return Check{ID: "host.riot-client", Status: StatusPass, Summary: "A regular Riot Client executable is present at a local path derived from process environment; signature and integrity are not verified."}
	}
	return Check{
		ID:       "host.riot-client",
		Status:   StatusFail,
		Summary:  "Riot Client was not detected in a standard installation location.",
		Guidance: "Install Riot Client directly from Riot Games on the Windows host.",
	}
}

func (p *Prober) leagueInstallCheck() Check {
	if p.regularFileExistsAny(p.installCandidates(targetPathJoin(p.goos, "Riot Games", "League of Legends", "LeagueClient.exe"))...) {
		return Check{ID: "host.league", Status: StatusPass, Summary: "A regular League executable is present at a local path derived from process environment; signature and integrity are not verified."}
	}
	return Check{
		ID:       "host.league",
		Status:   StatusFail,
		Summary:  "League of Legends was not detected in a standard installation location.",
		Guidance: "Install League of Legends through Riot Client on the Windows host.",
	}
}

func (p *Prober) vanguardServiceCheck(ctx context.Context) Check {
	kernel := p.serviceState(ctx, "vgk")
	userMode := p.serviceState(ctx, "vgc")
	if kernel == serviceUnavailable || userMode == serviceUnavailable {
		summary := "One or both required Riot Vanguard services were not detected."
		if p.regularFileExistsAny(p.installCandidates(targetPathJoin(p.goos, "Riot Vanguard", "installer.exe"))...) {
			summary = "The Riot Vanguard installer executable is present, but one or both required services were not detected; installer presence does not prove Vanguard is installed or running."
		}
		return Check{
			ID:       "host.vanguard-service",
			Status:   StatusFail,
			Summary:  summary,
			Guidance: "Repair Riot Vanguard through supported Riot software; do not download or copy standalone DLLs or drivers.",
		}
	}
	if kernel != serviceRunning || userMode != serviceRunning {
		return Check{
			ID:       "host.vanguard-service",
			Status:   StatusWarn,
			Summary:  "The Riot Vanguard services are registered, but the Windows Service Control Manager did not report both as running.",
			Guidance: "Start Riot software normally and follow Vanguard's own guidance; do not modify or bypass its services.",
		}
	}
	return Check{ID: "host.vanguard-service", Status: StatusPass, Summary: "The Windows Service Control Manager reports both Riot Vanguard services as registered and running."}
}

func (p *Prober) sunshineCheck(ctx context.Context) Check {
	if _, ok := p.lookupAny("sunshine.exe", "sunshine"); ok {
		return Check{ID: "host.sunshine", Status: StatusPass, Summary: "A Sunshine executable is discoverable on the Windows host."}
	}
	if p.regularFileExistsAny(p.installCandidates(targetPathJoin(p.goos, "Sunshine", "sunshine.exe"))...) ||
		p.regularFileExistsAny(p.installCandidates(targetPathJoin(p.goos, "LizardByte", "Sunshine", "sunshine.exe"))...) {
		return Check{ID: "host.sunshine", Status: StatusPass, Summary: "A regular Sunshine executable is present at a local path derived from process environment; signature and integrity are not verified."}
	}
	registeredService := false
	for _, name := range []string{"SunshineService", "sunshine"} {
		switch p.serviceState(ctx, name) {
		case serviceRunning:
			return Check{ID: "host.sunshine", Status: StatusPass, Summary: "The Windows Service Control Manager reports a Sunshine service as running."}
		case serviceRegistered:
			registeredService = true
		}
	}
	if registeredService {
		return Check{
			ID:       "host.sunshine",
			Status:   StatusWarn,
			Summary:  "A Sunshine service is registered, but the Windows Service Control Manager did not report it as running.",
			Guidance: "Start Sunshine through its supported Windows service or user-session configuration, then verify pairing and streaming from the client; LeagueBridge never starts or changes services.",
		}
	}
	return Check{
		ID:       "host.sunshine",
		Status:   StatusFail,
		Summary:  "Sunshine was not detected.",
		Guidance: "Install Sunshine from its official project and complete pairing directly in Sunshine and Moonlight.",
	}
}

func (p *Prober) registryValue(ctx context.Context, key, valueName string) (string, bool) {
	result, err := p.run(ctx, "reg.exe", "query", key, "/v", valueName)
	if err != nil || result.ExitCode != 0 || result.Truncated {
		return "", false
	}
	return parseRegistryValue(result.Output, valueName)
}

type observedServiceState uint8

const (
	serviceUnavailable observedServiceState = iota
	serviceRegistered
	serviceRunning
)

func (p *Prober) serviceState(ctx context.Context, name string) observedServiceState {
	if ctx != nil && ctx.Err() != nil {
		return serviceUnavailable
	}
	// Service Control Manager queries are synchronous, local, and read-only.
	registered, running, _ := p.services.Query(name)
	if !registered {
		return serviceUnavailable
	}
	if running {
		return serviceRunning
	}
	return serviceRegistered
}

func (p *Prober) serviceExists(ctx context.Context, name string) bool {
	return p.serviceState(ctx, name) != serviceUnavailable
}

func (p *Prober) windowsRoot() (string, bool) {
	if p.goos != "windows" {
		return "", false
	}
	if root, ok := p.localEnvironmentRoot(p.envValue("SystemRoot")); ok {
		return root, true
	}
	return p.localEnvironmentRoot("C:/Windows")
}

func (p *Prober) installCandidates(relative string) []string {
	roots := make([]string, 0, 3)
	for _, name := range []string{"ProgramFiles", "ProgramFiles(x86)"} {
		if root, ok := p.localEnvironmentRoot(p.envValue(name)); ok {
			roots = append(roots, root)
		}
	}
	if drive := strings.TrimSpace(p.envValue("SystemDrive")); len(drive) == 2 && isASCIILetter(drive[0]) && drive[1] == ':' {
		if root, ok := p.localEnvironmentRoot(drive + "/"); ok {
			roots = append(roots, root)
		}
	}
	paths := make([]string, 0, len(roots))
	for _, root := range uniqueNonEmpty(roots) {
		paths = append(paths, targetPathJoin(p.goos, root, relative))
	}
	return paths
}

func containsVMIndicator(value string) bool {
	normalized := strings.ToLower(strings.Join(strings.Fields(value), " "))
	for _, indicator := range []string{
		"bhyve", "bochs", "hvm domu", "hyper-v", "kvm", "parallels", "qemu",
		"virtual machine", "virtualbox", "vmware", "xen",
	} {
		if strings.Contains(normalized, indicator) {
			return true
		}
	}
	return false
}
