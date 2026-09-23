package contracts

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

type sunshineArtifactLock struct {
	SchemaVersion          int              `json:"schema_version"`
	Project                string           `json:"project"`
	ReleaseTag             string           `json:"release_tag"`
	ReleaseURL             string           `json:"release_url"`
	OfficialMetadataSource string           `json:"official_metadata_source"`
	SourceCheckedAt        string           `json:"source_checked_at"`
	Platform               string           `json:"platform"`
	Architecture           string           `json:"architecture"`
	Stability              string           `json:"stability"`
	RecommendedAsset       sunshineArtifact `json:"recommended_asset"`
	StandaloneReference    sunshineArtifact `json:"standalone_reference"`
	DriverCompatibility    sunshineDriver   `json:"driver_compatibility"`
}

type sunshineArtifact struct {
	Name                 string `json:"name"`
	DownloadURL          string `json:"download_url"`
	SizeBytes            int64  `json:"size_bytes"`
	SHA256               string `json:"sha256"`
	RequiresAuthenticode bool   `json:"requires_authenticode"`
	SupportedByInspector bool   `json:"supported_by_inspector"`
}

type sunshineDriver struct {
	Project                      string           `json:"project"`
	ReleaseTag                   string           `json:"release_tag"`
	ReleaseURL                   string           `json:"release_url"`
	OfficialMetadataSource       string           `json:"official_metadata_source"`
	Stability                    string           `json:"stability"`
	RecommendedAsset             sunshineArtifact `json:"recommended_asset"`
	MinimumDriverRelease         string           `json:"minimum_driver_release"`
	ActiveMachineLicenseRequired bool             `json:"active_machine_license_required"`
}

func TestSunshineArtifactLockIsExactAndBounded(t *testing.T) {
	data, err := os.ReadFile(repositoryFile(t, "compatibility/sunshine-windows-amd64.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var lock sunshineArtifactLock
	if err := decoder.Decode(&lock); err != nil {
		t.Fatalf("decode Sunshine artifact lock: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("Sunshine artifact lock has trailing content: %v", err)
	}
	if lock.SchemaVersion != 1 || lock.Project != "LizardByte/Sunshine" || lock.Platform != "windows" || lock.Architecture != "amd64" {
		t.Fatalf("unexpected Sunshine artifact lock identity: %+v", lock)
	}
	if lock.ReleaseTag != "v2026.914.233613" || lock.Stability != "stable" {
		t.Fatalf("unexpected Sunshine release tag %q", lock.ReleaseTag)
	}
	if parsed, err := time.Parse("2006-01-02", lock.SourceCheckedAt); err != nil || parsed.Format("2006-01-02") != "2026-09-23" {
		t.Fatalf("invalid source_checked_at: %v", err)
	}
	expectedReleaseURL := "https://github.com/LizardByte/Sunshine/releases/tag/" + lock.ReleaseTag
	expectedMetadataSource := "https://github.com/LizardByte/Sunshine/releases/expanded_assets/" + lock.ReleaseTag
	if lock.ReleaseURL != expectedReleaseURL || lock.OfficialMetadataSource != expectedMetadataSource {
		t.Fatalf("Sunshine lock is not bound to the official release endpoints: %+v", lock)
	}

	sha256Pattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for name, asset := range map[string]sunshineArtifact{
		"recommended": lock.RecommendedAsset,
		"standalone":  lock.StandaloneReference,
	} {
		if asset.SizeBytes <= 0 || !sha256Pattern.MatchString(asset.SHA256) {
			t.Fatalf("%s Sunshine asset has invalid size or digest: %+v", name, asset)
		}
		expectedDownloadURL := "https://github.com/LizardByte/Sunshine/releases/download/" + lock.ReleaseTag + "/" + asset.Name
		if asset.DownloadURL != expectedDownloadURL {
			t.Fatalf("%s Sunshine asset URL = %q, want %q", name, asset.DownloadURL, expectedDownloadURL)
		}
	}
	if lock.RecommendedAsset.Name != "Sunshine-Windows-AMD64-installer.msi" ||
		lock.RecommendedAsset.SizeBytes != 33710080 ||
		lock.RecommendedAsset.SHA256 != "1d7fed8beecd5889dc7ff14cf9f42d6d38f37c3066c13c6c2a5f4e91847e0ccf" ||
		!lock.RecommendedAsset.RequiresAuthenticode || !lock.RecommendedAsset.SupportedByInspector {
		t.Fatalf("recommended Sunshine asset is not the signed MSI inspector contract: %+v", lock.RecommendedAsset)
	}
	if lock.StandaloneReference.Name != "Sunshine-Windows-AMD64-lite.zip" ||
		lock.StandaloneReference.SizeBytes != 38060196 ||
		lock.StandaloneReference.SHA256 != "233008e46f4c0e501a586cbfd6c4fd4a4c0d414a0b5fc7f13c070eb92ec3824b" ||
		lock.StandaloneReference.RequiresAuthenticode || lock.StandaloneReference.SupportedByInspector {
		t.Fatalf("standalone Sunshine asset must remain a non-inspector reference: %+v", lock.StandaloneReference)
	}
	driver := lock.DriverCompatibility
	if driver.Project != "LizardByte/libvirtualhid" || driver.ReleaseTag != "v2026.914.1218.10" ||
		driver.Stability != "stable" || driver.MinimumDriverRelease != driver.ReleaseTag ||
		!driver.ActiveMachineLicenseRequired {
		t.Fatalf("Sunshine driver compatibility is not the stable licensed pair: %+v", driver)
	}
	if driver.ReleaseURL != "https://github.com/LizardByte/libvirtualhid/releases/tag/"+driver.ReleaseTag ||
		driver.OfficialMetadataSource != "https://github.com/LizardByte/libvirtualhid/releases/expanded_assets/"+driver.ReleaseTag {
		t.Fatalf("driver lock is not bound to official release endpoints: %+v", driver)
	}
	if driver.RecommendedAsset.Name != "libvirtualhid-Windows-AMD64-driver-installer.msi" ||
		driver.RecommendedAsset.DownloadURL != "https://github.com/LizardByte/libvirtualhid/releases/download/"+driver.ReleaseTag+"/"+driver.RecommendedAsset.Name ||
		driver.RecommendedAsset.SizeBytes != 2772992 ||
		driver.RecommendedAsset.SHA256 != "bc31539a41f71939c13decb171ccbd4306fae1fed63273434a4f5ceccaf3e71c" ||
		!driver.RecommendedAsset.RequiresAuthenticode || driver.RecommendedAsset.SupportedByInspector {
		t.Fatalf("driver MSI is not the verified external reference: %+v", driver.RecommendedAsset)
	}
}

func TestRetiredSunshinePreviewLockCannotRecommendArtifacts(t *testing.T) {
	data, err := os.ReadFile(repositoryFile(t, "compatibility/sunshine-windows-amd64-raw-input-preview.lock.json"))
	if err != nil {
		t.Fatal(err)
	}
	var lock map[string]json.RawMessage
	if err := json.Unmarshal(data, &lock); err != nil {
		t.Fatalf("decode historical Sunshine preview lock: %v", err)
	}
	for field, want := range map[string]string{
		"release_tag":        "v2026.831.233010",
		"stability":          "prerelease",
		"status":             "retired",
		"retired_at":         "2026-09-23",
		"superseded_by_lock": "sunshine-windows-amd64.lock.json",
	} {
		var got string
		if err := json.Unmarshal(lock[field], &got); err != nil || got != want {
			t.Fatalf("historical Sunshine preview %s = %q, want %q: %v", field, got, want, err)
		}
	}
	if _, ok := lock["recommended_asset"]; ok {
		t.Fatal("retired Sunshine preview still recommends an artifact")
	}
	if _, ok := lock["requires_explicit_operator_acceptance"]; ok {
		t.Fatal("retired Sunshine preview still offers operator acceptance")
	}
	if _, ok := lock["historical_asset"]; !ok {
		t.Fatal("retired Sunshine preview lost its historical artifact record")
	}
	var pair map[string]json.RawMessage
	if err := json.Unmarshal(lock["historical_driver_pair"], &pair); err != nil {
		t.Fatalf("decode historical driver pair: %v", err)
	}
	if _, ok := pair["recommended_asset"]; ok {
		t.Fatal("retired Sunshine preview still recommends a driver")
	}
	if _, ok := pair["historical_asset"]; !ok {
		t.Fatal("retired Sunshine preview lost its historical driver record")
	}
}

func TestSunshineInspectorIsReadOnlyAndConsentGated(t *testing.T) {
	data, err := os.ReadFile(repositoryFile(t, "scripts/inspect-sunshine-host.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(data)
	consentGuard := strings.Index(source, "if (-not $ConsentToReadOnlyInspection)")
	if consentGuard < 0 {
		t.Fatal("Sunshine inspector has no explicit consent guard")
	}
	for _, operation := range []string{"Resolve-Path", "Get-FileHash", "Get-AuthenticodeSignature", "& $leagueBridge.FullName doctor --profile windows-host --json"} {
		position := strings.Index(source, operation)
		if position < 0 {
			t.Fatalf("Sunshine inspector is missing %q", operation)
		}
		if operation != "Resolve-Path" && position < consentGuard {
			t.Fatalf("Sunshine inspector performs %q before consent", operation)
		}
	}
	if position := strings.LastIndex(source, "Get-MsiTableInspection -Path"); position < consentGuard {
		t.Fatal("Sunshine inspector opens the MSI database before consent")
	}

	forbidden := regexp.MustCompile(`(?i)\b(?:msiexec|start-process|start-service|stop-service|new-service|remove-service|new-netfirewallrule|set-netfirewallrule|remove-netfirewallrule|set-itemproperty|new-itemproperty|remove-itemproperty|invoke-webrequest|invoke-restmethod)\b`)
	if match := forbidden.FindString(source); match != "" {
		t.Fatalf("Sunshine inspector contains forbidden mutating or network operation %q", match)
	}
	for _, required := range []string{
		"installation_authorized = $false",
		"launch_authorized = $false",
		"exit $exitBlocked",
		"artifact-authenticode-invalid",
		"artifact-sha256-mismatch",
		"leaguebridge-sha256-mismatch",
		"OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0)",
		"Property = @('Property', 'Value')",
		"CustomAction = @('Action', 'Type', 'Source', 'Target')",
		"ServiceInstall = @('ServiceInstall'",
		"ServiceControl = @('ServiceControl'",
		"Registry = @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component_')",
		"Environment = @('Environment', 'Name', 'Value', 'Component_')",
		"rollback_requires_separate_user_authorization = $true",
		"[System.IO.FileShare]::Read",
		"Get-FileHash -InputStream $artifactStream",
		"Get-FileHash -InputStream $leagueBridgeStream",
		"$leagueBridgeStream.Dispose()",
		"$artifactStream.Dispose()",
		"$item.FullName -cnotmatch '^[A-Za-z]:\\\\'",
		"[System.IO.DriveInfo]::new($root)",
		"$drive.DriveType -ne [System.IO.DriveType]::Fixed",
		"($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint)",
		"Confirm-ReadLockedRegularFile -Stream $leagueBridgeStream",
		"$platformChecks.Count -ne 1",
		"$platformChecks[0].status -cne 'pass'",
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("Sunshine inspector is missing safety contract %q", required)
		}
	}
	lockPosition := strings.Index(source, "$leagueBridgeStream = Open-ReadLockedRegularFile")
	hashPosition := strings.Index(source, "Get-FileHash -InputStream $leagueBridgeStream")
	doctorPosition := strings.Index(source, "& $leagueBridge.FullName doctor --profile windows-host --json")
	disposePosition := strings.LastIndex(source, "$leagueBridgeStream.Dispose()")
	if lockPosition < 0 || hashPosition < lockPosition || doctorPosition < hashPosition || disposePosition < doctorPosition {
		t.Fatal("Sunshine inspector does not hold the read lock from LeagueBridge hashing through doctor execution")
	}
}
