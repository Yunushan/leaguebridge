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
	RecommendedAsset       sunshineArtifact `json:"recommended_asset"`
	PortableReference      sunshineArtifact `json:"portable_reference"`
}

type sunshineArtifact struct {
	Name                 string `json:"name"`
	DownloadURL          string `json:"download_url"`
	SizeBytes            int64  `json:"size_bytes"`
	SHA256               string `json:"sha256"`
	RequiresAuthenticode bool   `json:"requires_authenticode"`
	SupportedByInspector bool   `json:"supported_by_inspector"`
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
	if lock.ReleaseTag != "v2026.516.143833" {
		t.Fatalf("unexpected Sunshine release tag %q", lock.ReleaseTag)
	}
	if parsed, err := time.Parse("2006-01-02", lock.SourceCheckedAt); err != nil || parsed.Format("2006-01-02") != "2026-08-29" {
		t.Fatalf("invalid source_checked_at: %v", err)
	}
	expectedReleaseURL := "https://github.com/LizardByte/Sunshine/releases/tag/" + lock.ReleaseTag
	expectedMetadataSource := "https://api.github.com/repos/LizardByte/Sunshine/releases/tags/" + lock.ReleaseTag
	if lock.ReleaseURL != expectedReleaseURL || lock.OfficialMetadataSource != expectedMetadataSource {
		t.Fatalf("Sunshine lock is not bound to the official release endpoints: %+v", lock)
	}

	sha256Pattern := regexp.MustCompile(`^[a-f0-9]{64}$`)
	for name, asset := range map[string]sunshineArtifact{
		"recommended": lock.RecommendedAsset,
		"portable":    lock.PortableReference,
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
		lock.RecommendedAsset.SizeBytes != 24465408 ||
		lock.RecommendedAsset.SHA256 != "e7208b11a4ab9dd89871133a054bbb8dc55dfbba408227b0eccab22c60b273a2" ||
		!lock.RecommendedAsset.RequiresAuthenticode || !lock.RecommendedAsset.SupportedByInspector {
		t.Fatalf("recommended Sunshine asset is not the signed MSI inspector contract: %+v", lock.RecommendedAsset)
	}
	if lock.PortableReference.Name != "Sunshine-Windows-AMD64-portable.zip" ||
		lock.PortableReference.SizeBytes != 26852145 ||
		lock.PortableReference.SHA256 != "0a3af3dde43b8f2c94ffe04b850ad736d6e1be2b75906779d7094a5ad9d4783b" ||
		lock.PortableReference.RequiresAuthenticode || lock.PortableReference.SupportedByInspector {
		t.Fatalf("portable Sunshine asset must remain a non-inspector reference: %+v", lock.PortableReference)
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
