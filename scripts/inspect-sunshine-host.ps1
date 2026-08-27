[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ArtifactPath,

    [Parameter(Mandatory = $true)]
    [string]$LeagueBridgePath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedLeagueBridgeSha256,

    [switch]$ConsentToReadOnlyInspection,

    [switch]$Json
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$exitUsage = 2
$exitBlocked = 3

function Write-InspectionResult {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IDictionary]$Result
    )

    if ($Json) {
        $Result | ConvertTo-Json -Depth 8
        return
    }

    Write-Output ("Sunshine host inspection: {0}" -f $Result.inspection_status)
    if ($Result.Contains('failure_code')) {
        Write-Output ("Failure: {0}" -f $Result.failure_code)
    }
    if ($Result.Contains('artifact')) {
        Write-Output ("Artifact integrity: {0}" -f $Result.artifact.integrity_verified)
        Write-Output ("Authenticode: {0}" -f $Result.artifact.authenticode_status)
    }
    if ($Result.Contains('msi_inspection')) {
        $tables = $Result.msi_inspection.tables
        Write-Output ("MSI tables (read-only): Property={0}, CustomAction={1}, ServiceInstall={2}, ServiceControl={3}, Registry={4}, Environment={5}" -f
            $tables.Property.row_count,
            $tables.CustomAction.row_count,
            $tables.ServiceInstall.row_count,
            $tables.ServiceControl.row_count,
            $tables.Registry.row_count,
            $tables.Environment.row_count)
        Write-Output ("Custom-action review required: {0}" -f $Result.msi_inspection.custom_action_review_required)
        Write-Output ("Rollback actions are review-only: {0}" -f ($Result.msi_inspection.rollback_action_names -join ', '))
    }
    if ($Result.Contains('host_report')) {
        Write-Output ("Windows host preflight: {0}" -f $Result.host_report.status)
    }
    Write-Output 'This inspection never authorizes installation or launch.'
}

function Resolve-RegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Candidate,

        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    try {
        $resolved = @(Resolve-Path -LiteralPath $Candidate -ErrorAction Stop)
        if ($resolved.Count -ne 1) {
            throw [System.InvalidOperationException]::new($FailureCode)
        }
        $item = Get-Item -LiteralPath $resolved[0].ProviderPath -Force -ErrorAction Stop
    }
    catch {
        throw [System.InvalidOperationException]::new($FailureCode)
    }

    if (-not ($item -is [System.IO.FileInfo]) -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
        throw [System.InvalidOperationException]::new($FailureCode)
    }
    if ($item.FullName -cnotmatch '^[A-Za-z]:\\') {
        throw [System.InvalidOperationException]::new($FailureCode)
    }
    try {
        $root = [System.IO.Path]::GetPathRoot($item.FullName)
        $drive = [System.IO.DriveInfo]::new($root)
        if (-not $drive.IsReady -or $drive.DriveType -ne [System.IO.DriveType]::Fixed) {
            throw [System.InvalidOperationException]::new($FailureCode)
        }
    }
    catch {
        throw [System.InvalidOperationException]::new($FailureCode)
    }
    $ancestor = $item.Directory
    while ($null -ne $ancestor) {
        try {
            $ancestor = Get-Item -LiteralPath $ancestor.FullName -Force -ErrorAction Stop
        }
        catch {
            throw [System.InvalidOperationException]::new($FailureCode)
        }
        if (-not ($ancestor -is [System.IO.DirectoryInfo]) -or
            ($ancestor.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
            throw [System.InvalidOperationException]::new($FailureCode)
        }
        $ancestor = $ancestor.Parent
    }
    return $item
}

function Confirm-ReadLockedRegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileStream]$Stream,

        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    $revalidated = Resolve-RegularFile -Candidate $Path -FailureCode $FailureCode
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($revalidated.FullName, $Path) -or
        $revalidated.Length -ne $Stream.Length) {
        throw [System.InvalidOperationException]::new($FailureCode)
    }
    return $revalidated
}

function Open-ReadLockedRegularFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.FileInfo]$File,

        [Parameter(Mandatory = $true)]
        [string]$FailureCode
    )

    $stream = $null
    try {
        # FileShare.Read permits the Windows image loader and read-only
        # inspectors to reopen the file, while denying writes, deletion, and
        # path replacement until the caller disposes the stream.
        $stream = [System.IO.FileStream]::new(
            $File.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        [void](Confirm-ReadLockedRegularFile -Stream $stream -Path $File.FullName -FailureCode $FailureCode)
        return $stream
    }
    catch {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        throw [System.InvalidOperationException]::new($FailureCode)
    }
}

function Read-MsiTable {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Database,

        [Parameter(Mandatory = $true)]
        [System.Collections.Generic.HashSet[string]]$AvailableTables,

        [Parameter(Mandatory = $true)]
        [string]$TableName,

        [Parameter(Mandatory = $true)]
        [string[]]$Columns
    )

    if (-not $AvailableTables.Contains($TableName)) {
        return [pscustomobject][ordered]@{
            present = $false
            columns = $Columns
            row_count = 0
            rows = @()
        }
    }

    $view = $null
    try {
        $quotedColumns = @($Columns | ForEach-Object { "``$_``" }) -join ', '
        $query = "SELECT $quotedColumns FROM ``$TableName``"
        $view = $Database.OpenView($query)
        [void]$view.Execute()
        $rows = @()
        while ($null -ne ($record = $view.Fetch())) {
            if ($rows.Count -ge 256) {
                throw [System.InvalidOperationException]::new('msi-table-row-limit-exceeded')
            }
            $row = [ordered]@{}
            for ($index = 0; $index -lt $Columns.Count; $index++) {
                $value = [string]$record.StringData($index + 1)
                if ($value.Length -gt 2048) {
                    throw [System.InvalidOperationException]::new('msi-table-value-limit-exceeded')
                }
                $row[$Columns[$index]] = $value
            }
            $rows += [pscustomobject]$row
        }
        return [pscustomobject][ordered]@{
            present = $true
            columns = $Columns
            row_count = $rows.Count
            rows = $rows
        }
    }
    finally {
        if ($null -ne $view) {
            try { [void]$view.Close() } catch { }
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($view)
        }
    }
}

function Get-MsiTableInspection {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $installer = $null
    $database = $null
    $tableView = $null
    try {
        $installer = New-Object -ComObject WindowsInstaller.Installer
        $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))

        $availableTables = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::Ordinal)
        $tableView = $database.OpenView('SELECT `Name` FROM `_Tables`')
        [void]$tableView.Execute()
        while ($null -ne ($tableRecord = $tableView.Fetch())) {
            [void]$availableTables.Add([string]$tableRecord.StringData(1))
        }
        [void]$tableView.Close()
        [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($tableView)
        $tableView = $null

        $contracts = [ordered]@{
            Property = @('Property', 'Value')
            CustomAction = @('Action', 'Type', 'Source', 'Target')
            ServiceInstall = @('ServiceInstall', 'Name', 'DisplayName', 'ServiceType', 'StartType', 'ErrorControl', 'Arguments', 'Component_')
            ServiceControl = @('ServiceControl', 'Name', 'Event', 'Arguments', 'Wait', 'Component_')
            Registry = @('Registry', 'Root', 'Key', 'Name', 'Value', 'Component_')
            Environment = @('Environment', 'Name', 'Value', 'Component_')
        }
        $tables = [ordered]@{}
        foreach ($contract in $contracts.GetEnumerator()) {
            $tableResult = @(Read-MsiTable -Database $database -AvailableTables $availableTables -TableName $contract.Key -Columns $contract.Value)
            if ($tableResult.Count -ne 1) {
                throw [System.InvalidOperationException]::new('msi-table-inspection-failed')
            }
            $tables[$contract.Key] = $tableResult[0]
        }

        $customActionTable = $tables['CustomAction']
        $serviceInstallTable = $tables['ServiceInstall']
        $serviceControlTable = $tables['ServiceControl']
        $rollbackActions = @(
            $customActionTable.rows |
                Where-Object { $_.Action -match 'Uninstall|Rollback' } |
                ForEach-Object { $_.Action }
        )
        return [pscustomobject][ordered]@{
            database_open_mode = 'read-only'
            tables = $tables
            custom_action_review_required = ($customActionTable.row_count -gt 0)
            declarative_service_tables_present = ($serviceInstallTable.present -or $serviceControlTable.present)
            rollback_action_names = $rollbackActions
            rollback_requires_separate_user_authorization = $true
        }
    }
    catch {
        Write-Verbose $_.Exception.ToString()
        throw [System.InvalidOperationException]::new('msi-table-inspection-failed')
    }
    finally {
        if ($null -ne $tableView) {
            try { [void]$tableView.Close() } catch { }
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($tableView)
        }
        if ($null -ne $database) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($database)
        }
        if ($null -ne $installer) {
            [void][System.Runtime.InteropServices.Marshal]::FinalReleaseComObject($installer)
        }
    }
}

if (-not $ConsentToReadOnlyInspection) {
    $result = [ordered]@{
        schema_version = 1
        workflow = 'sunshine-physical-host-read-only-inspection'
        inspection_status = 'consent-required'
        failure_code = 'explicit-read-only-consent-required'
        inspection_only = $true
        installation_authorized = $false
        launch_authorized = $false
    }
    Write-InspectionResult -Result $result
    exit $exitUsage
}

$artifactStream = $null
$leagueBridgeStream = $null
$phase = 'platform-check'
try {
    if ($env:OS -cne 'Windows_NT') {
        throw [System.InvalidOperationException]::new('windows-amd64-required')
    }

    $phase = 'artifact-lock-read'
    $lockPath = Join-Path (Split-Path -Parent $PSScriptRoot) 'compatibility\sunshine-windows-amd64.lock.json'
    $lockFile = Resolve-RegularFile -Candidate $lockPath -FailureCode 'artifact-lock-unavailable'
    $lock = Get-Content -LiteralPath $lockFile.FullName -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($lock.schema_version -ne 1 -or
        $lock.project -cne 'LizardByte/Sunshine' -or
        $lock.platform -cne 'windows' -or
        $lock.architecture -cne 'amd64' -or
        $lock.recommended_asset.supported_by_inspector -ne $true -or
        $lock.recommended_asset.requires_authenticode -ne $true) {
        throw [System.InvalidOperationException]::new('artifact-lock-invalid')
    }

    $phase = 'artifact-open'
    $artifact = Resolve-RegularFile -Candidate $ArtifactPath -FailureCode 'artifact-unavailable'
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($artifact.Name, [string]$lock.recommended_asset.name)) {
        throw [System.InvalidOperationException]::new('artifact-name-mismatch')
    }
    $artifactStream = Open-ReadLockedRegularFile -File $artifact -FailureCode 'artifact-lock-failed'
    if ($artifactStream.Length -ne [int64]$lock.recommended_asset.size_bytes) {
        throw [System.InvalidOperationException]::new('artifact-size-mismatch')
    }

    $phase = 'artifact-hash'
    $artifactHash = (Get-FileHash -InputStream $artifactStream -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($artifactHash -cne [string]$lock.recommended_asset.sha256) {
        throw [System.InvalidOperationException]::new('artifact-sha256-mismatch')
    }

    $phase = 'artifact-signature'
    $artifact = Confirm-ReadLockedRegularFile -Stream $artifactStream -Path $artifact.FullName -FailureCode 'artifact-path-changed'
    $signature = Get-AuthenticodeSignature -LiteralPath $artifact.FullName
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid -or
        $null -eq $signature.SignerCertificate) {
        throw [System.InvalidOperationException]::new('artifact-authenticode-invalid')
    }

    $phase = 'msi-table-inspection'
    $artifact = Confirm-ReadLockedRegularFile -Stream $artifactStream -Path $artifact.FullName -FailureCode 'artifact-path-changed'
    $msiInspection = Get-MsiTableInspection -Path $artifact.FullName

    $phase = 'leaguebridge-open'
    $leagueBridge = Resolve-RegularFile -Candidate $LeagueBridgePath -FailureCode 'leaguebridge-unavailable'
    if (-not [System.StringComparer]::OrdinalIgnoreCase.Equals($leagueBridge.Name, 'leaguebridge.exe')) {
        throw [System.InvalidOperationException]::new('leaguebridge-name-mismatch')
    }
    if ($ExpectedLeagueBridgeSha256 -cnotmatch '^[a-f0-9]{64}$') {
        throw [System.InvalidOperationException]::new('leaguebridge-expected-sha256-invalid')
    }
    $leagueBridgeStream = Open-ReadLockedRegularFile -File $leagueBridge -FailureCode 'leaguebridge-lock-failed'
    $leagueBridgeHash = (Get-FileHash -InputStream $leagueBridgeStream -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($leagueBridgeHash -cne $ExpectedLeagueBridgeSha256) {
        throw [System.InvalidOperationException]::new('leaguebridge-sha256-mismatch')
    }

    $phase = 'leaguebridge-doctor'
    $leagueBridge = Confirm-ReadLockedRegularFile -Stream $leagueBridgeStream -Path $leagueBridge.FullName -FailureCode 'leaguebridge-path-changed'
    $doctorLines = @(& $leagueBridge.FullName doctor --profile windows-host --json 2>$null)
    $doctorExitCode = $LASTEXITCODE
    if ($doctorExitCode -notin @(0, $exitBlocked) -or $doctorLines.Count -eq 0) {
        throw [System.InvalidOperationException]::new('leaguebridge-doctor-failed')
    }
    $doctor = ($doctorLines -join [Environment]::NewLine) | ConvertFrom-Json
    if ($doctor.schema_version -ne 1 -or
        $doctor.command -cne 'doctor' -or
        $doctor.ok -ne $true -or
        $doctor.data.profile -cne 'windows-host' -or
        $doctor.data.os -cne 'windows' -or
        $doctor.data.architecture -cne 'amd64') {
        throw [System.InvalidOperationException]::new('leaguebridge-doctor-contract-invalid')
    }

    $requiredChecks = @('host.platform', 'host.physical-machine', 'host.hardware-requirements', 'host.windows-security', 'host.sunshine')
    $observedChecks = @($doctor.data.checks | ForEach-Object { $_.id })
    foreach ($requiredCheck in $requiredChecks) {
        if ($requiredCheck -cnotin $observedChecks) {
            throw [System.InvalidOperationException]::new('leaguebridge-doctor-contract-invalid')
        }
    }
    $platformChecks = @($doctor.data.checks | Where-Object { $_.id -ceq 'host.platform' })
    if ($platformChecks.Count -ne 1 -or $platformChecks[0].status -cne 'pass') {
        throw [System.InvalidOperationException]::new('windows-amd64-required')
    }

    $result = [ordered]@{
        schema_version = 1
        workflow = 'sunshine-physical-host-read-only-inspection'
        inspection_status = 'review-required'
        inspection_only = $true
        installation_authorized = $false
        launch_authorized = $false
        artifact = [ordered]@{
            project = $lock.project
            release_tag = $lock.release_tag
            name = $lock.recommended_asset.name
            size_bytes = [int64]$artifactStream.Length
            sha256 = $artifactHash
            integrity_verified = $true
            authenticode_status = [string]$signature.Status
            signer_subject = $signature.SignerCertificate.Subject
            signer_thumbprint = $signature.SignerCertificate.Thumbprint.ToLowerInvariant()
            official_metadata_source = $lock.official_metadata_source
            source_checked_at = $lock.source_checked_at
        }
        msi_inspection = $msiInspection
        leaguebridge = [ordered]@{
            sha256 = $leagueBridgeHash
            doctor_exit_code = $doctorExitCode
        }
        host_report = $doctor.data
        limitations = @(
            'Artifact integrity and a valid Windows signature do not authorize installation.',
            'MSI table rows are declarative metadata; custom actions can make additional changes and were not executed.',
            'The read-only host report does not prove physical hardware, active security state, or Riot support.',
            'No installer, service, firewall rule, streaming server, Riot software, or game was started or changed.'
        )
    }
    Write-InspectionResult -Result $result
    exit $exitBlocked
}
catch {
    Write-Verbose $_.Exception.ToString()
    $failureCode = if ($_.Exception.Message -match '^[a-z0-9-]+$') { $_.Exception.Message } else { "$phase-failed" }
    $result = [ordered]@{
        schema_version = 1
        workflow = 'sunshine-physical-host-read-only-inspection'
        inspection_status = 'blocked'
        failure_code = $failureCode
        inspection_only = $true
        installation_authorized = $false
        launch_authorized = $false
    }
    Write-InspectionResult -Result $result
    exit $exitBlocked
}
finally {
    if ($null -ne $leagueBridgeStream) {
        $leagueBridgeStream.Dispose()
    }
    if ($null -ne $artifactStream) {
        $artifactStream.Dispose()
    }
}
