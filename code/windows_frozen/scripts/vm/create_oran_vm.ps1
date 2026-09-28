#Requires -Version 5.1
<#
.SYNOPSIS
Print an offline Ubuntu lab VM plan, or explicitly create a new stopped VM.
.DESCRIPTION
The default and -Plan modes are read-only and do not call Hyper-V cmdlets.
-Create requires an elevated administrator, verified installation media, and
unused VM/disk paths. This script never downloads software, enables features,
changes group membership or execution policy, starts a VM, or changes switches.
#>
[CmdletBinding(DefaultParameterSetName = 'Plan', SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'Plan')]
    [switch]$Plan,

    [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
    [switch]$Create
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$localRoot = Join-Path $repoRoot '.vm-local'
$mediaRoot = Join-Path $localRoot 'media'
$vmParent = Join-Path $localRoot 'vms'
$vmName = 'ORAN-Security-Lab'
$vmRoot = Join-Path $vmParent $vmName
$vhdPath = Join-Path $vmRoot 'ORAN-Security-Lab.vhdx'
$isoPath = Join-Path $mediaRoot 'ubuntu-24.04.5-live-server-amd64.iso'
$isoReceiptPath = $isoPath + '.verified.json'
$creationReceiptPath = Join-Path $vmRoot 'creation_receipt.json'
$expectedSha = '97f3d7ffb032c3eb3b23d2c8be9cc76e60c2c1f2c0146ba5ba9fe01cafae0fd8'
$expectedSigningKey = '843938DF228D22F7B3742BC0D94AA3F0EFE21092'
$secureBootTemplate = 'MicrosoftUEFICertificateAuthority'
$memoryBytes = 4GB
$diskBytes = 40GB
$processorCount = 4

$configuration = [ordered]@{
    vm_name = $vmName
    generation = 2
    memory_bytes = $memoryBytes
    dynamic_memory = $false
    processors = $processorCount
    disk_capacity_bytes = $diskBytes
    disk_type = 'Dynamic'
    vm_directory = $vmRoot
    disk_path = $vhdPath
    iso_path = $isoPath
    iso_sha256 = $expectedSha
    signing_key_fingerprint = $expectedSigningKey
    secure_boot = 'On'
    secure_boot_template = $secureBootTemplate
    network_adapters = 0
    automatic_start = 'Nothing'
    automatic_checkpoints = $false
    start_after_creation = $false
}

if (-not $Create) {
    [ordered]@{
        status = 'PLAN_ONLY_NO_CHANGES'
        configuration = $configuration
        prerequisites = @(
            'An owner or IT-approved elevated administrator must run -Create.'
            'Hyper-V must already be installed and running.'
            'The pinned ISO and its verified signature/SHA256 receipt must exist.'
            'The VM name and VM directory must not already exist.'
            'Offline installation and qualification remain manual/pending.'
        )
    } | ConvertTo-Json -Depth 5
    return
}

function Assert-NoReparseAncestor {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = [System.IO.Path]::GetFullPath($Path)
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing a reparse point in the lab artifact path: $candidate"
            }
        }
        $parent = [System.IO.Directory]::GetParent($candidate)
        if ($null -eq $parent) { break }
        $candidate = $parent.FullName
    }
}

function Write-CreationReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Status,
        [AllowNull()][string]$VMId,
        [AllowNull()][string]$ErrorType
    )
    [ordered]@{
        status = $Status
        recorded_at_utc = [DateTime]::UtcNow.ToString('o')
        vm_id = $VMId
        configuration = $configuration
        error_type = $ErrorType
        next_step = 'Owner-operated offline installation; guest qualification has not run.'
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $creationReceiptPath -Encoding UTF8
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Creation requires an elevated administrator approved by the owner or IT. No credentials should be entered in chat. No permission changes were made.'
    }
}
finally {
    $identity.Dispose()
}

foreach ($path in @($isoPath, $isoReceiptPath, $vmRoot)) {
    Assert-NoReparseAncestor -Path $path
}
if (-not (Test-Path -LiteralPath $isoPath -PathType Leaf)) {
    throw "Missing pinned ISO: $isoPath"
}
if (-not (Test-Path -LiteralPath $isoReceiptPath -PathType Leaf)) {
    throw "Missing verified ISO receipt: $isoReceiptPath"
}
$isoReceipt = Get-Content -LiteralPath $isoReceiptPath -Raw | ConvertFrom-Json
if ($isoReceipt.status -cne 'VERIFIED_SIGNATURE_AND_SHA256' -or
    $isoReceipt.iso_sha256 -ine $expectedSha -or
    (($isoReceipt.signing_key_fingerprint -replace '\s', '') -ine $expectedSigningKey)) {
    throw 'ISO verification receipt is missing the required status, SHA256 or signing key fingerprint.'
}
$actualSha = (Get-FileHash -LiteralPath $isoPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualSha -cne $expectedSha) {
    throw 'The ISO no longer matches the pinned SHA256. No VM was created.'
}
if (Test-Path -LiteralPath $vmRoot) {
    throw "Refusing to reuse any existing VM directory: $vmRoot"
}
if (Test-Path -LiteralPath $vhdPath) {
    throw "Refusing to reuse an existing VHDX: $vhdPath"
}

Import-Module Hyper-V -ErrorAction Stop
if ((Get-Service -Name vmms).Status -ne 'Running') {
    throw 'Hyper-V management service is not running. Ask the owner or IT; this script will not start services or enable features.'
}
$existing = @(Get-VM -ErrorAction Stop | Where-Object { $_.Name -ieq $vmName })
if ($existing.Count -ne 0) {
    throw "Refusing to modify or replace the existing VM named $vmName."
}
$os = Get-CimInstance -ClassName Win32_OperatingSystem
if (([uint64]$os.FreePhysicalMemory * 1KB) -lt 6GB) {
    throw 'At least 6 GiB of currently available host memory is required to reserve 4 GiB for this VM and leave headroom.'
}
$drive = New-Object System.IO.DriveInfo([System.IO.Path]::GetPathRoot($vmRoot))
if ($drive.AvailableFreeSpace -lt 50GB) {
    throw 'At least 50 GiB of free space is required for this 40 GiB lab disk and working headroom.'
}

if (-not $PSCmdlet.ShouldProcess($vmRoot, "Create new stopped, network-disconnected VM $vmName")) {
    return
}

$createdVM = $null
$createdDirectory = $false
try {
    # All creation is inside this new lab directory. No existing VM is adopted.
    if (-not (Test-Path -LiteralPath $vmParent)) {
        New-Item -ItemType Directory -Path $vmParent | Out-Null
    }
    New-Item -ItemType Directory -Path $vmRoot | Out-Null
    $createdDirectory = $true
    New-VHD -Path $vhdPath -Dynamic -SizeBytes $diskBytes | Out-Null
    $createdVM = New-VM -Name $vmName -Generation 2 -MemoryStartupBytes $memoryBytes -VHDPath $vhdPath -Path $vmRoot
    Set-VM -VM $createdVM -AutomaticStartAction Nothing -AutomaticCheckpointsEnabled $false
    Set-VMMemory -VM $createdVM -DynamicMemoryEnabled $false -StartupBytes $memoryBytes
    Set-VMProcessor -VM $createdVM -Count $processorCount

    # New-VM is given no switch. Remove its new disconnected NIC as defense in depth.
    foreach ($adapter in @(Get-VMNetworkAdapter -VM $createdVM)) {
        Remove-VMNetworkAdapter -VMNetworkAdapter $adapter -Confirm:$false
    }
    $dvd = Add-VMDvdDrive -VM $createdVM -Path $isoPath -Passthru
    Set-VMFirmware -VM $createdVM -EnableSecureBoot On -SecureBootTemplate $secureBootTemplate -FirstBootDevice $dvd

    # Read back the actual configuration before reporting successful preparation.
    $verifiedVM = Get-VM -Id $createdVM.Id
    $firmware = Get-VMFirmware -VM $verifiedVM
    $memory = Get-VMMemory -VM $verifiedVM
    $processor = Get-VMProcessor -VM $verifiedVM
    $disks = @(Get-VMHardDiskDrive -VM $verifiedVM)
    $disk = Get-VHD -Path $vhdPath
    $dvds = @(Get-VMDvdDrive -VM $verifiedVM)
    if ($verifiedVM.State.ToString() -ne 'Off' -or
        $verifiedVM.Generation -ne 2 -or
        $verifiedVM.AutomaticStartAction.ToString() -ne 'Nothing' -or
        $verifiedVM.AutomaticCheckpointsEnabled -ne $false -or
        $memory.DynamicMemoryEnabled -ne $false -or
        $memory.Startup -ne $memoryBytes -or
        $processor.Count -ne $processorCount -or
        @(Get-VMNetworkAdapter -VM $verifiedVM).Count -ne 0 -or
        $firmware.SecureBoot.ToString() -ne 'On' -or
        $firmware.SecureBootTemplate -ine $secureBootTemplate -or
        $disks.Count -ne 1 -or $disks[0].Path -ine $vhdPath -or
        $disk.VhdType.ToString() -ne 'Dynamic' -or $disk.Size -ne $diskBytes -or
        $dvds.Count -ne 1 -or $dvds[0].Path -ine $isoPath) {
        throw 'New VM configuration did not pass readback. It has not been started; inspect the preserved partial setup.'
    }
    Write-CreationReceipt -Status 'CREATED_STOPPED_OS_NOT_INSTALLED' -VMId $createdVM.Id.ToString() -ErrorType $null
    Write-Output "Created stopped VM $vmName. No operating system or experiment has run."
    Write-Output "Local receipt: $creationReceiptPath"
    Write-Output 'Next: the owner/administrator opens its console for offline installation; see docs/UBUNTU_VM_SETUP.md.'
}
catch {
    # Preserve partial evidence and the original exception. Never delete disks or
    # guess ownership after a failed call, and never start an incompletely set VM.
    $originalError = $_
    if ($createdDirectory) {
        try {
            $createdId = $null
            if ($null -ne $createdVM) { $createdId = $createdVM.Id.ToString() }
            Write-CreationReceipt -Status 'PARTIAL_FAILED_NOT_STARTED' -VMId $createdId -ErrorType $originalError.Exception.GetType().FullName
        }
        catch {
            Write-Warning 'The partial setup was preserved, but writing its receipt also failed.'
        }
    }
    throw $originalError
}
