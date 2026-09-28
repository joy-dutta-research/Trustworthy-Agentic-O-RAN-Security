#Requires -Version 5.1
<#
.SYNOPSIS
Plan, create, or read an offline transfer VHDX for the isolated Ubuntu VM.
.DESCRIPTION
Default/-Plan is read-only. -Create formats ONLY a newly created fixed-path
1 GiB VHDX after repeated identity/size/RAW/not-system checks. It never accepts
an existing disk for initialization. -Collect mounts that recorded disk READ
ONLY and copies only checksum-verified returned ZIP pairs. Neither operation
attaches disks to VMs, changes networking, starts VMs, or deletes files.
#>
[CmdletBinding(DefaultParameterSetName = 'Plan', SupportsShouldProcess = $true)]
param(
    [Parameter(ParameterSetName = 'Plan')][switch]$Plan,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')][switch]$Create,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')][string]$SourceZip,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
    [ValidatePattern('^[0-9a-fA-F]{64}$')][string]$SourceSha256,
    [Parameter(Mandatory = $true, ParameterSetName = 'Create')]
    [switch]$ConfirmNewTransferDisk,
    [Parameter(Mandatory = $true, ParameterSetName = 'Collect')][switch]$Collect
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$transferRoot = Join-Path $repoRoot '.vm-local/transfer'
$vhdPath = Join-Path $transferRoot 'ORAN-TRANSFER.vhdx'
$receiptPath = Join-Path $transferRoot 'transfer_receipt.json'
$returnParent = Join-Path $repoRoot '.vm-local/returned'
$vmName = 'ORAN-Security-Lab'
$diskBytes = 1GB
$label = 'ORANXFER'

if (-not $Create -and -not $Collect) {
    [ordered]@{
        status = 'PLAN_ONLY_NO_CHANGES'
        vm_name = $vmName
        transfer_vhdx = $vhdPath
        disk_capacity_bytes = $diskBytes
        file_system = 'FAT32'
        volume_label = $label
        source_names_on_disk = @('SOURCE.zip', 'SOURCE.sha256', 'TRANSFER_ID.json')
        return_directory_on_disk = 'RETURN'
        host_return_directory = $returnParent
        constraints = @(
            'Explicit owner-approved elevated administrator is required.'
            'Target VM must be Off and have zero network adapters.'
            'Transfer disk must be detached from every VM and snapshot before host mounting.'
            'Create refuses any existing transfer directory or disk.'
            'Collect never formats; it mounts read-only and preserves all originals.'
            'Guest/host must never mount the disk simultaneously.'
        )
    } | ConvertTo-Json -Depth 4
    return
}

function Assert-NoReparseAncestor {
    param([Parameter(Mandatory = $true)][string]$Path)
    $candidate = [IO.Path]::GetFullPath($Path)
    while ($candidate) {
        if (Test-Path -LiteralPath $candidate) {
            $item = Get-Item -LiteralPath $candidate -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Refusing reparse-point path: $candidate"
            }
        }
        $parent = [IO.Directory]::GetParent($candidate)
        if ($null -eq $parent) { break }
        $candidate = $parent.FullName
    }
}

function Write-NewUtf8 {
    param([string]$Path, [string]$Text)
    $stream = New-Object IO.FileStream($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Copy-NewFile {
    param([string]$Source, [string]$Destination)
    # .NET's false flag refuses destination replacement.
    [IO.File]::Copy($Source, $Destination, $false)
}

function Assert-OfflineVMAndDetachedDisk {
    $target = @(Get-VM -ErrorAction Stop | Where-Object { $_.Name -ceq $vmName })
    if ($target.Count -ne 1 -or $target[0].State.ToString() -ne 'Off') {
        throw "Exactly one stopped ($vmName) VM is required. Shut Ubuntu down cleanly; do not force-stop it."
    }
    if (@(Get-VMNetworkAdapter -VM $target[0]).Count -ne 0) {
        throw 'Target VM must have zero network adapters before offline transfer.'
    }
    foreach ($vm in @(Get-VM -ErrorAction Stop)) {
        $drives = @(Get-VMHardDiskDrive -VM $vm)
        foreach ($snapshot in @(Get-VMSnapshot -VM $vm)) {
            $drives += @(Get-VMHardDiskDrive -VMSnapshot $snapshot)
        }
        foreach ($drive in $drives) {
            if ([string]::IsNullOrWhiteSpace($drive.Path)) { continue }
            $candidate = [IO.Path]::GetFullPath($drive.Path)
            $seen = @{}
            while ($candidate) {
                if ($candidate -ieq $vhdPath) {
                    throw "Transfer disk is still attached to VM/snapshot $($vm.Name). Detach only this transfer disk first."
                }
                if ($seen.ContainsKey($candidate) -or $seen.Count -ge 64) {
                    throw 'Cannot verify a VM disk parent chain safely.'
                }
                $seen[$candidate] = $true
                $ancestorVhd = Get-VHD -Path $candidate -ErrorAction Stop
                if ([string]::IsNullOrWhiteSpace($ancestorVhd.ParentPath)) { break }
                $candidate = [IO.Path]::GetFullPath($ancestorVhd.ParentPath)
            }
        }
    }
    if (Test-Path -LiteralPath $vhdPath) {
        if ((Get-VHD -Path $vhdPath).Attached) {
            throw 'Transfer VHDX is already mounted on the host. This script will not adopt an existing mount.'
        }
    }
}

function Get-VerifiedDisk {
    param([uint32]$Number, [string]$Identifier, [string]$DiskUniqueId)
    $vhd = Get-VHD -Path $vhdPath
    if (-not $vhd.Attached -or $vhd.DiskNumber -ne $Number -or
        $vhd.DiskIdentifier.ToString() -cne $Identifier -or
        $vhd.Size -ne $diskBytes -or $vhd.VhdType.ToString() -ne 'Dynamic' -or
        -not [string]::IsNullOrWhiteSpace($vhd.ParentPath)) {
        throw 'The mounted VHDX identity/number/type/capacity is not the recorded new transfer disk.'
    }
    $disk = Get-Disk -Number $Number
    if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne $diskBytes -or
        ($disk.BusType.ToString() -ne 'File Backed Virtual' -and $disk.BusType.ToString() -ne 'FileBackedVirtual')) {
        throw 'Refusing disk: it is not the expected non-system 1 GiB file-backed virtual disk.'
    }
    if ([string]::IsNullOrWhiteSpace($disk.UniqueId)) {
        throw 'Disk has no stable UniqueId; refusing to continue.'
    }
    if ($DiskUniqueId -and $disk.UniqueId -cne $DiskUniqueId) {
        throw 'Disk UniqueId changed unexpectedly; refusing to continue.'
    }
    return $disk
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
try {
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'An owner-approved elevated Windows administrator must run Create/Collect. No permission changes were made.'
    }
}
finally { $identity.Dispose() }
Import-Module Hyper-V -ErrorAction Stop
foreach ($path in @($transferRoot, $vhdPath, $receiptPath, $returnParent)) {
    Assert-NoReparseAncestor -Path $path
}
Assert-OfflineVMAndDetachedDisk

$mountedByThisRun = $false
try {
    if ($Create) {
        if (-not $ConfirmNewTransferDisk) { throw 'Explicit -ConfirmNewTransferDisk is required.' }
        if (Test-Path -LiteralPath $transferRoot) {
            throw 'Transfer directory already exists. No existing disk will be initialized, formatted, replaced, or deleted.'
        }
        $source = [IO.Path]::GetFullPath($SourceZip)
        Assert-NoReparseAncestor -Path $source
        if (-not (Test-Path -LiteralPath $source -PathType Leaf) -or
            [IO.Path]::GetExtension($source) -ine '.zip') { throw 'SourceZip must identify an existing ZIP file.' }
        $sourceItem = Get-Item -LiteralPath $source
        if ($sourceItem.Length -le 0 -or $sourceItem.Length -gt 256MB) {
            throw 'Source ZIP must be nonempty and at most 256 MiB; raw datasets/VM images do not belong in this transfer.'
        }
        $sourceHash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($sourceHash -cne $SourceSha256.ToLowerInvariant()) { throw 'Source ZIP checksum mismatch.' }
        if (-not $PSCmdlet.ShouldProcess($vhdPath, 'Create and format ONLY a NEW 1 GiB FAT32 transfer VHDX')) { return }
        New-Item -ItemType Directory -Path $transferRoot | Out-Null
        New-VHD -Path $vhdPath -Dynamic -SizeBytes $diskBytes | Out-Null
        $created = Get-VHD -Path $vhdPath
        $vhdIdentifier = $created.DiskIdentifier.ToString()
        if ($created.Attached -or $created.Size -ne $diskBytes -or
            $created.VhdType.ToString() -ne 'Dynamic') { throw 'New VHDX readback failed.' }
        $mounted = Mount-VHD -Path $vhdPath -NoDriveLetter -Passthru
        $mountedByThisRun = $true
        $diskNumber = [uint32]$mounted.DiskNumber
        $disk = Get-VerifiedDisk -Number $diskNumber -Identifier $vhdIdentifier -DiskUniqueId ''
        $diskUniqueId = $disk.UniqueId
        if ($disk.PartitionStyle.ToString() -ne 'RAW' -or $disk.NumberOfPartitions -ne 0 -or
            $disk.IsReadOnly -or $disk.IsOffline) { throw 'New transfer disk is not an online writable RAW empty disk.' }
        # Re-identify immediately before the only initialization operation.
        $disk = Get-VerifiedDisk -Number $diskNumber -Identifier $vhdIdentifier -DiskUniqueId $diskUniqueId
        if ($disk.PartitionStyle.ToString() -ne 'RAW' -or $disk.NumberOfPartitions -ne 0) { throw 'RAW disk state changed.' }
        Initialize-Disk -Number $diskNumber -PartitionStyle MBR | Out-Null
        $disk = Get-VerifiedDisk -Number $diskNumber -Identifier $vhdIdentifier -DiskUniqueId $diskUniqueId
        if ($disk.PartitionStyle.ToString() -ne 'MBR' -or $disk.NumberOfPartitions -ne 0) { throw 'Initialized disk readback failed.' }
        $partition = New-Partition -DiskNumber $diskNumber -UseMaximumSize -AssignDriveLetter
        $disk = Get-VerifiedDisk -Number $diskNumber -Identifier $vhdIdentifier -DiskUniqueId $diskUniqueId
        $parts = @(Get-Partition -DiskNumber $diskNumber)
        if ($parts.Count -ne 1 -or $partition.DiskNumber -ne $diskNumber -or
            $parts[0].PartitionNumber -ne $partition.PartitionNumber -or $partition.Size -gt $diskBytes -or
            $partition.IsBoot -or $partition.IsSystem) { throw 'New partition identity readback failed.' }
        $volume = Format-Volume -Partition $partition -FileSystem FAT32 -NewFileSystemLabel $label -Confirm:$false
        $disk = Get-VerifiedDisk -Number $diskNumber -Identifier $vhdIdentifier -DiskUniqueId $diskUniqueId
        $volume = Get-Volume -Partition (Get-Partition -DiskNumber $diskNumber -PartitionNumber $partition.PartitionNumber)
        if ($volume.FileSystem -ne 'FAT32' -or $volume.FileSystemLabel -cne $label -or -not $volume.DriveLetter) {
            throw 'Formatted volume failed filesystem/label/drive-letter readback.'
        }
        $volumeRoot = "$($volume.DriveLetter):\"
        $transferId = [Guid]::NewGuid().ToString()
        $manifest = [ordered]@{
            schema_version = 1
            transfer_id = $transferId
            vhd_identifier = $vhdIdentifier
            disk_unique_id = $disk.UniqueId
            disk_capacity_bytes = $diskBytes
            volume_label = $label
            source_sha256 = $sourceHash
            source_bytes = $sourceItem.Length
            created_at_utc = [DateTime]::UtcNow.ToString('o')
        }
        Copy-NewFile -Source $source -Destination (Join-Path $volumeRoot 'SOURCE.zip')
        if ((Get-FileHash -LiteralPath (Join-Path $volumeRoot 'SOURCE.zip') -Algorithm SHA256).Hash -ine $sourceHash) {
            throw 'Copied source checksum mismatch; disk preserved but not marked READY.'
        }
        Write-NewUtf8 -Path (Join-Path $volumeRoot 'SOURCE.sha256') -Text "$sourceHash  SOURCE.zip`n"
        Write-NewUtf8 -Path (Join-Path $volumeRoot 'TRANSFER_ID.json') -Text (($manifest | ConvertTo-Json -Depth 4) + "`n")
        New-Item -ItemType Directory -Path (Join-Path $volumeRoot 'RETURN') | Out-Null
        Dismount-VHD -Path $vhdPath
        $mountedByThisRun = $false
        if ((Get-VHD -Path $vhdPath).Attached) { throw 'Host dismount did not complete.' }
        Write-NewUtf8 -Path $receiptPath -Text (($manifest | ConvertTo-Json -Depth 4) + "`n")
        Write-Output "READY: host-detached transfer disk: $vhdPath"
        Write-Output "Record transfer ID for guest identity check: $transferId"
        Write-Output 'Attach this disk ONLY to the stopped isolated lab VM; see docs/HOME_VM_TRANSFER.md.'
    }
    else {
        if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) { throw 'Missing original transfer receipt; collection will not adopt an unverified disk.' }
        $receipt = Get-Content -LiteralPath $receiptPath -Raw | ConvertFrom-Json
        if ($receipt.schema_version -ne 1 -or $receipt.disk_capacity_bytes -ne $diskBytes -or
            $receipt.volume_label -cne $label) { throw 'Transfer receipt has unexpected schema/capacity/label.' }
        $before = Get-VHD -Path $vhdPath
        if ($before.DiskIdentifier.ToString() -cne $receipt.vhd_identifier -or
            $before.Size -ne $diskBytes) { throw 'Transfer VHDX no longer matches its creation receipt.' }
        if (-not $PSCmdlet.ShouldProcess($vhdPath, 'Mount recorded transfer disk READ ONLY and copy verified returned ZIP pairs')) { return }
        $mounted = Mount-VHD -Path $vhdPath -ReadOnly -Passthru
        $mountedByThisRun = $true
        $disk = Get-VerifiedDisk -Number ([uint32]$mounted.DiskNumber) -Identifier $receipt.vhd_identifier -DiskUniqueId $receipt.disk_unique_id
        if (-not $disk.IsReadOnly -or $disk.PartitionStyle.ToString() -ne 'MBR') { throw 'Collection requires the recorded MBR disk mounted read-only.' }
        $parts = @(Get-Partition -DiskNumber $disk.Number)
        if ($parts.Count -ne 1) { throw 'Transfer disk must contain exactly one partition.' }
        $volume = Get-Volume -Partition $parts[0]
        if ($volume.FileSystem -ne 'FAT32' -or $volume.FileSystemLabel -cne $label -or -not $volume.DriveLetter) {
            throw 'Expected FAT32 ORANXFER volume with an automatically assigned drive letter. No disk was modified.'
        }
        $volumeRoot = "$($volume.DriveLetter):\"
        $diskManifest = Get-Content -LiteralPath (Join-Path $volumeRoot 'TRANSFER_ID.json') -Raw | ConvertFrom-Json
        if ($diskManifest.transfer_id -cne $receipt.transfer_id -or
            $diskManifest.source_sha256 -cne $receipt.source_sha256 -or
            $diskManifest.vhd_identifier -cne $receipt.vhd_identifier) { throw 'Guest-visible transfer identity does not match the host receipt.' }
        $returnRoot = Join-Path $volumeRoot 'RETURN'
        $zipFiles = @(Get-ChildItem -LiteralPath $returnRoot -File | Where-Object { $_.Extension -ieq '.zip' })
        if ($zipFiles.Count -lt 1 -or $zipFiles.Count -gt 20) { throw 'Expected 1 to 20 returned ZIP files; none copied.' }
        [long]$total = 0
        $verified = @()
        foreach ($zip in $zipFiles) {
            if ($zip.Name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,150}\.zip$') { throw 'Unexpected result ZIP filename.' }
            $sidecar = $zip.FullName + '.sha256'
            if (-not (Test-Path -LiteralPath $sidecar -PathType Leaf) -or
                (Get-Item -LiteralPath $sidecar).Length -gt 512) { throw 'Missing or oversized result ZIP checksum sidecar.' }
            $line = (Get-Content -LiteralPath $sidecar -Raw).Trim()
            $expectedPattern = '^([a-fA-F0-9]{64})  ' + [regex]::Escape($zip.Name) + '$'
            if ($line -cnotmatch $expectedPattern) { throw 'Checksum file must contain exactly one SHA256, two spaces, and the ZIP basename.' }
            $expectedHash = $Matches[1].ToLowerInvariant()
            $total += $zip.Length
            if ($zip.Length -le 0 -or $total -gt 750MB) { throw 'Returned ZIPs must be nonempty and together no larger than 750 MiB.' }
            if ((Get-FileHash -LiteralPath $zip.FullName -Algorithm SHA256).Hash -ine $expectedHash) { throw 'Returned ZIP checksum mismatch; none copied.' }
            $verified += [pscustomobject]@{ path = $zip.FullName; name = $zip.Name; sha256 = $expectedHash; sidecar = $sidecar }
        }
        $runName = 'run_' + [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '_' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
        $destination = Join-Path $returnParent $runName
        Assert-NoReparseAncestor -Path $destination
        if (Test-Path -LiteralPath $destination) { throw 'Return destination already exists; nothing will be overwritten.' }
        New-Item -ItemType Directory -Path $destination | Out-Null
        foreach ($zip in $verified) {
            $copiedPath = Join-Path $destination $zip.name
            Copy-NewFile -Source $zip.path -Destination $copiedPath
            Copy-NewFile -Source $zip.sidecar -Destination ($copiedPath + '.sha256')
            if ((Get-FileHash -LiteralPath $copiedPath -Algorithm SHA256).Hash -ine $zip.sha256) { throw 'Copied result failed checksum verification; preserve partial return directory.' }
        }
        Write-NewUtf8 -Path (Join-Path $destination 'collection_receipt.json') -Text (([ordered]@{
            schema_version = 1
            status = 'COPIED_AND_SHA256_VERIFIED'
            transfer_id = $receipt.transfer_id
            collected_at_utc = [DateTime]::UtcNow.ToString('o')
            files = @($verified | Select-Object name, sha256)
        } | ConvertTo-Json -Depth 5) + "`n")
        Write-Output "Returned ZIP/checksum pairs copied to: $destination"
        Write-Output 'Upload the returned ZIP and matching SHA256, not the VM disk or private host receipt.'
    }
}
finally {
    if ($mountedByThisRun) {
        try { Dismount-VHD -Path $vhdPath -ErrorAction Stop }
        catch { Write-Warning 'Could not dismount the transfer VHDX. Do NOT attach it to a VM until an administrator confirms host dismount.' }
    }
}
