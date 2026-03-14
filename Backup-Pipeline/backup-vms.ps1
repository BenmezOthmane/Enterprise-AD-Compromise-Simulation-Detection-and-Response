# backup-vms.ps1
# VMware Snapshot Backup Script — SOC Lab
# Author: Othmane Benmezian

param(
    [string]$VCenter = "localhost",
    [string]$SnapshotName = "Pre-Attack-Backup",
    [string]$Description = "Post-Incident Clean State Snapshot"
)

$VMs = @("DC01", "WORKSTATION01", "SIEM01")
$Date = Get-Date -Format "yyyy-MM-dd_HH-mm"
$LogFile = "backup-log-$Date.txt"

function Write-Log {
    param([string]$Message, [string]$Color = "White")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogEntry = "[$Timestamp] $Message"
    Write-Host $LogEntry -ForegroundColor $Color
    Add-Content -Path $LogFile -Value $LogEntry
}

Write-Log "=== SOC Lab Backup Started ===" "Cyan"
Write-Log "Snapshot Name: $SnapshotName-$Date" "Cyan"

# Connect to VMware
try {
    Connect-VIServer -Server $VCenter -ErrorAction Stop
    Write-Log "Connected to VMware: $VCenter" "Green"
} catch {
    Write-Log "ERROR: Cannot connect to VMware — $($_.Exception.Message)" "Red"
    exit 1
}

# Take snapshots
$Success = 0
$Failed = 0

foreach ($VM in $VMs) {
    try {
        Write-Log "Taking snapshot for: $VM" "Yellow"
        
        New-Snapshot `
            -VM $VM `
            -Name "$SnapshotName-$Date" `
            -Description $Description `
            -Quiesce:$false `
            -Memory:$false `
            -ErrorAction Stop
        
        Write-Log "[OK] Snapshot created: $VM" "Green"
        $Success++

    } catch {
        Write-Log "[FAILED] $VM — $($_.Exception.Message)" "Red"
        $Failed++
    }
}

# Summary
Write-Log "=== Backup Summary ===" "Cyan"
Write-Log "Total VMs: $($VMs.Count)" "White"
Write-Log "Success:   $Success" "Green"
Write-Log "Failed:    $Failed" "Red"
Write-Log "Log saved: $LogFile" "White"

# Disconnect
Disconnect-VIServer -Server $VCenter -Confirm:$false
Write-Log "Disconnected from VMware" "Cyan"

if ($Failed -gt 0) {
    exit 1
} else {
    exit 0
}
