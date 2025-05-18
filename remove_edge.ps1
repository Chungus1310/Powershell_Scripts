# Requires Administrator privileges
if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run as Administrator. Restarting..."
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Kill Edge processes
taskkill /f /im msedge.exe > $null 2>&1
taskkill /f /im msedgewebview2.exe > $null 2>&1

# Uninstall using Edge's own installer
$EdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe"
if (Test-Path $EdgePath) {
    $SetupPath = (Get-Item $EdgePath).FullName
    Start-Process -FilePath $SetupPath -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait
}

# Remove Appx packages
Get-AppxPackage -AllUsers *MicrosoftEdge* | Remove-AppxPackage -ErrorAction SilentlyContinue

# Block Edge installation through registry
$RegistryPath = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"
$Name = "DoNotUpdateToEdgeWithChromium"
$Value = 1
if (-not (Test-Path $RegistryPath)) {
    New-Item -Path $RegistryPath -Force | Out-Null
}
New-ItemProperty -Path $RegistryPath -Name $Name -Value $Value -PropertyType DWORD -Force | Out-Null

# Disable Microsoft Store auto-updates
$StoreRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
$AutoDownload = "AutoDownload"
if (-not (Test-Path $StoreRegistryPath)) {
    New-Item -Path $StoreRegistryPath -Force | Out-Null
}
New-ItemProperty -Path $StoreRegistryPath -Name $AutoDownload -Value 2 -PropertyType DWORD -Force | Out-Null

# Prevent reinstallation through Windows Update
$WindowsUpdatePath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
$TargetVersion = "TargetReleaseVersion"
$TargetVersionValue = 1
$TargetVersionInfo = "TargetReleaseVersionInfo"
$TargetVersionInfoValue = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").ReleaseId

if (-not (Test-Path $WindowsUpdatePath)) {
    New-Item -Path $WindowsUpdatePath -Force | Out-Null
}
New-ItemProperty -Path $WindowsUpdatePath -Name $TargetVersion -Value $TargetVersionValue -PropertyType DWORD -Force | Out-Null
New-ItemProperty -Path $WindowsUpdatePath -Name $TargetVersionInfo -Value $TargetVersionInfoValue -PropertyType String -Force | Out-Null

# Remove residual files
$EdgeFolders = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge",
    "${env:ProgramFiles}\Microsoft\Edge",
    "$env:LOCALAPPDATA\Microsoft\Edge"
)

foreach ($Folder in $EdgeFolders) {
    if (Test-Path $Folder) {
        Takeown /F $Folder /R /A /D Y > $null 2>&1
        icacls $Folder /grant Administrators:F /T /C > $null 2>&1
        Remove-Item $Folder -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# Disable Edge services
$Services = @(
    "edgeupdate",
    "edgeupdatem",
    "MicrosoftEdgeElevationService"
)

foreach ($Service in $Services) {
    if (Get-Service $Service -ErrorAction SilentlyContinue) {
        Stop-Service $Service -Force
        Set-Service $Service -StartupType Disabled
    }
}

Write-Host "Microsoft Edge has been removed and updates blocked. A system restart is recommended."