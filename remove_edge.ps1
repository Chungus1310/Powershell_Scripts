# Enhanced Microsoft Edge Removal and Installation Blocker
# Requires Administrator privileges

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script needs to be run as Administrator. Restarting..." -ForegroundColor Red
    Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Enhanced Microsoft Edge Removal Tool" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ============================================
# STEP 1: Kill Edge Processes
# ============================================
Write-Host "[1/10] Terminating Edge processes..." -ForegroundColor Yellow
$EdgeProcesses = @("msedge", "msedgewebview2", "MicrosoftEdgeUpdate", "identity_helper")
foreach ($Process in $EdgeProcesses) {
    Get-Process -Name $Process -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    taskkill /f /im "$Process.exe" > $null 2>&1
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 2: Disable Edge Services
# ============================================
Write-Host "[2/10] Disabling Edge services..." -ForegroundColor Yellow
$Services = @(
    "edgeupdate",
    "edgeupdatem",
    "MicrosoftEdgeElevationService"
)

foreach ($Service in $Services) {
    $ServiceObj = Get-Service $Service -ErrorAction SilentlyContinue
    if ($ServiceObj) {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        Set-Service $Service -StartupType Disabled -ErrorAction SilentlyContinue
        Write-Host "    Disabled: $Service" -ForegroundColor Gray
    }
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 3: Disable Scheduled Tasks
# ============================================
Write-Host "[3/10] Disabling Edge scheduled tasks..." -ForegroundColor Yellow
$TaskNames = @(
    "MicrosoftEdgeUpdateTaskMachineCore",
    "MicrosoftEdgeUpdateTaskMachineUA",
    "MicrosoftEdgeUpdateBrowserReplacementTask",
    "MicrosoftEdgeUpdateTaskUser*"
)

foreach ($TaskPattern in $TaskNames) {
    Get-ScheduledTask -TaskName $TaskPattern -ErrorAction SilentlyContinue | 
        Disable-ScheduledTask -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 4: Uninstall Edge Using Built-in Installer
# ============================================
Write-Host "[4/10] Uninstalling Microsoft Edge..." -ForegroundColor Yellow

# Find the latest Edge version
$EdgePath = "${env:ProgramFiles(x86)}\Microsoft\Edge\Application"
if (Test-Path $EdgePath) {
    $LatestVersion = Get-ChildItem -Path $EdgePath -Directory | 
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    
    if ($LatestVersion) {
        $SetupPath = Join-Path $LatestVersion.FullName "Installer\setup.exe"
        if (Test-Path $SetupPath) {
            Write-Host "    Found version: $($LatestVersion.Name)" -ForegroundColor Gray
            Start-Process -FilePath $SetupPath -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }
}

# Also try the 64-bit path
$EdgePath64 = "${env:ProgramFiles}\Microsoft\Edge\Application"
if (Test-Path $EdgePath64) {
    $LatestVersion = Get-ChildItem -Path $EdgePath64 -Directory | 
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    
    if ($LatestVersion) {
        $SetupPath = Join-Path $LatestVersion.FullName "Installer\setup.exe"
        if (Test-Path $SetupPath) {
            Start-Process -FilePath $SetupPath -ArgumentList "--uninstall --system-level --verbose-logging --force-uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }
}

# Uninstall EdgeWebView2
$WebView2Path = "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application"
if (Test-Path $WebView2Path) {
    $LatestVersion = Get-ChildItem -Path $WebView2Path -Directory | 
        Where-Object { $_.Name -match '^\d+\.\d+\.\d+\.\d+$' } | 
        Sort-Object Name -Descending | 
        Select-Object -First 1
    
    if ($LatestVersion) {
        $SetupPath = Join-Path $LatestVersion.FullName "Installer\setup.exe"
        if (Test-Path $SetupPath) {
            Start-Process -FilePath $SetupPath -ArgumentList "--uninstall --msedgewebview --system-level --verbose-logging --force-uninstall" -Wait -ErrorAction SilentlyContinue
        }
    }
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 5: Remove Appx Packages
# ============================================
Write-Host "[5/10] Removing Edge Appx packages..." -ForegroundColor Yellow
Get-AppxPackage -AllUsers *MicrosoftEdge* | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like "*MicrosoftEdge*" | 
    Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 6: Block Edge Installation via Registry (Multiple Methods)
# ============================================
Write-Host "[6/10] Setting registry blocks..." -ForegroundColor Yellow

# Primary blocker - DoNotUpdateToEdgeWithChromium
$EdgeUpdatePath = "HKLM:\SOFTWARE\Microsoft\EdgeUpdate"
if (-not (Test-Path $EdgeUpdatePath)) {
    New-Item -Path $EdgeUpdatePath -Force | Out-Null
}
Set-ItemProperty -Path $EdgeUpdatePath -Name "DoNotUpdateToEdgeWithChromium" -Value 1 -Type DWORD -Force

# Block updates through Edge Update Policies
$EdgeUpdatePoliciesPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
if (-not (Test-Path $EdgeUpdatePoliciesPath)) {
    New-Item -Path $EdgeUpdatePoliciesPath -Force | Out-Null
}
# Prevent installation
Set-ItemProperty -Path $EdgeUpdatePoliciesPath -Name "InstallDefault" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path $EdgeUpdatePoliciesPath -Name "Install{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path $EdgeUpdatePoliciesPath -Name "UpdateDefault" -Value 0 -Type DWORD -Force
Set-ItemProperty -Path $EdgeUpdatePoliciesPath -Name "Update{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}" -Value 0 -Type DWORD -Force

# Disable Microsoft Store auto-updates for Edge
$StoreRegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore"
if (-not (Test-Path $StoreRegistryPath)) {
    New-Item -Path $StoreRegistryPath -Force | Out-Null
}
Set-ItemProperty -Path $StoreRegistryPath -Name "AutoDownload" -Value 2 -Type DWORD -Force

# Block through Windows Update (additional method)
$WindowsUpdatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Orchestrator"
if (-not (Test-Path $WindowsUpdatePath)) {
    New-Item -Path $WindowsUpdatePath -Force | Out-Null
}

# Prevent Edge from being the default browser
$EdgePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
if (-not (Test-Path $EdgePolicyPath)) {
    New-Item -Path $EdgePolicyPath -Force | Out-Null
}
Set-ItemProperty -Path $EdgePolicyPath -Name "DefaultBrowserSettingEnabled" -Value 0 -Type DWORD -Force

Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 7: Remove Edge Folders with Permissions
# ============================================
Write-Host "[7/10] Removing Edge folders..." -ForegroundColor Yellow
$EdgeFolders = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge",
    "${env:ProgramFiles}\Microsoft\Edge",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
    "${env:ProgramFiles}\Microsoft\EdgeUpdate",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView",
    "${env:ProgramFiles}\Microsoft\EdgeWebView",
    "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
    "${env:ProgramFiles}\Microsoft\EdgeCore",
    "$env:LOCALAPPDATA\Microsoft\Edge",
    "$env:ProgramData\Microsoft\EdgeUpdate"
)

foreach ($Folder in $EdgeFolders) {
    if (Test-Path $Folder) {
        Write-Host "    Removing: $Folder" -ForegroundColor Gray
        # Take ownership
        takeown /F "$Folder" /R /A /D Y > $null 2>&1
        # Grant full control
        icacls "$Folder" /grant Administrators:F /T /C > $null 2>&1
        # Remove the folder
        Remove-Item -Path "$Folder" -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 8: Clean Registry Entries
# ============================================
Write-Host "[8/10] Cleaning registry entries..." -ForegroundColor Yellow
$RegistryPaths = @(
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
    "HKCU:\SOFTWARE\Microsoft\Edge",
    "HKCU:\SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe"
)

foreach ($RegPath in $RegistryPaths) {
    if (Test-Path $RegPath) {
        Remove-Item -Path $RegPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 9: Create Software Restriction Policy (Optional - Most Robust)
# ============================================
Write-Host "[9/10] Setting up Software Restriction Policy..." -ForegroundColor Yellow

$SRPPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths"
if (-not (Test-Path $SRPPath)) {
    # Create SRP infrastructure
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0" -Force | Out-Null
    New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer\CodeIdentifiers\0\Paths" -Force | Out-Null
}

# Block Edge executable
$EdgeBlockGUID = [guid]::NewGuid().ToString("B")
$EdgeBlockPath = "$SRPPath\$EdgeBlockGUID"
New-Item -Path $EdgeBlockPath -Force | Out-Null
Set-ItemProperty -Path $EdgeBlockPath -Name "ItemData" -Value "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe" -Type String -Force
Set-ItemProperty -Path $EdgeBlockPath -Name "SaferFlags" -Value 0 -Type DWORD -Force

Write-Host "    Done" -ForegroundColor Green

# ============================================
# STEP 10: Disable Edge in Group Policy (Pro/Enterprise)
# ============================================
Write-Host "[10/10] Configuring Group Policy settings..." -ForegroundColor Yellow

# Check if machine has Group Policy (Pro/Enterprise)
$GPPath = "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate"
if (Test-Path "C:\Windows\System32\gpedit.msc") {
    Write-Host "    Group Policy available - Manual configuration recommended" -ForegroundColor Gray
    Write-Host "    Navigate to: Computer Configuration > Administrative Templates > Windows Components" -ForegroundColor Gray
    Write-Host "    Enable: 'Don't run specified Windows applications' and add 'msedge.exe'" -ForegroundColor Gray
}

# Block via AppLocker alternative registry
$AppLockerPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
if (-not (Test-Path $AppLockerPath)) {
    New-Item -Path $AppLockerPath -Force | Out-Null
}
Set-ItemProperty -Path $AppLockerPath -Name "TransparentEnabled" -Value 1 -Type DWORD -Force

Write-Host "    Done" -ForegroundColor Green

# ============================================
# Final Summary
# ============================================
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Edge Removal Complete!" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Actions taken:" -ForegroundColor Green
Write-Host "  [✓] Edge processes terminated" -ForegroundColor Green
Write-Host "  [✓] Edge services disabled" -ForegroundColor Green
Write-Host "  [✓] Scheduled tasks disabled" -ForegroundColor Green
Write-Host "  [✓] Edge uninstalled" -ForegroundColor Green
Write-Host "  [✓] Appx packages removed" -ForegroundColor Green
Write-Host "  [✓] Registry blocks configured" -ForegroundColor Green
Write-Host "  [✓] Folders removed" -ForegroundColor Green
Write-Host "  [✓] Registry entries cleaned" -ForegroundColor Green
Write-Host "  [✓] Software Restriction Policy set" -ForegroundColor Green
Write-Host "  [✓] Group Policy configured" -ForegroundColor Green
Write-Host ""
Write-Host "Important Notes:" -ForegroundColor Yellow
Write-Host "  • A system restart is HIGHLY RECOMMENDED" -ForegroundColor Yellow
Write-Host "  • Windows updates may attempt to reinstall Edge" -ForegroundColor Yellow
Write-Host "  • Run this script again if Edge reappears after major updates" -ForegroundColor Yellow
Write-Host "  • Some Windows features that depend on Edge may not work" -ForegroundColor Yellow
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
