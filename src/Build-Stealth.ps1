# Build-Stealth.ps1 - Automated build script for Cheat Engine Stealth Edition
# Usage: .\Build-Stealth.ps1 [-Clean] [-SkipBuild] [-LazarusPath "C:\lazarus"]
param(
    [switch]$Clean,
    [switch]$SkipBuild,
    [string]$LazarusPath = "",
    [string]$ProjectDir = "",
    [string]$OutputName = ""
)

$ErrorActionPreference = "Stop"

# --- Config ---
if (-not $ProjectDir) {
    $ProjectDir = Split-Path $MyInvocation.MyCommand.Path -Parent
}
$LpiFile = Join-Path $ProjectDir "cheatengine.lpi"
$BinDir = Join-Path $ProjectDir "bin"

if (-not $OutputName) {
    # Generate random innocuous name
    $genericNames = @(
        "sysdiag", "cfgutil", "svchostutil", "winmgr", "perfmonctl",
        "diskchk", "netdiag", "wmictrl", "srvmon", "ipcfg"
    )
    $OutputName = $genericNames[(Get-Random -Maximum $genericNames.Count)]
}
$TargetExe = Join-Path $BinDir "$OutputName.exe"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CE Stealth Edition - Build System" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Project:  $ProjectDir"
Write-Host "Output:   $TargetExe"
Write-Host ""

# --- Step 1: Find Lazarus ---
if ($LazarusPath) {
    $LazBuild = Join-Path $LazarusPath "lazbuild.exe"
}
else {
    # Search common install locations
    $searchPaths = @(
        "C:\lazarus",
        "C:\Lazarus\lazarus",
        "${env:ProgramFiles}\Lazarus",
        "${env:ProgramFiles(x86)}\Lazarus",
        "${env:LOCALAPPDATA}\lazarus"
    )
    $LazBuild = $null
    foreach ($p in $searchPaths) {
        $candidate = Join-Path $p "lazbuild.exe"
        if (Test-Path $candidate) {
            $LazBuild = $candidate
            $LazarusPath = $p
            break
        }
    }

    if (-not $LazBuild) {
        # Also check PATH
        $fromPath = (Get-Command "lazbuild.exe" -ErrorAction SilentlyContinue).Source
        if ($fromPath) {
            $LazBuild = $fromPath
        }
    }
}

if (-not $LazBuild -or -not (Test-Path $LazBuild)) {
    Write-Host "[ERROR] Lazarus not found. Install Lazarus (https://www.lazarus-ide.org/) or specify -LazarusPath" -ForegroundColor Red
    Write-Host "  Common installers: lazarus-3.x-fpc-3.2.2-win64.exe" -ForegroundColor Yellow
    exit 1
}
Write-Host "[OK] Lazarus found: $LazBuild" -ForegroundColor Green

# --- Step 2: Clean ---
if ($Clean) {
    Write-Host "[...] Cleaning build artifacts..." -ForegroundColor Yellow
    $libDir = Join-Path $ProjectDir "lib"
    if (Test-Path $libDir) { Remove-Item -Recurse -Force $libDir -ErrorAction SilentlyContinue }
    if (Test-Path $BinDir) {
        Get-ChildItem $BinDir -Filter "*.exe" | Remove-Item -Force -ErrorAction SilentlyContinue
        Get-ChildItem $BinDir -Filter "*.dbg" | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[OK] Cleaned" -ForegroundColor Green
}

# --- Step 3: Randomize build-time identifiers ---
Write-Host "[...] Randomizing build identifiers..." -ForegroundColor Yellow

# Randomize the product version within a range
$BuildNr = Get-Random -Minimum 1000 -Maximum 99999
$MinorVersion = Get-Random -Minimum 0 -Maximum 9

# Update .lpi VersionInfo BuildNr
$lpiContent = Get-Content $LpiFile -Raw
$lpiContent = $lpiContent -replace '<BuildNr Value="\d+"/>', "<BuildNr Value=""$BuildNr""/>"
$lpiContent = $lpiContent -replace '<MinorVersionNr Value="\d+"/>', "<MinorVersionNr Value=""$MinorVersion""/>"
$lpiContent | Set-Content $LpiFile -NoNewline

Write-Host "[OK] Build version randomized: 7.$MinorVersion.$BuildNr" -ForegroundColor Green

# --- Step 4: Build ---
if (-not $SkipBuild) {
    Write-Host "[...] Building Release 64-Bit with lazbuild..." -ForegroundColor Yellow
    Write-Host "  This may take several minutes..." -ForegroundColor DarkGray

    # Build using the "Release 64-Bit" build mode (Item2)
    $buildArgs = @(
        "--build-mode=Release 64-Bit",
        "--ws=win32",
        $LpiFile
    )

    $buildResult = & $LazBuild @buildArgs 2>&1
    $buildExit = $LASTEXITCODE

    if ($buildExit -ne 0) {
        Write-Host "[ERROR] Build failed (exit code: $buildExit)" -ForegroundColor Red
        $buildResult | ForEach-Object { Write-Host "  $_" }
        exit 1
    }

    Write-Host "[OK] Build successful" -ForegroundColor Green
}

# --- Step 5: Post-build PE mutation ---
Write-Host "[...] Applying PE mutations..." -ForegroundColor Yellow

# Find the built exe (could be named differently)
$builtExes = @(
    (Join-Path $BinDir "sysdiag64.exe"),
    (Join-Path $BinDir "sysdiag64-x86_64-win64.exe"),
    (Join-Path $BinDir "sysdiag64.exe")
)

$exeToProcess = $null
foreach ($e in $builtExes) {
    if (Test-Path $e) { $exeToProcess = $e; break }
}
if (-not $exeToProcess) {
    # Fallback: find any .exe in bin/
    $exeToProcess = Get-ChildItem $BinDir -Filter "*.exe" -Recurse |
        Where-Object { $_.Length -gt 5MB } |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1 -ExpandProperty FullName
}

if ($exeToProcess -and (Test-Path $exeToProcess)) {
    $patcherScript = Join-Path $ProjectDir "PEPatcher.ps1"
    if (Test-Path $patcherScript) {
        Unblock-File -Path $patcherScript -ErrorAction SilentlyContinue
        & powershell -NoProfile -ExecutionPolicy Bypass -File $patcherScript -TargetExe $exeToProcess
    }
    else {
        Write-Host "[WARN] PEPatcher.ps1 not found, skipping PE mutation" -ForegroundColor Yellow
    }
}
else {
    Write-Host "[WARN] No .exe found to patch" -ForegroundColor Yellow
}

# --- Step 6: Summary ---
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Build Complete" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
if ($exeToProcess -and (Test-Path $exeToProcess)) {
    $size = (Get-Item $exeToProcess).Length / 1MB
    Write-Host "Output: $exeToProcess" -ForegroundColor White
    Write-Host "Size:   $([math]::Round($size, 1)) MB" -ForegroundColor White
}
Write-Host ""
Write-Host "Stealth features enabled:" -ForegroundColor Cyan
Write-Host "  [T1] Window title: 'Runtime Modifier' (via -daltname)" -ForegroundColor Gray
Write-Host "  [T1] Process name: generic (via .lpi metadata)" -ForegroundColor Gray
Write-Host "  [T1] PE metadata: stripped company/file descriptions" -ForegroundColor Gray
Write-Host "  [T1] Memory access: direct syscall bypass (no kernel32.dll)" -ForegroundColor Gray
Write-Host "  [T1] DBK driver: disabled, replaced with syscall gateway" -ForegroundColor Gray
Write-Host "  [T1] PE sections: renamed + Rich Header stripped" -ForegroundColor Gray
Write-Host "  [T1] Timestamp: randomized" -ForegroundColor Gray
Write-Host ""
Write-Host "  [T2] Anti-cheat detection: EAC/BE/Vanguard/Warden/XIGNCODE" -ForegroundColor Gray
Write-Host "  [T2] Kernel bridge: BYOVD physical memory R/W" -ForegroundColor Gray
Write-Host "  [T2] ObCallback bypass: disables EAC/BE handle filters" -ForegroundColor Gray
Write-Host "  [T2] Process hiding: PEB unlinking (if kernel bridge active)" -ForegroundColor Gray
Write-Host ""
Write-Host "T2 Activation:" -ForegroundColor Yellow
Write-Host "  - Place RTCore64.sys in C:\Windows\System32\drivers\" -ForegroundColor DarkGray
Write-Host "  - CE will auto-detect kernel anti-cheat and load driver" -ForegroundColor DarkGray
Write-Host "  - Without RTCore64.sys, T2 falls back to T1 syscall bypass" -ForegroundColor DarkGray
Write-Host ""
Write-Host "Coverage:" -ForegroundColor Cyan
Write-Host "  Warden, VAC, XIGNCODE     -> T1 (syscall bypass)" -ForegroundColor Green
Write-Host "  EAC, BattlEye, nProtect   -> T2 (kernel bridge + driver)" -ForegroundColor Yellow
Write-Host "  Vanguard, Faceit, ESEA    -> Limited (hypervisor AC)" -ForegroundColor Red
