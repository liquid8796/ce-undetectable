# Build.ps1 - Cheat Engine Undetectable Build System
# Clones upstream CE, applies patches, builds, and post-processes
param(
    [switch]$Clean,
    [string]$LazarusPath = "",
    [string]$OutputName = "",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path $MyInvocation.MyCommand.Path -Parent
$SrcDir = Join-Path $RootDir "src"
$CeDir = Join-Path $RootDir "cheat-engine"
$CeProjectDir = Join-Path $CeDir "Cheat Engine"

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " CE Undetectable - Build System" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Root:     $RootDir"
Write-Host "Source:   $SrcDir"
Write-Host "Target:   $CeProjectDir"
Write-Host ""

# --- Step 1: Clone/fetch upstream Cheat Engine ---
$ceRepoUrl = "https://github.com/cheat-engine/cheat-engine.git"

if (-not (Test-Path (Join-Path $CeDir "Cheat Engine\cheatengine.lpi"))) {
    Write-Host "[...] Cloning upstream Cheat Engine..." -ForegroundColor Yellow
    if (Test-Path $CeDir) { Remove-Item -Recurse -Force $CeDir }
    git clone --depth 1 $ceRepoUrl $CeDir
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Failed to clone Cheat Engine" -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Upstream cloned" -ForegroundColor Green
}
else {
    Write-Host "[OK] Upstream Cheat Engine already present" -ForegroundColor Green
}

# --- Step 2: Find Lazarus ---
if ($LazarusPath) {
    $LazBuild = Join-Path $LazarusPath "lazbuild.exe"
}
else {
    $searchPaths = @(
        "C:\lazarus",
        "C:\Lazarus\lazarus",
        "${env:ProgramFiles}\Lazarus",
        "${env:ProgramFiles(x86)}\Lazarus"
    )
    $LazBuild = $null
    foreach ($p in $searchPaths) {
        $candidate = Join-Path $p "lazbuild.exe"
        if (Test-Path $candidate) { $LazBuild = $candidate; break }
    }
    if (-not $LazBuild) {
        $fromPath = (Get-Command "lazbuild.exe" -ErrorAction SilentlyContinue).Source
        if ($fromPath) { $LazBuild = $fromPath }
    }
}

if (-not $LazBuild -or -not (Test-Path $LazBuild)) {
    Write-Host "[ERROR] Lazarus not found. Install from https://www.lazarus-ide.org/ or use -LazarusPath" -ForegroundColor Red
    exit 1
}
Write-Host "[OK] Lazarus: $LazBuild" -ForegroundColor Green

# --- Step 3: Clean ---
if ($Clean) {
    Write-Host "[...] Cleaning..." -ForegroundColor Yellow
    $libDir = Join-Path $CeProjectDir "lib"
    $binDir = Join-Path $CeProjectDir "bin"
    if (Test-Path $libDir) { Remove-Item -Recurse -Force $libDir -ErrorAction SilentlyContinue }
    if (Test-Path $binDir) {
        Get-ChildItem $binDir -Filter "*.exe" | Remove-Item -Force -ErrorAction SilentlyContinue
    }
    Write-Host "[OK] Cleaned" -ForegroundColor Green
}

# --- Step 4: Apply patches ---
Write-Host "[...] Applying patches..." -ForegroundColor Yellow

# Copy new units
$newUnits = @("SyscallGateway.pas", "AntiCheatDetector.pas", "PhysicalMemory.pas", "KernelBridge.pas")
foreach ($unit in $newUnits) {
    $src = Join-Path $SrcDir $unit
    $dst = Join-Path $CeProjectDir $unit
    if (Test-Path $src) {
        Copy-Item $src $dst -Force
        Write-Host "  Copied: $unit"
    }
}

# Copy patched files
$patchedFiles = @("cheatengine.lpi", "cheatengine.lpr", "NewKernelHandler.pas")
foreach ($file in $patchedFiles) {
    $src = Join-Path $SrcDir $file
    $dst = Join-Path $CeProjectDir $file
    if (Test-Path $src) {
        Copy-Item $src $dst -Force
        Write-Host "  Patched: $file"
    }
}

# Copy PE patcher
$pePatcherSrc = Join-Path $SrcDir "PEPatcher.ps1"
$pePatcherDst = Join-Path $CeProjectDir "PEPatcher.ps1"
Copy-Item $pePatcherSrc $pePatcherDst -Force

Write-Host "[OK] Patches applied" -ForegroundColor Green

# --- Step 5: Randomize build identifiers ---
if (-not $SkipBuild) {
    Write-Host "[...] Randomizing build identifiers..." -ForegroundColor Yellow
    $BuildNr = Get-Random -Minimum 1000 -Maximum 99999

    $lpiFile = Join-Path $CeProjectDir "cheatengine.lpi"
    $lpiContent = Get-Content $lpiFile -Raw
    $lpiContent = $lpiContent -replace '<BuildNr Value="\d+"/>', "<BuildNr Value=""$BuildNr""/>"
    $lpiContent | Set-Content $lpiFile -NoNewline
    Write-Host "[OK] Build #$BuildNr" -ForegroundColor Green

    # --- Step 6: Build ---
    Write-Host "[...] Building Release 64-Bit with lazbuild..." -ForegroundColor Yellow
    Write-Host "  This may take a while (first build is slow)..." -ForegroundColor DarkGray

    $buildArgs = @(
        "--build-mode=Release 64-Bit",
        "--ws=win32",
        $lpiFile
    )

    Push-Location $CeProjectDir
    try {
        $buildResult = & $LazBuild @buildArgs 2>&1
        $buildExit = $LASTEXITCODE
    }
    finally {
        Pop-Location
    }

    if ($buildExit -ne 0) {
        Write-Host "[ERROR] Build failed (exit code: $buildExit)" -ForegroundColor Red
        if ($buildResult) { $buildResult | ForEach-Object { Write-Host "  $_" } }
        exit 1
    }
    Write-Host "[OK] Build successful" -ForegroundColor Green
}

# --- Step 7: Post-build PE mutation ---
Write-Host "[...] Applying PE mutations..." -ForegroundColor Yellow

$binDir = Join-Path $CeProjectDir "bin"
$exeToProcess = Get-ChildItem $binDir -Filter "*.exe" |
    Where-Object { $_.Length -gt 5MB } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1 -ExpandProperty FullName

if ($exeToProcess -and (Test-Path $exeToProcess)) {
    & $pePatcherDst -TargetExe $exeToProcess
}
else {
    Write-Host "[WARN] No built .exe found to patch" -ForegroundColor Yellow
}

# --- Summary ---
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
Write-Host "Tiers Loaded:" -ForegroundColor Cyan
Write-Host "  [T1] User-mode evasion: obfuscation + syscall gateway" -ForegroundColor Gray
Write-Host "  [T2] Kernel bridge: WinNotify.sys CR3 page table R/W + ObCallback bypass" -ForegroundColor Gray
Write-Host "  [PE] Rich Header stripped + sections renamed + timestamp randomized" -ForegroundColor Gray
Write-Host ""
Write-Host "T2 Activation requires WinNotify.sys / signeddrv.sys" -ForegroundColor Yellow
Write-Host "[T3] DMA hardware: documented but NOT IMPLEMENTED (future research)" -ForegroundColor DarkGray
