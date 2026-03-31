# axios Supply Chain Poisoning Emergency Scanner
# 支持 Windows (PowerShell)
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块

$ErrorActionPreference = 'SilentlyContinue'

$MALICIOUS_VERSIONS = @("1.14.1", "0.30.4")
$MALICIOUS_PACKAGE = "plain-crypto-js"

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "[ $Title ]" -ForegroundColor Yellow
    Write-Host ("-" * 40)
}

function Test-NpmPackageVersion {
    param(
        [string]$PackageName,
        [string]$Version,
        [string]$Location
    )
    
    $cleanVersion = $Version -replace '^[\^~]',''
    $isMalicious = $MALICIOUS_VERSIONS -contains $cleanVersion
    
    $status = if ($isMalicious) { "❌ MALICIOUS" } else { "✅ Safe" }
    $color = if ($isMalicious) { "Red" } else { "Green" }
    
    Write-Host "  $status  $PackageName@$Version" -ForegroundColor $color
    Write-Host "         Location: $Location" -ForegroundColor Gray
    
    return -not $isMalicious
}

function Invoke-ProjectCheck {
    param([string]$ScanPath)
    
    $pjFiles = Get-ChildItem -Path $ScanPath -Filter "package.json" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch "node_modules" }
    
    foreach ($pjFile in $pjFiles) {
        Write-Host "`n  🔍 检查: $($pjFile.DirectoryName)" -ForegroundColor Cyan
        try {
            $pj = Get-Content $pjFile.FullName -Raw | ConvertFrom-Json
            $deps = @()
            if ($pj.dependencies) { $deps += $pj.dependencies.PSObject.Properties }
            if ($pj.devDependencies) { $deps += $pj.devDependencies.PSObject.Properties }
            
            foreach ($dep in $deps) {
                if ($dep.Name -eq "axios") {
                    $null = Test-NpmPackageVersion -PackageName "axios" -Version $dep.Value -Location $pjFile.FullName
                }
                if ($dep.Name -eq $MALICIOUS_PACKAGE) {
                    Write-Host "  ❌ MALICIOUS: $MALICIOUS_PACKAGE 发现于 $($pjFile.FullName)" -ForegroundColor Red
                }
            }
        } catch {}

        $nmMalDir = Join-Path $pjFile.DirectoryName "node_modules\$MALICIOUS_PACKAGE"
        if (Test-Path $nmMalDir) {
            Write-Host "  ❌ MALICIOUS: $MALICIOUS_PACKAGE 发现于 node_modules" -ForegroundColor Red
            Write-Host "         Path: $nmMalDir" -ForegroundColor Red
        }
    }
}

# ========== 主程序 ==========
Clear-Host
Write-Header "axios 供应链投毒应急扫描器"
Write-Host "扫描时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# 1. 全局检查
Write-Section "1. NPM 全局安装包检查"
if (Get-Command npm -ErrorAction SilentlyContinue) {
    $globalAxios = npm list -g axios --depth=0 2>$null | Select-String "axios@"
    if ($globalAxios) {
        $ver = ($globalAxios -split "@")[-1].Trim()
        $null = Test-NpmPackageVersion -PackageName "axios" -Version $ver -Location "npm global"
    } else {
        Write-Host "  ✅ 未在全局发现 axios" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠️ npm 未安装" -ForegroundColor Yellow
}

# 2. RAT 检查
Write-Section "2. RAT Artifact 检查"
$foundRAT = $false
$artifacts = @(
    Join-Path $env:PROGRAMDATA "wt.exe",
    Join-Path $env:APPDATA "axios-security-check.exe"
)
foreach ($art in $artifacts) {
    if (Test-Path $art) {
        Write-Host "  ❌ COMPROMISED: 发现恶意文件 $art" -ForegroundColor Red
        $foundRAT = $true
    }
}
if (-not $foundRAT) { Write-Host "  ✅ 未发现 Windows 系统下的已知 RAT artifacts" -ForegroundColor Green }

# 3. 项目检查
$ScanPath = if ($args[0]) { $args[0] } else { "." }
Write-Section "3. 项目检查 (递归): $(Resolve-Path $ScanPath)"
Invoke-ProjectCheck -ScanPath $ScanPath

Write-Header "扫描结束"
Write-Host "💡 建议: 如果发现问题，请立即隔离系统并更新 axios 到 1.14.0 或 0.30.3。" -ForegroundColor Yellow
Write-Host "💡 提示: 也可以使用 'npm run scan' 使用 Node.js 版扫描器。" -ForegroundColor Cyan
