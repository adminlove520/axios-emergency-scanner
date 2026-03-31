# axios Supply Chain Poisoning Emergency Scanner (v1.1.0)
# 支持 Windows (PowerShell)
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块

$ErrorActionPreference = 'SilentlyContinue'

$MALICIOUS_VERSIONS = @("1.14.1", "0.30.4")
$MALICIOUS_PACKAGE = "plain-crypto-js"
$MALICIOUS_DOMAINS = @("axios-updates.com", "npm-security.org", "registry-npmjs.com", "plain-crypto.io")

function Write-Header {
    param([string]$Title)
    Write-Host ""
    Write-Host "==================================================" -ForegroundColor Cyan
    Write-Host " 🛡️  $Title" -ForegroundColor Cyan
    Write-Host "==================================================" -ForegroundColor Cyan
}

function Write-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "[ $Title ]" -ForegroundColor Yellow
    Write-Host ("-" * 50)
}

function Test-NpmPackageVersion {
    param(
        [string]$PackageName,
        [string]$Version,
        [string]$Location
    )
    
    $cleanVersion = $Version -replace '^[\^~]',''
    $isMalicious = $MALICIOUS_VERSIONS -contains $cleanVersion
    
    $status = if ($isMalicious) { "❌ 发现投毒版本" } else { "✅ 安全" }
    $color = if ($isMalicious) { "Red" } else { "Green" }
    
    Write-Host "  $status  $PackageName@$Version" -ForegroundColor $color
    Write-Host "         位置: $Location" -ForegroundColor Gray
    
    return -not $isMalicious
}

function Invoke-ProjectCheck {
    param([string]$ScanPath)
    
    $pjFiles = Get-ChildItem -Path $ScanPath -Filter "package.json" -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch "node_modules" }
    
    foreach ($pjFile in $pjFiles) {
        Write-Host "`n  🔍 检查项目: $($pjFile.DirectoryName)" -ForegroundColor Cyan
        try {
            $pj_raw = Get-Content $pjFile.FullName -Raw
            $pj = $pj_raw | ConvertFrom-Json
            $deps = @()
            if ($pj.dependencies) { $deps += $pj.dependencies.PSObject.Properties }
            if ($pj.devDependencies) { $deps += $pj.devDependencies.PSObject.Properties }
            
            foreach ($dep in $deps) {
                if ($dep.Name -eq "axios") {
                    $null = Test-NpmPackageVersion -PackageName "axios" -Version $dep.Value -Location $pjFile.FullName
                }
                if ($dep.Name -eq $MALICIOUS_PACKAGE) {
                    Write-Host "  ❌ 严重风险: $MALICIOUS_PACKAGE 发现于 $($pjFile.FullName)" -ForegroundColor Red
                }
            }

            foreach ($domain in $MALICIOUS_DOMAINS) {
                if ($pj_raw -like "*$domain*") {
                    Write-Host "  ❌ 恶意指令: 在 $($pjFile.FullName) 中发现恶意域名 $domain" -ForegroundColor Red
                }
            }
        } catch {}

        $nmMalDir = Join-Path $pjFile.DirectoryName "node_modules\$MALICIOUS_PACKAGE"
        if (Test-Path $nmMalDir) {
            Write-Host "  ❌ 实体感染: $MALICIOUS_PACKAGE 发现于 node_modules" -ForegroundColor Red
            Write-Host "         Path: $nmMalDir" -ForegroundColor Red
        }
    }
}

# ========== 主程序 ==========
Clear-Host
Write-Header "axios 供应链投毒应急审计工具 (PowerShell)"
Write-Host "扫描时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host ""

# 1. 全局检查
Write-Section "1. NPM 全局包安全审计"
if (Get-Command npm -ErrorAction SilentlyContinue) {
    $globalAxios = npm list -g axios --depth=0 2>$null | Select-String "axios@"
    if ($globalAxios) {
        $ver = ($globalAxios -split "@")[-1].Trim()
        $null = Test-NpmPackageVersion -PackageName "axios" -Version $ver -Location "npm global"
    } else {
        Write-Host "  ✅ 未在全局发现 axios" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠️  npm 未安装" -ForegroundColor Yellow
}

# 2. RAT 检查
Write-Section "2. 系统恶意软件 (RAT) 留痕检查"
$foundRAT = $false
$artifacts = @(
    Join-Path $env:PROGRAMDATA "wt.exe",
    Join-Path $env:APPDATA "axios-security-check.exe",
    Join-Path $env:TEMP "axios_install.ps1"
)
foreach ($art in $artifacts) {
    if (Test-Path $art) {
        Write-Host "  ❌ 发现后门文件: $art" -ForegroundColor Red
        $foundRAT = $true
    }
}
if (-not $foundRAT) { Write-Host "  ✅ 未发现 Windows 系统下的已知 RAT 留痕" -ForegroundColor Green }

# 3. 网络配置 (Hosts)
Write-Section "3. 网络配置审计 (Hosts)"
$hostsFile = "C:\Windows\System32\drivers\etc\hosts"
$foundHosts = $false
if (Test-Path $hostsFile) {
    $hostsContent = Get-Content $hostsFile
    foreach ($domain in $MALICIOUS_DOMAINS) {
        if ($hostsContent -match $domain) {
            Write-Host "  ❌ Hosts 劫持: 发现恶意域名 $domain" -ForegroundColor Red
            $foundHosts = $true
        }
    }
}
if (-not $foundHosts) { Write-Host "  ✅ 系统 Hosts 文件未发现劫持" -ForegroundColor Green }

# 4. 本地项目检查
$ScanPath = if ($args[0]) { $args[0] } else { "." }
Write-Section "4. 本地项目递归审计: $(Resolve-Path $ScanPath)"
Invoke-ProjectCheck -ScanPath $ScanPath

Write-Header "审计汇总"
Write-Host "💡 建议: 如果发现问题，请参考 README_CN.md 中的处置建议。" -ForegroundColor Yellow
Write-Host "💡 提示: 推荐使用 'npm run scan' 以获得最完整的审计功能。" -ForegroundColor Cyan
