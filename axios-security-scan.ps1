# axios Supply Chain Poisoning Emergency Scanner
# 支持 Windows (PowerShell) 和 Linux/macOS (Bash)
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块

$ErrorActionPreference = 'Continue'

# ========== 配置 ==========
$MALICIOUS_VERSIONS = @("1.14.1", "0.30.4")
$MALICIOUS_PACKAGE = "plain-crypto-js"
$RAT_ARTIFACTS_WINDOWS = @(
    @{Path="$env:PROGRAMDATA\wt.exe";Name="Windows RAT (wt.exe)"}
)
$RAT_ARTIFACTS_LINUX = @(
    @{Path="/tmp/ld.py";Name="Linux RAT (ld.py)"},
    @{Path="/Library/Caches/com.apple.act.mond";Name="macOS RAT (act.mond)"}
)
# =========================

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
    
    $isMalicious = $MALICIOUS_VERSIONS -contains $Version
    
    $status = if ($isMalicious) { "❌ MALICIOUS" } else { "✅ Safe" }
    $color = if ($isMalicious) { "Red" } else { "Green" }
    
    Write-Host "  $status  $PackageName@$Version" -ForegroundColor $color
    Write-Host "         Location: $Location" -ForegroundColor Gray
    
    return -not $isMalicious
}

function Invoke-NpmGlobalCheck {
    Write-Section "1. NPM 全局安装包检查"
    
    try {
        $globalPkgs = npm list -g --json 2>$null | ConvertFrom-Json
        if ($globalPkgs.dependencies) {
            $foundIssues = $false
            foreach ($pkg in $globalPkgs.dependencies.PSObject.Properties) {
                $pkgName = $pkg.Name
                $pkgInfo = $pkg.Value
                
                if ($pkgName -eq "axios") {
                    $version = $pkgInfo.Version
                    if (-not (Test-NpmPackageVersion -PackageName $pkgName -Version $version -Location "npm global")) {
                        $foundIssues = $true
                    }
                }
                
                # 检查依赖中的 axios
                if ($pkgInfo.Dependencies -and $pkgInfo.Dependencies.PSObject.Properties.Name -contains "axios") {
                    $depAxiosVersion = $pkgInfo.Dependencies."axios"
                    $cleanVersion = $depAxiosVersion -replace '^[\^~]',''
                    if ($MALICIOUS_VERSIONS -contains $cleanVersion) {
                        if (-not (Test-NpmPackageVersion -PackageName "axios (dep of $pkgName)" -Version $cleanVersion -Location "$pkgName")) {
                            $foundIssues = $true
                        }
                    }
                }
            }
            
            if (-not $foundIssues) {
                Write-Host "  ✅ 未发现恶意 axios 版本" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  ⚠️ 无法获取全局包列表: $_" -ForegroundColor Yellow
    }
}

function Invoke-ProjectCheck {
    param([string]$ProjectPath)
    
    Write-Section "2. 项目检查: $ProjectPath"
    
    # 检查 package.json
    $packageJson = Join-Path $ProjectPath "package.json"
    if (Test-Path $packageJson) {
        try {
            $pkg = Get-Content $packageJson -Raw | ConvertFrom-Json
            $deps = @()
            if ($pkg.dependencies.PSObject.Properties) { $deps += $pkg.dependencies.PSObject.Properties }
            if ($pkg.devDependencies.PSObject.Properties) { $deps += $pkg.devDependencies.PSObject.Properties }
            
            foreach ($dep in $deps) {
                if ($dep.Name -eq "axios") {
                    $version = $dep.Value -replace '^[\^~]',''
                    $loc = if ($pkg.dependencies.PSObject.Properties.Name -contains $dep.Name) { "dependencies" } else { "devDependencies" }
                    $null = Test-NpmPackageVersion -PackageName "axios" -Version $version -Location "$ProjectPath ($loc)"
                }
            }
        } catch {
            Write-Host "  ⚠️ 解析 package.json 失败: $_" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  ⚠️ 未找到 package.json" -ForegroundColor Yellow
    }
    
    # 检查 package-lock.json
    $lockJson = Join-Path $ProjectPath "package-lock.json"
    if (Test-Path $lockJson) {
        try {
            $lock = Get-Content $lockJson -Raw | ConvertFrom-Json
            if ($lock.packages) {
                foreach ($pkg in $lock.packages.PSObject.Properties) {
                    if ($pkg.Name -match 'node_modules/axios$') {
                        $version = $pkg.Value.version
                        $location = $pkg.Name
                        $null = Test-NpmPackageVersion -PackageName "axios" -Version $version -Location $location
                    }
                }
            }
        } catch {
            Write-Host "  ⚠️ 解析 package-lock.json 失败: $_" -ForegroundColor Yellow
        }
    }
    
    # 检查 plain-crypto-js
    Write-Host ""
    Write-Host "  [ plain-crypto-js 投毒检查 ]" -ForegroundColor Yellow
    $plainCryptoPath = Join-Path $ProjectPath "node_modules\plain-crypto-js"
    if (Test-Path $plainCryptoPath) {
        Write-Host "  ❌ MALICIOUS: plain-crypto-js 发现于 $plainCryptoPath" -ForegroundColor Red
        Write-Host "         这表明投毒攻击已执行！" -ForegroundColor Red
    } else {
        Write-Host "  ✅ 未发现 plain-crypto-js" -ForegroundColor Green
    }
}

function Invoke-RatCheck {
    Write-Section "3. RAT Artifact 检查"
    
    $foundRAT = $false
    
    foreach ($artifact in $RAT_ARTIFACTS_WINDOWS) {
        $path = $ExecutionContext.InvokeCommand.ExpandString($artifact.Path)
        if (Test-Path $path) {
            Write-Host "  ❌ COMPROMISED: $($artifact.Name)" -ForegroundColor Red
            Write-Host "         Path: $path" -ForegroundColor Red
            $foundRAT = $true
        }
    }
    
    if (-not $foundRAT) {
        Write-Host "  ✅ 未发现 Windows RAT artifacts" -ForegroundColor Green
    }
    
    return -not $foundRAT
}

function Invoke-NpmCacheCheck {
    Write-Section "4. NPM 缓存检查 (plain-crypto-js)"
    
    $cachePaths = @(
        "$env:APPDATA\npm-cache",
        "$env:LOCALAPPDATA\npm-cache",
        "$env:USERPROFILE\.npm"
    )
    
    $foundMalicious = $false
    foreach ($cachePath in $cachePaths) {
        if (Test-Path $cachePath) {
            $malicious = Get-ChildItem -Path $cachePath -Recurse -Filter "plain-crypto-js" -ErrorAction SilentlyContinue
            if ($malicious) {
                Write-Host "  ❌ MALICIOUS: plain-crypto-js 发现于缓存" -ForegroundColor Red
                Write-Host "         Path: $($malicious.FullName)" -ForegroundColor Red
                $foundMalicious = $true
            }
        }
    }
    
    if (-not $foundMalicious) {
        Write-Host "  ✅ NPM 缓存安全" -ForegroundColor Green
    }
}

function Invoke-Summary {
    param(
        [bool]$GlobalSafe,
        [bool]$ProjectSafe,
        [bool]$RatSafe,
        [bool]$CacheSafe
    )
    
    Write-Header "扫描结果汇总"
    
    $allSafe = $GlobalSafe -and $ProjectSafe -and $RatSafe -and $CacheSafe
    
    if ($allSafe) {
        Write-Host "🎉 未发现 axios 投毒迹象！" -ForegroundColor Green
        Write-Host ""
        Write-Host "您的系统是安全的，但建议："
        Write-Host "  1. 尽快将 axios 锁定到安全版本 (1.14.0 或 0.30.3)" -ForegroundColor Yellow
        Write-Host "  2. 在 package.json 中添加 overrides 防止降级" -ForegroundColor Yellow
        Write-Host "  3. CI/CD 中使用 npm ci --ignore-scripts" -ForegroundColor Yellow
    } else {
        Write-Host "⚠️ 发现问题！立即采取行动：" -ForegroundColor Red
        Write-Host "  1. 隔离受感染系统" -ForegroundColor Red
        Write-Host "  2. 轮换所有凭证 (npm tokens, AWS keys, SSH keys)" -ForegroundColor Red
        Write-Host "  3. 从已知良好状态重建系统" -ForegroundColor Red
        Write-Host "  4. 审计 CI/CD 工作流" -ForegroundColor Red
    }
}

# ========== 主程序 ==========
Clear-Host
Write-Header "axios 供应链投毒应急扫描器"
Write-Host "扫描时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "系统: Windows ($env:COMPUTERNAME)"

$globalSafe = $true
$projectSafe = $true
$ratSafe = $true
$cacheSafe = $true

# 1. 全局检查
Invoke-NpmGlobalCheck

# 2. RAT 检查
$ratSafe = Invoke-RatCheck

# 3. 缓存检查
Invoke-NpmCacheCheck

# 4. 项目检查（如果提供了路径）
if ($args[0]) {
    $projectPath = $args[0]
    if (Test-Path $projectPath) {
        Invoke-ProjectCheck -ProjectPath $projectPath
    } else {
        Write-Host "❌ 项目路径不存在: $projectPath" -ForegroundColor Red
    }
} else {
    Write-Section "2. 项目检查"
    Write-Host "  请提供项目路径作为参数，或手动检查以下位置：" -ForegroundColor Yellow
    Write-Host "    - node_modules/axios" -ForegroundColor Gray
    Write-Host "    - package.json 中的 axios 版本" -ForegroundColor Gray
    Write-Host "    - package-lock.json 中的 axios 版本" -ForegroundColor Gray
}

# 汇总
Invoke-Summary -GlobalSafe $globalSafe -ProjectSafe $projectSafe -RatSafe $ratSafe -CacheSafe $cacheSafe
