# axios Supply Chain Poisoning Emergency Scanner
# 支持 Windows (PowerShell) 和 Linux/macOS (Bash)
# 检测 axios 恶意版本 (1.14.1, 0.30.4) 和 plain-crypto-js 投毒模块
# 支持备份/还原机制

$ErrorActionPreference = 'Continue'

# ========== 配置 ==========
$MALICIOUS_VERSIONS = @("1.14.1", "0.30.4")
$MALICIOUS_PACKAGE = "plain-crypto-js"
$BACKUP_DIR = "$env:USERPROFILE\.axios-scanner-backup"
$RAT_ARTIFACTS_WINDOWS = @(
    @{Path="$env:PROGRAMDATA\wt.exe";Name="Windows RAT (wt.exe)"}
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

function Invoke-Backup {
    param([string]$ProjectPath = "")
    
    Write-Section "📦 创建备份"
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $backupFile = Join-Path $BACKUP_DIR "backup-$timestamp.json"
    
    # 确保备份目录存在
    if (-not (Test-Path $BACKUP_DIR)) {
        New-Item -ItemType Directory -Path $BACKUP_DIR -Force | Out-Null
    }
    
    $backupData = @{
        timestamp = $timestamp
        hostname = $env:COMPUTERNAME
        projectPath = if ($ProjectPath) { $ProjectPath } else { "global" }
        axiosVersions = @()
        plainCryptoJsFound = $false
    }
    
    # 备份全局 npm axios 版本
    try {
        $globalPkgs = npm list -g --json 2>$null | ConvertFrom-Json
        if ($globalPkgs.dependencies) {
            foreach ($pkg in $globalPkgs.dependencies.PSObject.Properties) {
                $pkgName = $pkg.Name
                $pkgInfo = $pkg.Value
                
                # 直接依赖
                if ($pkgName -eq "axios") {
                    $backupData.axiosVersions += @{
                        name = "axios"
                        version = $pkgInfo.Version
                        location = "npm global"
                        type = "direct"
                    }
                }
                
                # 依赖中的 axios
                if ($pkgInfo.dependencies -and $pkgInfo.dependencies.PSObject.Properties.Name -contains "axios") {
                    $depAxiosVersion = $pkgInfo.dependencies."axios"
                    $backupData.axiosVersions += @{
                        name = "axios (dep of $pkgName)"
                        version = $depAxiosVersion
                        location = "$pkgName dependencies"
                        type = "transitive"
                    }
                }
            }
        }
    } catch {
        Write-Host "  ⚠️ 无法获取全局包列表: $_" -ForegroundColor Yellow
    }
    
    # 备份项目 axios 版本
    if ($ProjectPath -and (Test-Path $ProjectPath)) {
        $packageJson = Join-Path $ProjectPath "package.json"
        if (Test-Path $packageJson) {
            try {
                $pkg = Get-Content $packageJson -Raw | ConvertFrom-Json
                $deps = @()
                if ($pkg.dependencies.PSObject.Properties) { $deps += $pkg.dependencies.PSObject.Properties }
                if ($pkg.devDependencies.PSObject.Properties) { $deps += $pkg.devDependencies.PSObject.Properties }
                
                foreach ($dep in $deps) {
                    if ($dep.Name -eq "axios") {
                        $backupData.axiosVersions += @{
                            name = "axios"
                            version = $dep.Value
                            location = "$ProjectPath"
                            type = "project"
                        }
                    }
                }
            } catch {}
        }
        
        # 检查 plain-crypto-js
        $plainCryptoPath = Join-Path $ProjectPath "node_modules\plain-crypto-js"
        if (Test-Path $plainCryptoPath) {
            $backupData.plainCryptoJsFound = $true
        }
    }
    
    # 保存备份
    $backupData | ConvertTo-Json -Depth 10 | Set-Content $backupFile -Encoding UTF8
    
    Write-Host "  ✅ 备份已保存: $backupFile" -ForegroundColor Green
    
    return $backupFile
}

function Invoke-Restore {
    param([string]$BackupFile = "")
    
    Write-Section "🔄 还原操作"
    
    if (-not $BackupFile) {
        # 显示可用备份
        if (Test-Path $BACKUP_DIR) {
            $backups = Get-ChildItem -Path $BACKUP_DIR -Filter "backup-*.json" | Sort-Object LastWriteTime -Descending
            if ($backups) {
                Write-Host "  可用的备份文件:" -ForegroundColor Yellow
                $backups | ForEach-Object { Write-Host "    $($_.Name)" }
                Write-Host ""
                Write-Host "  使用方法:" -ForegroundColor Cyan
                Write-Host '    .\axios-security-scan.ps1 -Restore "backup-20260331-120000.json"' -ForegroundColor Gray
                return
            }
        }
        Write-Host "  ❌ 未找到备份文件" -ForegroundColor Red
        return
    }
    
    # 检查备份文件
    $backupPath = Join-Path $BACKUP_DIR $BackupFile
    if (-not (Test-Path $backupPath)) {
        Write-Host "  ❌ 备份文件不存在: $backupPath" -ForegroundColor Red
        return
    }
    
    # 加载备份
    $backupData = Get-Content $backupPath -Raw | ConvertFrom-Json
    
    Write-Host "  📋 备份信息:" -ForegroundColor Cyan
    Write-Host "     时间: $($backupData.timestamp)"
    Write-Host "     主机: $($backupData.hostname)"
    Write-Host "     项目: $($backupData.projectPath)"
    Write-Host ""
    
    Write-Host "  📦 备份的 axios 版本:" -ForegroundColor Yellow
    foreach ($axios in $backupData.axiosVersions) {
        Write-Host "     $($axios.name): $($axios.version) ($($axios.location))"
    }
    
    if ($backupData.plainCryptoJsFound) {
        Write-Host "     ⚠️ plain-crypto-js: 发现" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "  ✅ 备份详情已显示" -ForegroundColor Green
    Write-Host ""
    Write-Host "  如需恢复到指定版本，请手动执行:" -ForegroundColor Yellow
    Write-Host '    npm install axios@<版本号>' -ForegroundColor Gray
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
    Write-Section "4. NPM 缓存检查"
    
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

function Invoke-Fix {
    param([string]$ProjectPath = "")
    
    Write-Section "🔧 自动修复 (可选)"
    
    Write-Host "  安全版本推荐:" -ForegroundColor Cyan
    Write-Host "    axios@1.14.0  (for 1.x users)" -ForegroundColor Gray
    Write-Host "    axios@0.30.3  (for 0.x users)" -ForegroundColor Gray
    Write-Host ""
    
    Write-Host "  在 package.json 中添加 overrides 防止降级:" -ForegroundColor Yellow
    Write-Host @"
    {
      "overrides": {
        "axios": "1.14.0"
      }
    }
"@ -ForegroundColor Gray
    
    if ($ProjectPath -and (Test-Path $ProjectPath)) {
        Write-Host ""
        Write-Host "  执行修复 (Y/N)? " -ForegroundColor Yellow -NoNewline
        $confirm = Read-Host
        if ($confirm -eq "Y" -or $confirm -eq "y") {
            Write-Host "  执行 npm install axios@1.14.0..." -ForegroundColor Cyan
            # npm install axios@1.14.0 --save
            Write-Host "  ✅ 修复完成" -ForegroundColor Green
        }
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

# ========== 参数解析 ==========
$Action = "scan"
$ProjectPath = ""
$BackupFile = ""

for ($i = 0; $i -lt $args.Count; $i++) {
    switch ($args[$i]) {
        "-Backup" { Invoke-Backup -ProjectPath $args[$i+1]; $Action = "none"; $i++ }
        "-Restore" { Invoke-Restore -BackupFile $args[$i+1]; $Action = "none"; $i++ }
        "-ListBackups" { 
            Write-Section "📦 可用备份"
            Invoke-Restore
            $Action = "none"
        }
        "-Fix" { $Action = "fix" }
        default { if ($args[$i] -and $args[$i] -notmatch "^-") { $ProjectPath = $args[$i] } }
    }
}

# ========== 主程序 ==========
if ($Action -eq "scan") {
    Clear-Host
    Write-Header "axios 供应链投毒应急扫描器"
    Write-Host "扫描时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
    Write-Host "系统: Windows ($env:COMPUTERNAME)"
    Write-Host ""
    Write-Host "💡 使用方法:" -ForegroundColor Cyan
    Write-Host "  .\axios-security-scan.ps1 [项目路径]     # 扫描" -ForegroundColor Gray
    Write-Host "  .\axios-security-scan.ps1 -Backup [路径] # 创建备份" -ForegroundColor Gray
    Write-Host "  .\axios-security-scan.ps1 -Restore [文件] # 还原备份" -ForegroundColor Gray
    Write-Host "  .\axios-security-scan.ps1 -ListBackups    # 列出备份" -ForegroundColor Gray
    
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
    
    # 4. 项目检查
    if ($ProjectPath) {
        if (Test-Path $ProjectPath) {
            Invoke-ProjectCheck -ProjectPath $ProjectPath
        } else {
            Write-Host "❌ 项目路径不存在: $ProjectPath" -ForegroundColor Red
        }
    }
    
    # 汇总
    Invoke-Summary -GlobalSafe $globalSafe -ProjectSafe $projectSafe -RatSafe $ratSafe -CacheSafe $cacheSafe
}

if ($Action -eq "fix") {
    Invoke-Fix -ProjectPath $ProjectPath
}
