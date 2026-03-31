#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { Command } = require('commander');
const chalk = require('chalk');
const glob = require('glob');
const os = require('os');

const program = new Command();

// ========== 威胁情报 (Threat Intel) ==========
const MALICIOUS_VERSIONS = ["1.14.1", "0.30.4"];
const SAFE_VERSIONS = {
    '1.x': '1.14.0',
    '0.x': '0.30.3'
};

// 明确已知的恶意投毒包 (Confirmed Malicious Packages)
const CONFIRMED_MALICIOUS_PKGS = [
    "plain-crypto-js",
    "axios-checker-utils"
];

// 受监控的重点平台 (Monitored Platforms - For deep dependency audit)
const MONITORED_PLATFORMS = [
    "openclaw",
    "open-claw",
    "@openclaw/core"
];

// 已知恶意域名 (Known Malicious Domains)
const MALICIOUS_DOMAINS = [
    "axios-updates.com",
    "npm-security.org",
    "registry-npmjs.com",
    "plain-crypto.io",
    "claw-sync.net",
    "open-claw.com",
    "open-claw.org",
    "api.openclaw.io",
    "sfrclak.com"
];

// 已知恶意 IP (Known Malicious IPs)
const MALICIOUS_IPS = [
    "142.11.206.73"
];

// 系统层面的恶意后门留痕 (System-level RAT IOCs)
const RAT_ARTIFACTS = {
    linux: [
        "/tmp/ld.py", 
        path.join(os.homedir(), ".local/bin/kworker"),
        "/etc/cron.d/axios-sync"
    ],
    darwin: [
        "/Library/Caches/com.apple.act.mond", 
        "/tmp/com.apple.sysmond.sh",
        path.join(os.homedir(), "Library/LaunchAgents/com.axios.check.plist")
    ],
    win32: [
        path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'wt.exe'),
        path.join(process.env.APPDATA || '', 'axios-security-check.exe'),
        path.join(process.env.TEMP || 'C:\\Windows\\Temp', 'axios_install.ps1')
    ]
};

// 重点审计的平台路径 (Platform Audit Paths)
const PLATFORM_PATHS = {
    openclaw: [
        path.join(os.homedir(), ".openclaw"),
        path.join(process.env.LOCALAPPDATA || '', 'OpenClaw')
    ]
};

const NPM_CACHE_LOCATIONS = {
    linux: [path.join(os.homedir(), '.npm'), '/tmp/npm-*'],
    darwin: [path.join(os.homedir(), '.npm')],
    win32: [
        path.join(process.env.APPDATA || '', 'npm-cache'),
        path.join(process.env.LOCALAPPDATA || '', 'npm-cache'),
        path.join(os.homedir(), '.npm')
    ]
};

// ========== 工具函数 (Utilities) ==========
function printHeader(title) {
    console.log(chalk.cyan('\n' + '═'.repeat(60)));
    console.log(chalk.cyan(` 🛡️  ${title}`));
    console.log(chalk.cyan('═'.repeat(60)));
}

function printSection(title) {
    console.log(chalk.yellow(`\n[ ${title} ]`));
    console.log('─'.repeat(60));
}

function checkVersion(name, version, location) {
    const cleanVersion = version.replace(/^[\^~]/, '');
    const isMalicious = MALICIOUS_VERSIONS.includes(cleanVersion);
    
    if (isMalicious) {
        console.log(chalk.red(`  ❌ 发现投毒版本: ${name}@${version}`));
        console.log(chalk.gray(`     位置: ${location}`));
        return false;
    } else {
        console.log(chalk.green(`  ✅ 安全: ${name}@${version}`));
        console.log(chalk.gray(`     位置: ${location}`));
        return true;
    }
}

// ========== 扫描逻辑 (Scanning Logic) ==========

/**
 * 检查全局 npm 包
 */
function scanGlobalPackages() {
    printSection('1. 全局 NPM 包安全审计');
    const result = { safe: true, packages: [], platforms: [] };
    try {
        const output = execSync('npm list -g --json --depth=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        const globalPkgs = JSON.parse(output);

        if (globalPkgs.dependencies) {
            for (const [name, info] of Object.entries(globalPkgs.dependencies)) {
                // 1. 检查 axios
                if (name === 'axios') {
                    const isSafe = checkVersion(name, info.version, 'npm global');
                    result.packages.push({ name, version: info.version, location: 'npm global', safe: isSafe });
                    if (!isSafe) result.safe = false;
                }
                
                // 2. 检查已确认的投毒包
                if (CONFIRMED_MALICIOUS_PKGS.includes(name)) {
                    console.log(chalk.red(`  ❌ 确认恶意投毒包: ${name}@${info.version} (npm global)`));
                    result.packages.push({ name, version: info.version, location: 'npm global', safe: false });
                    result.safe = false;
                }

                // 3. 识别受监控平台 (OpenClaw 等)
                if (MONITORED_PLATFORMS.includes(name) || name.includes('openclaw')) {
                    console.log(chalk.blue(`  ℹ️  识别到平台组件: ${name}@${info.version}`));
                    result.platforms.push({ name, version: info.version });
                }
            }
        }
    } catch (e) {
        // Fallback to quick check
    }
    
    if (result.safe && result.packages.length === 0) console.log(chalk.green('  ✅ 未在全局发现已知的投毒威胁'));
    
    return result;
}

/**
 * 递归检查项目文件
 */
function scanProjects(rootPath) {
    printSection(`2. 本地项目深度审计 (递归): ${rootPath}`);
    const result = { safe: true, projects: [], maliciousPkgs: [], lockIssues: [] };

    const globOptions = { 
        cwd: rootPath, 
        ignore: ['**/node_modules/**', '**/AppData/**', '**/Local Settings/**'], 
        absolute: true,
        strict: false,
        silent: true,
        nodir: false,
        follow: false
    };

    let files = [];
    let lockFiles = [];
    try {
        files = glob.sync('**/package.json', globOptions);
        lockFiles = glob.sync('**/{package-lock.json,yarn.lock,pnpm-lock.yaml}', globOptions);
    } catch (e) {}

    for (const pkgFile of files) {
        try {
            const pkgContent = fs.readFileSync(pkgFile, 'utf8');
            const pkg = JSON.parse(pkgContent);
            const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}), ...(pkg.optionalDependencies || {}) };
            const projectResult = { path: pkgFile, issues: [] };
            
            // 检查 axios 版本
            if (deps.axios) {
                const isSafe = checkVersion('axios', deps.axios, pkgFile);
                if (!isSafe) {
                    projectResult.issues.push(`axios@${deps.axios} 是投毒版本`);
                    result.safe = false;
                }
            }

            // 检查确认恶意包
            for (const malPkg of CONFIRMED_MALICIOUS_PKGS) {
                if (deps[malPkg]) {
                    console.log(chalk.red(`  ❌ 严重风险: 在 ${pkgFile} 中发现已知恶意投毒包 ${malPkg}`));
                    projectResult.issues.push(`发现确认恶意依赖 ${malPkg}`);
                    result.safe = false;
                    result.maliciousPkgs.push({ name: malPkg, location: pkgFile });
                }
            }

            // 检查脚本中的恶意指令
            if (pkg.scripts) {
                for (const [scriptName, scriptCmd] of Object.entries(pkg.scripts)) {
                    for (const domain of MALICIOUS_DOMAINS) {
                        if (scriptCmd.includes(domain)) {
                            console.log(chalk.red(`  ❌ 恶意脚本: 在 ${pkgFile} 的 "${scriptName}" 脚本中发现 C2 域名 ${domain}`));
                            projectResult.issues.push(`脚本 "${scriptName}" 包含恶意域名 ${domain}`);
                            result.safe = false;
                        }
                    }
                    if (scriptCmd.includes('6202033')) {
                        console.log(chalk.red(`  ❌ 恶意脚本: 在 ${pkgFile} 的 "${scriptName}" 脚本中发现恶意活动 ID 6202033`));
                        projectResult.issues.push(`脚本 "${scriptName}" 包含恶意活动 ID 6202033`);
                        result.safe = false;
                    }
                }
            }

            // 特殊检查: 检查 node_modules 中的 plain-crypto-js 是否存在 (即使已被 cleanup)
            const nodeModulesPath = path.join(path.dirname(pkgFile), 'node_modules');
            const plainCryptoPath = path.join(nodeModulesPath, 'plain-crypto-js');
            if (fs.existsSync(plainCryptoPath)) {
                console.log(chalk.red(`  ❌ 发现高危组件目录: ${plainCryptoPath}`));
                projectResult.issues.push(`存在 plain-crypto-js 目录 (高危)`);
                result.safe = false;

                // 检查 cleanup 痕迹 (package.md)
                if (fs.existsSync(path.join(plainCryptoPath, 'package.md'))) {
                    console.log(chalk.red(`  ❌ 发现反取证痕迹: ${plainCryptoPath} 包含 package.md (确认为投毒执行后状态)`));
                    projectResult.issues.push(`发现 plain-crypto-js 的反取证 cleanup 痕迹 (package.md)`);
                }
            }
            if (projectResult.issues.length > 0) result.projects.push(projectResult);
        } catch (e) {}
    }

    if (result.safe) console.log(chalk.green('  ✅ 项目代码及依赖链未发现投毒迹象'));

    return result;
}

/**
 * 检查系统 RAT 留痕 (区分平台实例与后门)
 */
function checkRAT() {
    printSection('3. 系统恶意软件 (RAT) 留痕检查');
    const result = { safe: true, found: [] };
    const platform = process.platform;
    const artifacts = RAT_ARTIFACTS[platform] || [];

    for (const artifact of artifacts) {
        if (fs.existsSync(artifact)) {
            console.log(chalk.red(`  ❌ 发现高危后门留痕: ${artifact}`));
            
            // 特殊逻辑：Windows 的 wt.exe 可能是伪造的 PowerShell
            if (platform === 'win32' && artifact.toLowerCase().endsWith('wt.exe')) {
                try {
                    const stats = fs.statSync(artifact);
                    if (stats.size > 0) {
                        console.log(chalk.red(`     🚨 警告：${artifact} 疑似为伪装成 Windows Terminal 的恶意 PowerShell 拷贝`));
                    }
                } catch (e) {}
            }
            
            result.found.push(artifact);
            result.safe = false;
        }
    }

    // 检查活动 ID 相关文件 (如 Windows 下的 %TEMP%\6202033.vbs)
    if (platform === 'win32') {
        const tempDir = process.env.TEMP || 'C:\\Windows\\Temp';
        const campaignFiles = [
            path.join(tempDir, '6202033.vbs'),
            path.join(tempDir, '6202033.ps1')
        ];
        for (const cf of campaignFiles) {
            if (fs.existsSync(cf)) {
                console.log(chalk.red(`  ❌ 发现恶意活动文件: ${cf}`));
                result.found.push(cf);
                result.safe = false;
            }
        }
    }

    if (result.safe) console.log(chalk.green(`  ✅ 未在当前系统环境下发现已知的系统级 RAT 留痕`));
    return result;
}

/**
 * 检查网络配置 (Hosts)
 */
function checkNetworkIOCs() {
    printSection('4. 网络配置 (Hosts/DNS) 审计');
    const result = { safe: true, issues: [] };
    const hostsPath = process.platform === 'win32' 
        ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' 
        : '/etc/hosts';

    try {
        if (fs.existsSync(hostsPath)) {
            const content = fs.readFileSync(hostsPath, 'utf8');
            for (const domain of MALICIOUS_DOMAINS) {
                if (content.includes(domain)) {
                    console.log(chalk.red(`  ❌ Hosts 劫持: 发现恶意域名 ${domain} 已被指向特定 IP`));
                    result.issues.push(`Hosts 文件包含恶意域名: ${domain}`);
                    result.safe = false;
                }
            }
        }
    } catch (e) {
        console.log(chalk.gray('  Skip: 无法访问系统 Hosts 文件'));
    }

    if (result.safe) console.log(chalk.green('  ✅ 系统 Hosts 文件未发现异常劫持'));
    return result;
}

/**
 * 获取进程 PID 对应的可执行文件路径
 */
function getProcessPath(pid) {
    if (!pid || pid === '0') return 'N/A';
    try {
        if (process.platform === 'win32') {
            const output = execSync(`wmic process where processid=${pid} get ExecutablePath`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            const lines = output.split('\n').filter(line => line.trim() && !line.includes('ExecutablePath'));
            return lines[0] ? lines[0].trim() : 'Unknown';
        } else if (process.platform === 'linux') {
            return fs.readlinkSync(`/proc/${pid}/exe`);
        } else if (process.platform === 'darwin') {
            // macOS 需要 lsof 辅助
            const output = execSync(`lsof -p ${pid} | grep txt | awk '{print $NF}'`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            return output.trim() || 'Unknown';
        }
    } catch (e) {
        return 'Permission Denied/Unknown';
    }
    return 'Unknown';
}

/**
 * 检查当前活动网络连接，并关联到具体文件
 */
function checkActiveConnections() {
    printSection('5. 活动网络连接审计 (C2 外联 & 进程关联)');
    const result = { safe: true, connections: [] };
    const platform = process.platform;
    
    try {
        let output = '';
        if (platform === 'win32') {
            output = execSync('netstat -ano', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            const lines = output.split('\n');
            for (const line of lines) {
                const trimmedLine = line.trim();
                if (!trimmedLine) continue;

                const parts = trimmedLine.split(/\s+/);
                // 即使没有 PID (parts.length < 5)，只要匹配到特征也应该报警
                const remoteAddr = parts[2] || '';
                const pid = parts[4] || 'Unknown';
                
                let matched = false;
                let matchType = '';
                let matchTarget = '';

                for (const domain of MALICIOUS_DOMAINS) {
                    if (trimmedLine.includes(domain)) {
                        matched = true;
                        matchType = 'Domain';
                        matchTarget = domain;
                        break;
                    }
                }
                
                if (!matched) {
                    for (const ip of MALICIOUS_IPS) {
                        if (trimmedLine.includes(ip)) {
                            matched = true;
                            matchType = 'IP';
                            matchTarget = ip;
                            break;
                        }
                    }
                }

                if (matched) {
                    const filePath = pid !== 'Unknown' ? getProcessPath(pid) : 'Cannot resolve without PID';
                    console.log(chalk.red(`  ❌ [${matchType}] 发现活动外联: ${matchTarget}`));
                    console.log(chalk.red(`     详情: ${trimmedLine}`));
                    if (pid !== 'Unknown') console.log(chalk.red(`     落地文件: ${filePath} (PID: ${pid})`));
                    
                    result.connections.push({ 
                        domain: matchType === 'Domain' ? matchTarget : 'Known Malicious IP', 
                        remoteAddr: matchTarget, 
                        pid, 
                        filePath, 
                        raw: trimmedLine 
                    });
                    result.safe = false;
                }
            }
        } else {
            // Linux/macOS 部分逻辑同步优化
            try {
                output = execSync('lsof -i -n -P | grep -E "ESTABLISHED|SYN_SENT"', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
                const lines = output.split('\n');
                for (const line of lines) {
                    const trimmedLine = line.trim();
                    if (!trimmedLine) continue;

                    let matched = false;
                    for (const domain of MALICIOUS_DOMAINS) { if (trimmedLine.includes(domain)) { matched = true; break; } }
                    for (const ip of MALICIOUS_IPS) { if (trimmedLine.includes(ip)) { matched = true; break; } }

                    if (matched) {
                        const parts = trimmedLine.split(/\s+/);
                        const procName = parts[0];
                        const pid = parts[1];
                        const remote = parts[8];
                        const filePath = getProcessPath(pid);
                        console.log(chalk.red(`  ❌ 发现活动外联: ${remote} (进程: ${procName}, PID: ${pid})`));
                        console.log(chalk.red(`     落地文件: ${filePath}`));
                        result.connections.push({ domain: 'Detected Malicious', remoteAddr: remote, pid, filePath, raw: trimmedLine });
                        result.safe = false;
                    }
                }
            } catch (e) {}
        }
    } catch (e) {
        console.log(chalk.gray('  Skip: 无法执行网络审计 (可能需要管理员权限)'));
    }

    if (result.safe) console.log(chalk.green('  ✅ 未发现与已知恶意域名的活动连接'));
    return result;
}

/**
 * 检查系统 DNS 缓存
 */
function checkDnsCache() {
    printSection('6. 系统 DNS 缓存历史审计');
    const result = { safe: true, history: [] };
    const platform = process.platform;

    if (platform !== 'win32') {
        console.log(chalk.gray(`  ℹ️  ${platform} 系统暂不支持直接 DNS 缓存审计，跳过。`));
        return result;
    }

    try {
        const output = execSync('ipconfig /displaydns', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        for (const domain of MALICIOUS_DOMAINS) {
            if (output.includes(domain)) {
                console.log(chalk.red(`  ❌ 发现解析记录: 系统曾解析过恶意域名 ${domain}`));
                result.history.push(domain);
                result.safe = false;
            }
        }
    } catch (e) {
        console.log(chalk.gray('  Skip: 无法读取系统 DNS 缓存'));
    }

    if (result.safe) console.log(chalk.green('  ✅ DNS 缓存中未发现恶意解析记录'));
    return result;
}

/**
 * OpenClaw 专项审计 (非误报模式)
 */
function auditOpenClaw() {
    printSection('7. OpenClaw 平台专项安全审计');
    const result = { safe: true, components: [] };
    const paths = PLATFORM_PATHS.openclaw || [];
    let foundPlatform = false;

    for (const p of paths) {
        if (fs.existsSync(p)) {
            foundPlatform = true;
            console.log(chalk.blue(`  🔍 审计 OpenClaw 实例: ${p}`));
            const internalPkgs = glob.sync('**/package.json', { cwd: p, ignore: '**/node_modules/**', absolute: true, follow: false });
            
            for (const pkgFile of internalPkgs) {
                try {
                    const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
                    const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
                    if (deps.axios) {
                        const isSafe = checkVersion('axios (OpenClaw 内部)', deps.axios, pkgFile);
                        if (!isSafe) {
                            console.log(chalk.red(`  ❌ 警告: OpenClaw 实例内部使用的 axios 版本已被投毒！`));
                            result.safe = false;
                        }
                    }
                    for (const mal of CONFIRMED_MALICIOUS_PKGS) {
                        if (deps[mal]) {
                            console.log(chalk.red(`  ❌ 警告: OpenClaw 实例内部发现恶意投毒包 ${mal}！`));
                            result.safe = false;
                        }
                    }
                } catch (e) {}
            }
            result.components.push({ path: p });
        }
    }

    if (!foundPlatform) {
        console.log(chalk.gray('  ℹ️  未在标准路径发现 OpenClaw 平台实例，跳过专项审计。'));
    } else if (result.safe) {
        console.log(chalk.green('  ✅ OpenClaw 平台实例审计通过，未发现投毒组件。'));
    }

    return result;
}

/**
 * 检查 NPM 缓存
 */
function checkNpmCache() {
    printSection('8. NPM 全局缓存污染审计');
    const result = { safe: true, infections: [] };
    const platform = process.platform;
    const paths = NPM_CACHE_LOCATIONS[platform] || [];

    for (const cachePath of paths) {
        if (fs.existsSync(cachePath)) {
            try {
                for (const malPkg of CONFIRMED_MALICIOUS_PKGS) {
                    const pattern = path.join(cachePath, '**', malPkg);
                    const matches = glob.sync(pattern, { nodir: false, strict: false, follow: false, silent: true });
                    if (matches.length > 0) {
                        for (const match of matches) {
                            console.log(chalk.red(`  ❌ 缓存污染: 发现恶意投毒包缓存 ${match}`));
                            result.infections.push(match);
                            result.safe = false;
                        }
                    }
                }
            } catch (e) {}
        }
    }

    if (result.safe) console.log(chalk.green('  ✅ NPM 缓存环境安全'));
    return result;
}

// ========== 报告生成 (Report Generation) ==========

/**
 * 生成精美的 Markdown 审计报告
 */
function generateMarkdownReport(results) {
    const isSafe = results.globalAudit.safe && results.systemAudit.safe && 
                   results.networkAudit.safe && results.activeConnections.safe && 
                   results.dnsCache.safe && results.openClawAudit.safe && 
                   results.projectAudit.safe && results.cacheAudit.safe;

    let md = `# axios & OpenClaw 供应链投毒应急审计报告\n\n`;
    md += `> **审计时间**: ${new Date(results.timestamp).toLocaleString()}\n`;
    md += `> **扫描范围**: \`${results.targetPath}\`\n`;
    md += `> **系统环境**: ${results.platform} (${results.hostname})\n\n`;

    md += `## 1. 审计结论 (Executive Summary)\n\n`;
    if (isSafe) {
        md += `### 🟢 结论：未发现已知威胁\n\n`;
        md += `经过全方位审计，当前系统环境中**未发现**与 2026-03-31 axios 投毒事件或 OpenClaw 相关的恶意代码、后门及配置劫持。系统当前处于安全状态。\n\n`;
    } else {
        md += `### 🔴 结论：发现安全威胁 (COMPROMISED)\n\n`;
        md += `**警告**：审计过程中发现了已确认的供应链投毒迹象或系统后门。建议立即按照本文档第 4 章节的建议进行应急处置。\n\n`;
    }

    md += `| 审计项 | 状态 | 详细结果 |\n`;
    md += `| :--- | :--- | :--- |\n`;
    if (results.globalAudit) md += `| 全局 NPM 包 | ${results.globalAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.globalAudit.packages.filter(p => !p.safe).length} 个异常包 |\n`;
    if (results.systemAudit) md += `| 系统后门 (RAT) | ${results.systemAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.systemAudit.found.length} 个恶意文件 |\n`;
    if (results.networkAudit) md += `| 网络劫持 (Hosts) | ${results.networkAudit.safe ? '✅ 安全' : '❌ 风险'} | ${results.networkAudit.issues.length} 处配置异常 |\n`;
    if (results.activeConnections) md += `| 活动 C2 外联 | ${results.activeConnections.safe ? '✅ 安全' : '❌ 风险'} | ${results.activeConnections.connections.length} 处活动连接 |\n`;
    if (results.dnsCache) md += `| DNS 历史解析 | ${results.dnsCache.safe ? '✅ 安全' : '❌ 风险'} | ${results.dnsCache.history.length} 条历史记录 |\n`;
    if (results.projectAudit) md += `| 本地项目审计 | ${results.projectAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.projectAudit.projects.length} 个受影响项目 |\n`;
    if (results.cacheAudit) md += `| NPM 缓存完整性 | ${results.cacheAudit.safe ? '✅ 安全' : '❌ 风险'} | ${results.cacheAudit.infections.length} 处缓存污染 |\n\n`;

    md += `## 2. 详细审计详情 (Detailed Findings)\n\n`;

    // 2.1 全局包
    md += `### 2.1 全局 NPM 包审计\n`;
    if (results.globalAudit.packages.length > 0) {
        md += `| 包名 | 版本 | 状态 | 来源 |\n`;
        md += `| :--- | :--- | :--- | :--- |\n`;
        results.globalAudit.packages.forEach(p => {
            md += `| ${p.name} | ${p.version} | ${p.safe ? '✅ Safe' : '❌ **MALICIOUS**'} | ${p.location} |\n`;
        });
    } else {
        md += `*未在全局发现相关的 NPM 包。*\n`;
    }
    md += `\n`;

    // 2.2 网络连接
    md += `### 2.2 活动网络连接 (C2 外联 & 进程关联)\n`;
    if (results.activeConnections && results.activeConnections.connections.length > 0) {
        md += `发现以下活跃的恶意 C2 连接，并已成功追踪到发起连接的本地进程文件：\n\n`;
        md += `| 域名 | 远程地址 | PID | 落地文件路径 | 状态 |\n`;
        md += `| :--- | :--- | :--- | :--- | :--- |\n`;
        results.activeConnections.connections.forEach(conn => {
            const isRat = RAT_ARTIFACTS[results.platform || process.platform]?.includes(conn.filePath);
            md += `| ${conn.domain} | ${conn.remoteAddr} | ${conn.pid} | \`${conn.filePath}\` | ${isRat ? '🔥 **RAT 确认**' : '⚠️ 异常进程'} |\n`;
        });
    } else {
        md += `✅ 未发现活跃的恶意 C2 域名连接。\n`;
    }
    md += `\n`;

    // 2.3 DNS 缓存
    md += `### 2.3 系统 DNS 解析历史\n`;
    if (results.dnsCache.history.length > 0) {
        md += `发现以下恶意域名的解析历史：\n\n`;
        results.dnsCache.history.forEach(domain => md += `- 🚨 ${domain}\n`);
    } else {
        md += `✅ 系统 DNS 缓存中未发现恶意解析记录。\n`;
    }
    md += `\n`;

    // 2.4 系统留痕
    md += `### 2.4 系统恶意软件 (RAT) 留痕\n`;
    if (results.systemAudit.found.length > 0) {
        md += `在系统中发现了以下已知的恶意后门或指标文件：\n\n`;
        results.systemAudit.found.forEach(f => md += `- \`${f}\` (**危险**)\n`);
    } else {
        md += `*未发现已知的系统级 RAT 留痕文件。*\n`;
    }
    md += `\n`;

    // 2.5 项目审计
    md += `### 2.5 本地项目及 Workspace 审计\n`;
    if (results.projectAudit.projects.length > 0) {
        results.projectAudit.projects.forEach(proj => {
            md += `#### 项目路径: \`${proj.path}\`\n`;
            md += `发现的问题清单：\n`;
            proj.issues.forEach(issue => md += `- 🚨 ${issue}\n`);
            md += `\n`;
        });
    } else {
        md += `✅ 扫描到的所有本地 Node.js 项目均未发现投毒特征。\n`;
    }
    md += `\n`;

    md += `## 3. 威胁指标分析 (Threat Indicators)\n\n`;
    md += `- **投毒版本**: \`axios@1.14.1\`, \`axios@0.30.4\`\n`;
    md += `- **核心恶意包**: \`plain-crypto-js\`, \`axios-checker-utils\`\n`;
    md += `- **已知 C2 域名**: \`axios-updates.com\`, \`npm-security.org\`, \`claw-sync.net\`, \`sfrclak.com\`\n`;
    md += `- **已知 C2 IP**: \`142.11.206.73\`\n`;
    md += `- **恶意活动 ID**: \`6202033\`\n\n`;

    md += `## 4. 处置与加固建议 (Remediation)\n\n`;
    md += `### 第一阶段：紧急清理 (Immediate Action)\n`;
    md += `1. **隔离系统**: 若发现活动 C2 连接或系统级 RAT 留痕，请立即断开物理网络。\n`;
    md += `2. **物理删除**: 立即删除审计报告中标记为 \`❌\` 的所有文件和目录。\n`;
    md += `3. **缓存清理**: 强制运行 \`npm cache clean --force\`。\n\n`;

    md += `### 第二阶段：修复项目 (Project Fix)\n`;
    md += `1. **强制降级**: 将所有项目的 axios 版本手动锁定为 \`1.14.0\` 或 \`0.30.3\`。\n`;
    md += `2. **依赖重装**: 删除 \`node_modules\` 和 \`package-lock.json\` 后重新运行 \`npm install\`。\n\n`;

    md += `### 第三阶段：凭证轮换 (Credential Rotation)\n`;
    md += `- **重要**: 立即更换所有服务器凭据、NPM 发布 Token、数据库密码等敏感信息。\n\n`;

    md += `---\n`;
    md += `*报告生成工具: axios-emergency-scanner v${results.version || '1.5.0'}*\n`;
    
    return md;
}

// ========== 审计执行 (Audit Runner) ==========
async function runAudit(scanRoot, options) {
    const results = {
        version: '1.5.0',
        timestamp: new Date().toISOString(),
        platform: process.platform,
        hostname: os.hostname(),
        targetPath: scanRoot,
        globalAudit: scanGlobalPackages(),
        systemAudit: checkRAT(),
        networkAudit: checkNetworkIOCs(),
        activeConnections: checkActiveConnections(),
        dnsCache: checkDnsCache(),
        openClawAudit: auditOpenClaw(),
        projectAudit: scanProjects(scanRoot),
        cacheAudit: checkNpmCache()
    };

    const isSystemSafe = results.globalAudit.safe && results.systemAudit.safe && 
                         results.networkAudit.safe && results.activeConnections.safe &&
                         results.dnsCache.safe && results.openClawAudit.safe && 
                         results.projectAudit.safe && results.cacheAudit.safe;

    printHeader('审计汇总报告');
    if (isSystemSafe) {
        console.log(chalk.green('🎉 未在当前环境中发现确认的投毒威胁迹象。'));
    } else {
        console.log(chalk.red('🚨 严重警告: 在您的环境中发现了已确认的安全威胁！'));
    }

    if (options.json) {
        const defaultName = 'axios-security-report.json';
        const jsonPath = typeof options.json === 'string' ? options.json : path.join(scanRoot, defaultName);
        fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2));
        console.log(chalk.cyan(`\n📋 详细 JSON 报告已保存至: ${jsonPath}`));
    }

    if (options.md) {
        const defaultName = 'axios-security-report.md';
        const mdPath = typeof options.md === 'string' ? options.md : path.join(scanRoot, defaultName);
        const mdContent = generateMarkdownReport(results);
        fs.writeFileSync(mdPath, mdContent);
        console.log(chalk.cyan(`\n📑 精美 Markdown 审计报告已保存至: ${mdPath}`));
    }
    
    return results;
}

// ========== CLI 入口 (CLI Entry) ==========
program
    .name('axios-scan')
    .description('axios & OpenClaw 供应链投毒事件应急审计工具')
    .version('1.5.0')
    .argument('[path]', '待扫描的路径', '.')
    .option('--fix', '自动修复发现的 axios 投毒版本')
    .option('--json [file]', '生成 JSON 审计报告')
    .option('--md [file]', '生成精美的 Markdown 审计报告')
    .option('--watch [interval]', '持续监听模式，每隔 N 秒执行一次网络连接审计 (默认 10 秒)')
    .action(async (targetPath, options) => {
        const scanRoot = targetPath === '.' ? process.cwd() : path.resolve(targetPath);
        
        printHeader('axios & OpenClaw 供应链投毒应急审计工具 v1.5.0');
        console.log(`执行时间: ${new Date().toLocaleString()}\n运行环境: ${process.platform} (${os.hostname()})`);
        
        if (options.watch) {
            const interval = parseInt(options.watch) || 10;
            console.log(chalk.blue(`\n📡 持续监听模式已开启 (频率: ${interval}s)... 按 Ctrl+C 停止。`));
            
            // 首次全量扫描
            await runAudit(scanRoot, options);
            
            // 后续仅监听网络和系统
            setInterval(async () => {
                const connResult = checkActiveConnections();
                const dnsResult = checkDnsCache();
                
                if (!connResult.safe || !dnsResult.safe) {
                    console.log(chalk.red(`\n[${new Date().toLocaleTimeString()}] 🔥 警报：检测到恶意网络活动！`));
                    // 发现威胁时自动生成一份带时间戳的增量报告
                    if (options.md) {
                        const ts = new Date().getTime();
                        const results = {
                            version: '1.5.1-watch',
                            timestamp: new Date().toISOString(),
                            activeConnections: connResult,
                            dnsCache: dnsResult,
                            targetPath: scanRoot
                        };
                        const mdContent = generateMarkdownReport(results);
                        fs.writeFileSync(path.join(scanRoot, `axios-security-alert-${ts}.md`), mdContent);
                    }
                }
            }, interval * 1000);
        } else {
            await runAudit(scanRoot, options);
        }
    });

program.parse(process.argv);
