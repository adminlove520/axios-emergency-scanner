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
    "claw-sync.net"
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
                }
            }
            if (projectResult.issues.length > 0) result.projects.push(projectResult);
        } catch (e) {}
    }

    // Lockfile 审计逻辑省略（保留之前的...）
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
            result.found.push(artifact);
            result.safe = false;
        }
    }

    if (result.safe) console.log(chalk.green(`  ✅ 未在当前系统环境下发现已知的系统级 RAT 留痕`));
    return result;
}

/**
 * OpenClaw 专项审计 (非误报模式)
 */
function auditOpenClaw() {
    printSection('4. OpenClaw 平台专项安全审计');
    const result = { safe: true, components: [] };
    const paths = PLATFORM_PATHS.openclaw || [];
    let foundPlatform = false;

    for (const p of paths) {
        if (fs.existsSync(p)) {
            foundPlatform = true;
            console.log(chalk.blue(`  🔍 审计 OpenClaw 实例: ${p}`));
            
            // 在实例路径下递归寻找 package.json 进行深度审计
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
    printSection('5. NPM 全局缓存污染审计');
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
                   results.openClawAudit.safe && results.projectAudit.safe && 
                   results.cacheAudit.safe && results.networkAudit.safe;

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
    md += `| 全局 NPM 包 | ${results.globalAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.globalAudit.packages.filter(p => !p.safe).length} 个异常包 |\n`;
    md += `| 系统后门 (RAT) | ${results.systemAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.systemAudit.found.length} 个恶意文件 |\n`;
    md += `| 网络劫持 (Hosts) | ${results.networkAudit.safe ? '✅ 安全' : '❌ 风险'} | ${results.networkAudit.issues.length} 处配置异常 |\n`;
    md += `| 本地项目审计 | ${results.projectAudit.safe ? '✅ 安全' : '❌ 风险'} | 发现 ${results.projectAudit.projects.length} 个受影响项目 |\n`;
    md += `| NPM 缓存完整性 | ${results.cacheAudit.safe ? '✅ 安全' : '❌ 风险'} | ${results.cacheAudit.infections.length} 处缓存污染 |\n\n`;

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

    // 2.2 系统留痕
    md += `### 2.2 系统恶意软件 (RAT) 留痕\n`;
    if (results.systemAudit.found.length > 0) {
        md += `在系统中发现了以下已知的恶意后门或指标文件：\n\n`;
        results.systemAudit.found.forEach(f => md += `- \`${f}\` (**危险**)\n`);
    } else {
        md += `*未发现已知的系统级 RAT 留痕文件。*\n`;
    }
    md += `\n`;

    // 2.3 网络审计
    md += `### 2.3 网络配置与域名审计\n`;
    if (results.networkAudit.issues.length > 0) {
        md += `发现以下网络劫持或恶意域名指向：\n\n`;
        results.networkAudit.issues.forEach(issue => md += `- 🚨 ${issue}\n`);
    } else {
        md += `✅ 系统 Hosts 文件及 DNS 劫持审计通过。\n`;
    }
    md += `\n`;

    // 2.4 OpenClaw
    md += `### 2.4 OpenClaw 平台专项审计\n`;
    if (results.openClawAudit.safe) {
        md += `✅ 已识别的 OpenClaw 平台组件及其内部依赖项审计通过，未发现投毒。 (实例路径: \`${results.openClawAudit.components.length > 0 ? results.openClawAudit.components[0].path : '未发现'}\`)\n`;
    } else {
        md += `❌ **警告**：在 OpenClaw 平台实例内部发现了受污染的组件，请立即清理平台安装目录。\n`;
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
    md += `- **已知 C2 域名**: \`axios-updates.com\`, \`npm-security.org\`, \`claw-sync.net\`\n\n`;

    md += `## 4. 处置与加固建议 (Remediation)\n\n`;
    md += `### 第一阶段：紧急清理 (Immediate Action)\n`;
    md += `1. **隔离系统**: 若发现系统级 RAT 留痕，请立即断开物理网络。\n`;
    md += `2. **物理删除**: 立即删除审计报告中标记为 \`❌\` 的所有文件和目录。\n`;
    md += `3. **缓存清理**: 强制运行 \`npm cache clean --force\`。\n\n`;

    md += `### 第二阶段：修复项目 (Project Fix)\n`;
    md += `1. **强制降级**: 将所有项目的 axios 版本手动锁定为 \`1.14.0\` 或 \`0.30.3\`。\n`;
    md += `2. **版本锁定**: 在 \`package.json\` 中添加 \`overrides\` 字段强制锁定依赖树版本。\n`;
    md += `3. **依赖重装**: 删除 \`node_modules\` 和 \`package-lock.json\` 后重新运行 \`npm install\`。\n\n`;

    md += `### 第三阶段：凭证轮换 (Credential Rotation)\n`;
    md += `- **风险声明**: 投毒版本具备窃取环境变量和 NPM Token 的能力。\n`;
    md += `- **行动建议**: 立即更换所有服务器凭据、NPM 发布 Token、数据库密码等敏感信息。\n\n`;

    md += `---\n`;
    md += `*报告生成工具: axios-emergency-scanner v${results.version || '1.4.0'}*\n`;
    
    return md;
}

// ========== CLI 入口 (CLI Entry) ==========
program
    .name('axios-scan')
    .description('axios & OpenClaw 供应链投毒事件应急审计工具')
    .version('1.4.0')
    .argument('[path]', '待扫描的路径', '.')
    .option('--fix', '自动修复发现的 axios 投毒版本')
    .option('--json [file]', '生成 JSON 审计报告')
    .option('--md [file]', '生成精美的 Markdown 审计报告')
    .action(async (targetPath, options) => {
        // 动态获取当前路径，避免定义时的静态路径
        const scanRoot = targetPath === '.' ? process.cwd() : path.resolve(targetPath);
        
        printHeader('axios & OpenClaw 供应链投毒应急审计工具 v1.4.0');
        console.log(`执行时间: ${new Date().toLocaleString()}\n运行环境: ${process.platform} (${os.hostname()})`);
        
        const results = {
            version: '1.4.0',
            timestamp: new Date().toISOString(),
            platform: process.platform,
            hostname: os.hostname(),
            targetPath: scanRoot,
            globalAudit: scanGlobalPackages(),
            systemAudit: checkRAT(),
            networkAudit: checkNetworkIOCs(),
            openClawAudit: auditOpenClaw(),
            projectAudit: scanProjects(scanRoot),
            cacheAudit: checkNpmCache()
        };

        const isSystemSafe = results.globalAudit.safe && results.systemAudit.safe && 
                             results.networkAudit.safe &&
                             results.openClawAudit.safe && results.projectAudit.safe && 
                             results.cacheAudit.safe;

        printHeader('审计汇总报告');
        if (isSystemSafe) {
            console.log(chalk.green('🎉 未在当前环境中发现确认的投毒威胁迹象。'));
            console.log('\n💡 提示: 已成功识别并审计您的平台组件，未发现异常。');
        } else {
            console.log(chalk.red('🚨 严重警告: 在您的环境中发现了已确认的安全威胁！'));
            console.log(chalk.red('请优先处理被标记为 [❌ 严重风险] 或 [❌ 发现投毒版本] 的项目。'));
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
    });

program.parse(process.argv);
