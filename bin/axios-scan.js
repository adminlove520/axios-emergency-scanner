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

// 重点关注的恶意包
const MALICIOUS_PACKAGES = [
    "plain-crypto-js",
    "openclaw",
    "open-claw",
    "@openclaw/core",
    "axios-checker-utils"
];

// 已知恶意域名 (Known Malicious Domains)
const MALICIOUS_DOMAINS = [
    "axios-updates.com",
    "npm-security.org",
    "registry-npmjs.com",
    "plain-crypto.io",
    "open-claw.com",
    "open-claw.org",
    "claw-sync.net",
    "api.openclaw.io"
];

const RAT_ARTIFACTS = {
    linux: [
        "/tmp/ld.py", 
        path.join(os.homedir(), ".local/bin/kworker"),
        "/etc/cron.d/axios-sync",
        path.join(os.homedir(), ".openclaw"),
        "/tmp/.openclaw.lock"
    ],
    darwin: [
        "/Library/Caches/com.apple.act.mond", 
        "/tmp/com.apple.sysmond.sh",
        path.join(os.homedir(), "Library/LaunchAgents/com.axios.check.plist"),
        path.join(os.homedir(), ".openclaw"),
        "/Library/Application Support/.openclaw"
    ],
    win32: [
        path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'wt.exe'),
        path.join(process.env.APPDATA || '', 'axios-security-check.exe'),
        path.join(process.env.TEMP || 'C:\\Windows\\Temp', 'axios_install.ps1'),
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
    printSection('1. 全局 NPM 包安全审计 (含 OpenClaw 专项)');
    const result = { safe: true, packages: [] };
    try {
        const output = execSync('npm list -g --json --depth=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        const globalPkgs = JSON.parse(output);

        if (globalPkgs.dependencies) {
            for (const [name, info] of Object.entries(globalPkgs.dependencies)) {
                // 检查 axios 版本
                if (name === 'axios') {
                    const isSafe = checkVersion(name, info.version, 'npm global');
                    result.packages.push({ name, version: info.version, location: 'npm global', safe: isSafe });
                    if (!isSafe) result.safe = false;
                }
                
                // 检查 OpenClaw 相关的恶意包
                if (MALICIOUS_PACKAGES.includes(name) || name.includes('openclaw')) {
                    console.log(chalk.red(`  ❌ 严重风险: 在全局发现恶意包 ${name}@${info.version}`));
                    result.packages.push({ name, version: info.version, location: 'npm global', safe: false });
                    result.safe = false;
                }
            }
        }
    } catch (e) {
        console.log(chalk.yellow('  ⚠️  无法读取全局包详情，执行快速列出检查...'));
        try {
            const listOutput = execSync('npm list -g --depth=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            for (const pkg of MALICIOUS_PACKAGES) {
                if (listOutput.includes(`${pkg}@`)) {
                    console.log(chalk.red(`  ❌ 严重风险: 在全局发现恶意包 ${pkg}`));
                    result.safe = false;
                }
            }
        } catch (ee) {}
    }
    
    if (result.safe) console.log(chalk.green('  ✅ 未发现全局恶意包感染'));
    
    return result;
}

/**
 * 递归检查项目文件
 */
function scanProjects(rootPath) {
    printSection(`2. 本地项目深度审计 (递归): ${rootPath}`);
    const result = { safe: true, projects: [], maliciousPkgs: [], lockIssues: [] };

    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });
    const lockFiles = glob.sync('**/{package-lock.json,yarn.lock,pnpm-lock.yaml}', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

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

            // 检查 OpenClaw/恶意包
            for (const malPkg of MALICIOUS_PACKAGES) {
                if (deps[malPkg]) {
                    console.log(chalk.red(`  ❌ 严重风险: 在 ${pkgFile} 中发现恶意包 ${malPkg}`));
                    projectResult.issues.push(`发现恶意依赖 ${malPkg}`);
                    result.safe = false;
                    result.maliciousPkgs.push({ name: malPkg, location: pkgFile });
                }
            }

            // 模糊匹配 openclaw 相关
            Object.keys(deps).forEach(depName => {
                if (depName.includes('openclaw') && !MALICIOUS_PACKAGES.includes(depName)) {
                    console.log(chalk.yellow(`  ⚠️  可疑包: 在 ${pkgFile} 中发现 OpenClaw 相关依赖 ${depName}`));
                    result.safe = false;
                }
            });

            // 检查脚本中的恶意指令
            if (pkg.scripts) {
                for (const [scriptName, scriptCmd] of Object.entries(pkg.scripts)) {
                    for (const domain of MALICIOUS_DOMAINS) {
                        if (scriptCmd.includes(domain)) {
                            console.log(chalk.red(`  ❌ 恶意脚本: 在 ${pkgFile} 的 "${scriptName}" 脚本中发现恶意域名 ${domain}`));
                            projectResult.issues.push(`脚本 "${scriptName}" 包含恶意域名 ${domain}`);
                            result.safe = false;
                        }
                    }
                }
            }

            // 检查本地 node_modules 是否已感染
            const nmDir = path.join(path.dirname(pkgFile), 'node_modules');
            if (fs.existsSync(nmDir)) {
                for (const malPkg of MALICIOUS_PACKAGES) {
                    if (fs.existsSync(path.join(nmDir, malPkg))) {
                        console.log(chalk.red(`  ❌ 实体感染: 在 ${nmDir} 中发现恶意包文件 ${malPkg}`));
                        result.safe = false;
                    }
                }
            }

            if (projectResult.issues.length > 0) result.projects.push(projectResult);
        } catch (e) {}
    }

    // Lockfile 分析
    for (const lockFile of lockFiles) {
        try {
            const content = fs.readFileSync(lockFile, 'utf8');
            let hasIssue = false;
            for (const v of MALICIOUS_VERSIONS) {
                if (content.includes(`"axios": "${v}"`) || content.includes(`axios@${v}`)) {
                    console.log(chalk.red(`  ❌ Lockfile 污染: 在 ${lockFile} 中发现恶意 axios@${v}`));
                    hasIssue = true;
                    result.safe = false;
                }
            }
            for (const malPkg of MALICIOUS_PACKAGES) {
                if (content.includes(`"${malPkg}":`) || content.includes(`${malPkg}@`)) {
                    console.log(chalk.red(`  ❌ Lockfile 污染: 在 ${lockFile} 中发现恶意包 ${malPkg}`));
                    hasIssue = true;
                    result.safe = false;
                }
            }
            if (hasIssue) result.lockIssues.push(lockFile);
        } catch (e) {}
    }

    if (result.safe) console.log(chalk.green('  ✅ 项目代码及依赖链未发现 OpenClaw 投毒迹象'));

    return result;
}

/**
 * 检查系统 RAT 留痕
 */
function checkRAT() {
    printSection('3. 系统后门 (RAT) 与 OpenClaw 留痕检查');
    const result = { safe: true, found: [] };
    const platform = process.platform;
    const artifacts = RAT_ARTIFACTS[platform] || [];

    for (const artifact of artifacts) {
        if (fs.existsSync(artifact)) {
            console.log(chalk.red(`  ❌ 发现后门留痕: ${artifact}`));
            result.found.push(artifact);
            result.safe = false;
        }
    }

    if (result.safe) console.log(chalk.green(`  ✅ 未在当前系统环境下发现已知的 RAT/OpenClaw 留痕`));
    return result;
}

/**
 * 检查 NPM 缓存
 */
function checkNpmCache() {
    printSection('4. NPM 全局缓存污染审计');
    const result = { safe: true, infections: [] };
    const platform = process.platform;
    const paths = NPM_CACHE_LOCATIONS[platform] || [];

    for (const cachePath of paths) {
        if (fs.existsSync(cachePath)) {
            try {
                for (const malPkg of MALICIOUS_PACKAGES) {
                    const pattern = path.join(cachePath, '**', malPkg);
                    const matches = glob.sync(pattern, { nodir: false });
                    if (matches.length > 0) {
                        for (const match of matches) {
                            console.log(chalk.red(`  ❌ 缓存污染: 发现恶意包缓存 ${match}`));
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

/**
 * 检查网络配置 (Hosts)
 */
function checkNetworkIOCs() {
    printSection('5. 网络配置 (Hosts/DNS) 审计');
    const result = { safe: true, issues: [] };
    const hostsPath = process.platform === 'win32' 
        ? 'C:\\Windows\\System32\\drivers\\etc\\hosts' 
        : '/etc/hosts';

    try {
        if (fs.existsSync(hostsPath)) {
            const content = fs.readFileSync(hostsPath, 'utf8');
            for (const domain of MALICIOUS_DOMAINS) {
                if (content.includes(domain)) {
                    console.log(chalk.red(`  ❌ Hosts 劫持: 发现恶意域名 ${domain} 已被修改`));
                    result.issues.push(`Hosts 文件包含恶意域名: ${domain}`);
                    result.safe = false;
                }
            }
        }
    } catch (e) {}

    if (result.safe) console.log(chalk.green('  ✅ 系统 Hosts 文件未发现劫持'));
    return result;
}

/**
 * 自动修复逻辑
 */
async function fixProject(rootPath) {
    printSection(`🔧 正在执行 OpenClaw 专项自动修复: ${rootPath}`);
    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

    for (const pkgFile of files) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
            let modified = false;

            const fixDeps = (deps) => {
                if (!deps) return;
                // 修复 axios
                if (deps.axios) {
                    const version = deps.axios.replace(/^[\^~]/, '');
                    if (MALICIOUS_VERSIONS.includes(version)) {
                        const target = version.startsWith('1') ? SAFE_VERSIONS['1.x'] : SAFE_VERSIONS['0.x'];
                        console.log(chalk.cyan(`  🛠️  修复版本: ${pkgFile} [axios -> ${target}]`));
                        deps.axios = target;
                        modified = true;
                    }
                }
                // 移除恶意包
                for (const malPkg of MALICIOUS_PACKAGES) {
                    if (deps[malPkg]) {
                        console.log(chalk.red(`  🛠️  强制移除恶意依赖: ${pkgFile} [${malPkg}]`));
                        delete deps[malPkg];
                        modified = true;
                    }
                }
                // 移除模糊匹配的 openclaw
                Object.keys(deps).forEach(dep => {
                    if (dep.includes('openclaw')) {
                        console.log(chalk.red(`  🛠️  强制移除可疑依赖: ${pkgFile} [${dep}]`));
                        delete deps[dep];
                        modified = true;
                    }
                });
            };

            fixDeps(pkg.dependencies);
            fixDeps(pkg.devDependencies);
            fixDeps(pkg.optionalDependencies);

            if (modified) {
                // 加固
                if (!pkg.overrides) pkg.overrides = {};
                pkg.overrides.axios = pkg.dependencies?.axios || pkg.devDependencies?.axios || "1.14.0";
                
                fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2), 'utf8');
                console.log(chalk.green(`  ✅ 修复成功: ${pkgFile}`));
                
                // 清理 node_modules
                const nmPath = path.join(path.dirname(pkgFile), 'node_modules');
                if (fs.existsSync(nmPath)) {
                    console.log(chalk.gray('  ⏳ 正在更新 Lockfile (仅生成新版)...'));
                    try { execSync('npm install --package-lock-only', { cwd: path.dirname(pkgFile), stdio: 'ignore' }); } catch (e) {}
                }
            }
        } catch (e) {}
    }
}

// ========== CLI 入口 (CLI Entry) ==========
program
    .name('axios-scan')
    .description('axios & OpenClaw 供应链投毒应急审计工具')
    .version('1.3.0')
    .argument('[path]', '待扫描的路径', process.cwd())
    .option('--fix', '自动修复并锁定版本')
    .option('--json [file]', '生成 JSON 审计报告')
    .action(async (targetPath, options) => {
        const fullPath = path.resolve(targetPath);
        printHeader('axios & OpenClaw 供应链投毒应急审计工具 v1.3.0');
        console.log(`执行时间: ${new Date().toLocaleString()}\n运行环境: ${process.platform} (${os.hostname()})`);
        
        const results = {
            timestamp: new Date().toISOString(),
            platform: process.platform,
            hostname: os.hostname(),
            targetPath: fullPath,
            globalAudit: scanGlobalPackages(),
            systemAudit: checkRAT(),
            networkAudit: checkNetworkIOCs(),
            cacheAudit: checkNpmCache(),
            projectAudit: scanProjects(fullPath)
        };

        const isSystemSafe = results.globalAudit.safe && results.systemAudit.safe && 
                             results.networkAudit.safe && results.cacheAudit.safe && 
                             results.projectAudit.safe;

        printHeader('审计汇总报告');
        if (isSystemSafe) {
            console.log(chalk.green('🎉 未在当前环境中发现 axios 或 OpenClaw 相关的投毒威胁。'));
        } else {
            console.log(chalk.red('🚨 严重警告: 在您的环境中发现了潜在的安全威胁 (含 OpenClaw 专项)！'));
            if (options.fix) await fixProject(fullPath);
            else console.log(chalk.cyan('\n💡 处置方案: 请手动清理或使用 --fix 参数进行自动修复。'));
        }

        if (options.json) {
            const jsonPath = typeof options.json === 'string' ? options.json : 'axios-security-report.json';
            fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2));
            console.log(chalk.cyan(`\n📋 详细报告已保存至: ${jsonPath}`));
        }
    });

program.parse(process.argv);
