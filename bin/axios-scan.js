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
const MALICIOUS_PACKAGE = "plain-crypto-js";

// 已知恶意域名 (Known Malicious Domains)
const MALICIOUS_DOMAINS = [
    "axios-updates.com",
    "npm-security.org",
    "registry-npmjs.com",
    "plain-crypto.io"
];

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
    console.log(chalk.cyan('\n' + '═'.repeat(50)));
    console.log(chalk.cyan(` 🛡️  ${title}`));
    console.log(chalk.cyan('═'.repeat(50)));
}

function printSection(title) {
    console.log(chalk.yellow(`\n[ ${title} ]`));
    console.log('─'.repeat(50));
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
    const result = { safe: true, packages: [] };
    try {
        const output = execSync('npm list -g --json', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
        const globalPkgs = JSON.parse(output);

        if (globalPkgs.dependencies) {
            for (const [name, info] of Object.entries(globalPkgs.dependencies)) {
                if (name === 'axios') {
                    const isSafe = checkVersion(name, info.version, 'npm global');
                    result.packages.push({ name, version: info.version, location: 'npm global', safe: isSafe });
                    if (!isSafe) result.safe = false;
                }
                // 检查二级依赖
                if (info.dependencies && info.dependencies.axios) {
                    const isSafe = checkVersion('axios (传递依赖)', info.dependencies.axios.version, `npm global -> ${name}`);
                    result.packages.push({ name: 'axios', version: info.dependencies.axios.version, location: `npm global -> ${name}`, safe: isSafe });
                    if (!isSafe) result.safe = false;
                }
            }
        }
    } catch (e) {
        console.log(chalk.yellow('  ⚠️  无法读取全局包 JSON，执行快速列出检查...'));
        try {
            const listOutput = execSync('npm list -g axios --depth=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            if (listOutput.includes('axios@')) {
                const match = listOutput.match(/axios@([\d.]+)/);
                if (match) {
                    const isSafe = checkVersion('axios', match[1], 'npm global');
                    result.packages.push({ name: 'axios', version: match[1], location: 'npm global', safe: isSafe });
                    result.safe = isSafe;
                }
            }
        } catch (ee) {}
    }
    
    if (result.safe && result.packages.length === 0) console.log(chalk.green('  ✅ 未在全局发现 axios'));
    else if (result.safe) console.log(chalk.green('  ✅ 未发现全局恶意 axios 版本'));
    
    return result;
}

/**
 * 递归检查项目文件
 */
function scanProjects(rootPath) {
    printSection(`2. 本地项目深度审计: ${rootPath}`);
    const result = { safe: true, projects: [], maliciousPkgs: [], lockIssues: [] };

    // 搜索 package.json
    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });
    // 搜索 Lockfiles
    const lockFiles = glob.sync('**/{package-lock.json,yarn.lock,pnpm-lock.yaml}', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

    for (const pkgFile of files) {
        try {
            const pkgContent = fs.readFileSync(pkgFile, 'utf8');
            const pkg = JSON.parse(pkgContent);
            const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            const projectResult = { path: pkgFile, issues: [] };
            
            // 检查 axios 版本
            if (deps.axios) {
                const isSafe = checkVersion('axios', deps.axios, pkgFile);
                if (!isSafe) {
                    projectResult.issues.push(`axios@${deps.axios} 是投毒版本`);
                    result.safe = false;
                }
            }

            // 检查恶意包 plain-crypto-js
            if (deps[MALICIOUS_PACKAGE]) {
                console.log(chalk.red(`  ❌ 严重风险: 在 ${pkgFile} 中发现恶意包 ${MALICIOUS_PACKAGE}`));
                projectResult.issues.push(`发现恶意依赖 ${MALICIOUS_PACKAGE}`);
                result.safe = false;
                result.maliciousPkgs.push({ name: MALICIOUS_PACKAGE, location: pkgFile });
            }

            // 检查 scripts 中的恶意指令 (postinstall 等)
            if (pkg.scripts) {
                for (const [scriptName, scriptCmd] of Object.entries(pkg.scripts)) {
                    for (const domain of MALICIOUS_DOMAINS) {
                        if (scriptCmd.includes(domain)) {
                            console.log(chalk.red(`  ❌ 恶意指令: 在 ${pkgFile} 的 "${scriptName}" 脚本中发现恶意域名 ${domain}`));
                            projectResult.issues.push(`脚本 "${scriptName}" 包含恶意域名 ${domain}`);
                            result.safe = false;
                        }
                    }
                    // 检查 postinstall 常见的反弹 shell/下载指令
                    if (scriptName === 'postinstall' && (scriptCmd.includes('curl') || scriptCmd.includes('wget') || scriptCmd.includes('bash -i'))) {
                        console.log(chalk.yellow(`  ⚠️  可疑脚本: 在 ${pkgFile} 中发现潜在危险的 postinstall 脚本: ${scriptCmd}`));
                    }
                }
            }

            // 检查本地 node_modules 是否已感染
            const nodeModulesPath = path.join(path.dirname(pkgFile), 'node_modules', MALICIOUS_PACKAGE);
            if (fs.existsSync(nodeModulesPath)) {
                console.log(chalk.red(`  ❌ 实体感染: 在 node_modules 中发现 ${MALICIOUS_PACKAGE}`));
                projectResult.issues.push(`node_modules/${MALICIOUS_PACKAGE} 实体文件存在`);
                result.safe = false;
            }

            if (projectResult.issues.length > 0) result.projects.push(projectResult);
        } catch (e) {
            console.log(chalk.gray(`  Skip: 无法解析 ${pkgFile}`));
        }
    }

    // Lockfile 静态分析
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
            if (content.includes(MALICIOUS_PACKAGE)) {
                console.log(chalk.red(`  ❌ Lockfile 污染: 在 ${lockFile} 中发现恶意包 ${MALICIOUS_PACKAGE}`));
                hasIssue = true;
                result.safe = false;
            }
            if (hasIssue) result.lockIssues.push(lockFile);
        } catch (e) {}
    }

    if (files.length === 0 && lockFiles.length === 0) console.log(chalk.yellow('  ⚠️  未找到 Node.js 项目相关文件'));
    else if (result.safe) console.log(chalk.green('  ✅ 项目扫描未发现已知的投毒特征 (含传递依赖)'));

    return result;
}

/**
 * 检查系统 RAT 留痕
 */
function checkRAT() {
    printSection('3. 系统恶意软件 (RAT) 留痕检查');
    const result = { safe: true, found: [] };
    const platform = process.platform;
    const artifacts = RAT_ARTIFACTS[platform] || [];

    for (const artifact of artifacts) {
        if (fs.existsSync(artifact)) {
            console.log(chalk.red(`  ❌ 发现后门文件: ${artifact}`));
            result.found.push(artifact);
            result.safe = false;
        }
    }

    if (result.safe) console.log(chalk.green(`  ✅ 未在 ${platform} 系统环境下发现已知的 RAT 留痕`));
    return result;
}

/**
 * 检查 NPM 缓存是否包含恶意包
 */
function checkNpmCache() {
    printSection('4. NPM 全局缓存完整性审计');
    const result = { safe: true, infections: [] };
    const platform = process.platform;
    const paths = NPM_CACHE_LOCATIONS[platform] || [];

    for (const cachePath of paths) {
        if (fs.existsSync(cachePath)) {
            try {
                // 搜索缓存中的恶意包
                const pattern = path.join(cachePath, '**', MALICIOUS_PACKAGE);
                const matches = glob.sync(pattern, { nodir: false });
                if (matches.length > 0) {
                    for (const match of matches) {
                        console.log(chalk.red(`  ❌ 缓存污染: 发现恶意包缓存 ${match}`));
                        result.infections.push(match);
                        result.safe = false;
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
 * 自动修复逻辑
 */
async function fixProject(rootPath) {
    printSection(`🔧 正在执行自动修复策略: ${rootPath}`);
    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

    for (const pkgFile of files) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
            let modified = false;

            const fixDeps = (deps) => {
                if (deps && deps.axios) {
                    const version = deps.axios.replace(/^[\^~]/, '');
                    if (MALICIOUS_VERSIONS.includes(version)) {
                        const target = version.startsWith('1') ? SAFE_VERSIONS['1.x'] : SAFE_VERSIONS['0.x'];
                        console.log(chalk.cyan(`  🛠️  修复版本: ${pkgFile} [axios ${deps.axios} -> ${target}]`));
                        deps.axios = target;
                        modified = true;
                    }
                }
                if (deps && deps[MALICIOUS_PACKAGE]) {
                    console.log(chalk.red(`  🛠️  移除恶意包: ${pkgFile} [${MALICIOUS_PACKAGE}]`));
                    delete deps[MALICIOUS_PACKAGE];
                    modified = true;
                }
            };

            fixDeps(pkg.dependencies);
            fixDeps(pkg.devDependencies);

            // 额外安全加固: 添加 overrides (npm) 或 resolutions (yarn)
            if (modified) {
                if (!pkg.overrides) pkg.overrides = {};
                pkg.overrides.axios = pkg.dependencies.axios || pkg.devDependencies.axios;
                console.log(chalk.cyan(`  🛡️  添加安全防护: 已在 package.json 中添加 overrides 锁定版本`));

                fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2), 'utf8');
                console.log(chalk.green(`  ✅ 修复成功: ${pkgFile}`));
                
                // 清理对应的 node_modules
                const nmPath = path.join(path.dirname(pkgFile), 'node_modules');
                if (fs.existsSync(nmPath)) {
                    console.log(chalk.gray('  ⏳ 正在更新依赖并重新构建 Lockfile...'));
                    try {
                        execSync('npm install --package-lock-only', { cwd: path.dirname(pkgFile), stdio: 'ignore' });
                    } catch (e) {}
                }
            }
        } catch (e) {
            console.log(chalk.red(`  ❌ 修复失败: ${pkgFile} (${e.message})`));
        }
    }
}

// ========== CLI 入口 (CLI Entry) ==========
program
    .name('axios-scan')
    .description('axios 供应链投毒事件应急处置工具 (2026-03-31)')
    .version('1.1.0')
    .argument('[path]', '待扫描的路径 (默认为当前目录)', process.cwd())
    .option('--fix', '发现问题后尝试自动修复并锁定版本')
    .option('--json [file]', '生成详细的 JSON 审计报告')
    .action(async (targetPath, options) => {
        const fullPath = path.resolve(targetPath);
        printHeader('axios 供应链投毒应急审计工具 v1.1.0');
        console.log(`执行时间: ${new Date().toLocaleString()}`);
        console.log(`运行环境: ${process.platform} (${os.hostname()})`);
        
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
            console.log(chalk.green('🎉 恭喜！未在当前环境中发现已知的投毒威胁迹象。'));
            console.log('\n🛡️  安全建议:');
            console.log(chalk.white('  1. 确保所有项目的 axios 版本锁定为 1.14.0 或 0.30.3'));
            console.log(chalk.white('  2. 在 package.json 中使用 "overrides" 强制锁定依赖树版本'));
            console.log(chalk.white('  3. 定期清理 npm 缓存: npm cache clean --force'));
        } else {
            console.log(chalk.red('🚨 警告: 在您的环境中发现了潜在的安全威胁！'));
            console.log(chalk.red('请立即按照上述审计细项进行排查，并参考处置手册进行系统清理。'));
            
            if (options.fix) {
                await fixProject(fullPath);
            } else {
                console.log(chalk.cyan('\n💡 处置方案: 使用 --fix 参数可尝试自动修复版本并添加安全加固配置。'));
            }
        }

        if (options.json) {
            const jsonPath = typeof options.json === 'string' ? options.json : 'axios-security-report.json';
            fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2));
            console.log(chalk.cyan(`\n📋 详细审计报告已导出至: ${jsonPath}`));
        }
    });

program.parse(process.argv);
