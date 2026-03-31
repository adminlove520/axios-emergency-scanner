#!/usr/bin/env node

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');
const { Command } = require('commander');
const chalk = require('chalk');
const glob = require('glob');
const os = require('os');

const program = new Command();

const MALICIOUS_VERSIONS = ["1.14.1", "0.30.4"];
const SAFE_VERSIONS = {
    '1.x': '1.14.0',
    '0.x': '0.30.3'
};
const MALICIOUS_PACKAGE = "plain-crypto-js";

const RAT_ARTIFACTS = {
    linux: ["/tmp/ld.py", path.join(os.homedir(), ".local/bin/kworker")],
    darwin: ["/Library/Caches/com.apple.act.mond", "/tmp/com.apple.sysmond.sh"],
    win32: [
        path.join(process.env.PROGRAMDATA || 'C:\\ProgramData', 'wt.exe'),
        path.join(process.env.APPDATA || '', 'axios-security-check.exe')
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

// ========== Utilities ==========
function printHeader(title) {
    console.log(chalk.cyan('\n' + '='.repeat(40)));
    console.log(chalk.cyan(` ${title}`));
    console.log(chalk.cyan('='.repeat(40)));
}

function printSection(title) {
    console.log(chalk.yellow(`\n[ ${title} ]`));
    console.log('-'.repeat(40));
}

function checkVersion(name, version, location) {
    const cleanVersion = version.replace(/^[\^~]/, '');
    const isMalicious = MALICIOUS_VERSIONS.includes(cleanVersion);
    
    if (isMalicious) {
        console.log(chalk.red(`  ❌ MALICIOUS  ${name}@${version}`));
        console.log(chalk.gray(`         Location: ${location}`));
        return false;
    } else {
        console.log(chalk.green(`  ✅ Safe      ${name}@${version}`));
        console.log(chalk.gray(`         Location: ${location}`));
        return true;
    }
}

// ========== Main Logic ==========
function scanGlobalPackages() {
    printSection('1. NPM 全局安装包检查');
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
                
                if (info.dependencies && info.dependencies.axios) {
                    const isSafe = checkVersion('axios (transitive)', info.dependencies.axios.version, `npm global -> ${name}`);
                    result.packages.push({ name: 'axios', version: info.dependencies.axios.version, location: `npm global -> ${name}`, safe: isSafe });
                    if (!isSafe) result.safe = false;
                }
            }
        }
    } catch (e) {
        console.log(chalk.yellow('  ⚠️ 无法获取详细列表，执行快速检查...'));
        try {
            const output = execSync('npm list -g axios --depth=0', { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
            if (output.includes('axios@')) {
                const match = output.match(/axios@([\d.]+)/);
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

function scanProjects(rootPath) {
    printSection(`2. 项目检查 (递归): ${rootPath}`);
    const result = { safe: true, projects: [], maliciousPackages: [], lockfiles: [] };

    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });
    const lockFiles = glob.sync('**/{package-lock.json,yarn.lock,pnpm-lock.yaml}', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

    for (const pkgFile of files) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
            const deps = { ...(pkg.dependencies || {}), ...(pkg.devDependencies || {}) };
            const projectResult = { path: pkgFile, axios: null, hasMalicious: false };
            
            if (deps.axios) {
                const isSafe = checkVersion('axios', deps.axios, pkgFile);
                projectResult.axios = { version: deps.axios, safe: isSafe };
                if (!isSafe) result.safe = false;
            }

            if (deps[MALICIOUS_PACKAGE]) {
                console.log(chalk.red(`  ❌ MALICIOUS: ${MALICIOUS_PACKAGE} 发现于 package.json`));
                console.log(chalk.gray(`         Location: ${pkgFile}`));
                projectResult.hasMalicious = true;
                result.safe = false;
                result.maliciousPackages.push({ name: MALICIOUS_PACKAGE, location: pkgFile });
            }

            const nodeModulesPath = path.join(path.dirname(pkgFile), 'node_modules', MALICIOUS_PACKAGE);
            if (fs.existsSync(nodeModulesPath)) {
                console.log(chalk.red(`  ❌ MALICIOUS: ${MALICIOUS_PACKAGE} 发现于 node_modules`));
                console.log(chalk.gray(`         Path: ${nodeModulesPath}`));
                projectResult.nodeModulesInfection = true;
                result.safe = false;
                result.maliciousPackages.push({ name: MALICIOUS_PACKAGE, location: nodeModulesPath });
            }
            result.projects.push(projectResult);
        } catch (e) {}
    }

    for (const lockFile of lockFiles) {
        try {
            const content = fs.readFileSync(lockFile, 'utf8');
            let lockfileIssue = false;
            for (const v of MALICIOUS_VERSIONS) {
                if (content.includes(`"axios": "${v}"`) || content.includes(`axios@${v}`)) {
                    console.log(chalk.red(`  ❌ MALICIOUS: 在 lockfile 中发现恶意 axios 版本 ${v}`));
                    console.log(chalk.gray(`         Location: ${lockFile}`));
                    lockfileIssue = true;
                    result.safe = false;
                }
            }
            if (content.includes(MALICIOUS_PACKAGE)) {
                console.log(chalk.red(`  ❌ MALICIOUS: 在 lockfile 中发现恶意包 ${MALICIOUS_PACKAGE}`));
                console.log(chalk.gray(`         Location: ${lockFile}`));
                lockfileIssue = true;
                result.safe = false;
            }
            result.lockfiles.push({ path: lockFile, safe: !lockfileIssue });
        } catch (e) {}
    }

    if (files.length === 0 && lockFiles.length === 0) console.log(chalk.yellow('  ⚠️ 未找到相关项目文件'));
    else if (result.safe) console.log(chalk.green('  ✅ 所有扫描的项目均未发现恶意版本 (含传递依赖)'));

    return result;
}

function checkRAT() {
    printSection('3. RAT Artifact 检查');
    const result = { safe: true, artifacts: [] };
    const platform = process.platform;
    const artifacts = RAT_ARTIFACTS[platform] || [];

    for (const artifact of artifacts) {
        const found = fs.existsSync(artifact);
        result.artifacts.push({ path: artifact, found });
        if (found) {
            console.log(chalk.red(`  ❌ COMPROMISED: 发现恶意文件 ${artifact}`));
            result.safe = false;
        }
    }

    if (result.safe) console.log(chalk.green(`  ✅ 未发现 ${platform} 系统下的已知 RAT artifacts`));
    return result;
}

function checkNpmCache() {
    printSection('4. NPM 缓存检查');
    const result = { safe: true, infections: [] };
    const platform = process.platform;
    const paths = NPM_CACHE_LOCATIONS[platform] || [];

    for (const cachePath of paths) {
        if (fs.existsSync(cachePath)) {
            try {
                const pattern = path.join(cachePath, '**', MALICIOUS_PACKAGE);
                const matches = glob.sync(pattern, { nodir: false });
                if (matches.length > 0) {
                    for (const match of matches) {
                        console.log(chalk.red(`  ❌ MALICIOUS: ${MALICIOUS_PACKAGE} 发现于缓存`));
                        console.log(chalk.gray(`         Path: ${match}`));
                        result.infections.push(match);
                        result.safe = false;
                    }
                }
            } catch (e) {}
        }
    }

    if (result.safe) console.log(chalk.green('  ✅ NPM 缓存安全'));
    return result;
}

async function fixProject(rootPath) {
    printSection(`🔧 自动修复: ${rootPath}`);
    const files = glob.sync('**/package.json', { cwd: rootPath, ignore: '**/node_modules/**', absolute: true });

    for (const pkgFile of files) {
        try {
            const pkg = JSON.parse(fs.readFileSync(pkgFile, 'utf8'));
            let modified = false;

            const updateDeps = (deps) => {
                if (deps && deps.axios) {
                    const version = deps.axios.replace(/^[\^~]/, '');
                    if (MALICIOUS_VERSIONS.includes(version)) {
                        const target = version.startsWith('1') ? SAFE_VERSIONS['1.x'] : SAFE_VERSIONS['0.x'];
                        console.log(chalk.cyan(`  🛠️  更新 ${pkgFile}: axios ${deps.axios} -> ${target}`));
                        deps.axios = target;
                        modified = true;
                    }
                }
                if (deps && deps[MALICIOUS_PACKAGE]) {
                    console.log(chalk.red(`  🛠️  移除 ${pkgFile}: ${MALICIOUS_PACKAGE}`));
                    delete deps[MALICIOUS_PACKAGE];
                    modified = true;
                }
            };

            updateDeps(pkg.dependencies);
            updateDeps(pkg.devDependencies);

            if (modified) {
                fs.writeFileSync(pkgFile, JSON.stringify(pkg, null, 2), 'utf8');
                console.log(chalk.green(`  ✅ 已保存 ${pkgFile}`));
                console.log(chalk.gray('  ⏳ 正在更新 lockfile...'));
                try { execSync('npm install', { cwd: path.dirname(pkgFile), stdio: 'inherit' }); } catch (e) {}
            }
        } catch (e) {}
    }
}

// ========== CLI Interface ==========
program
    .name('axios-scan')
    .description('axios 供应链投毒应急扫描器')
    .version('1.0.0')
    .argument('[path]', '扫描的根路径', process.cwd())
    .option('--fix', '自动尝试修复')
    .option('--json [file]', '将结果输出到 JSON 文件')
    .action(async (targetPath, options) => {
        const fullPath = path.resolve(targetPath);
        printHeader('axios 供应链投毒应急扫描器');
        console.log(`时间: ${new Date().toLocaleString()}\n系统: ${process.platform} (${os.hostname()})`);
        
        const results = {
            timestamp: new Date().toISOString(),
            platform: process.platform,
            hostname: os.hostname(),
            targetPath: fullPath,
            global: scanGlobalPackages(),
            rat: checkRAT(),
            cache: checkNpmCache(),
            projects: scanProjects(fullPath)
        };

        const allSafe = results.global.safe && results.rat.safe && results.cache.safe && results.projects.safe;

        printHeader('汇总结果');
        if (allSafe) {
            console.log(chalk.green('🎉 未发现投毒迹象！建议锁定版本到 1.14.0 或 0.30.3。'));
        } else {
            console.log(chalk.red('⚠️ 发现安全风险！请根据上述报错信息立即处理。'));
            if (options.fix) await fixProject(fullPath);
            else console.log(chalk.cyan('\n💡 提示: 使用 --fix 参数可尝试自动修复版本。'));
        }

        if (options.json) {
            const jsonPath = typeof options.json === 'string' ? options.json : 'scan-report.json';
            fs.writeFileSync(jsonPath, JSON.stringify(results, null, 2));
            console.log(chalk.cyan(`\n📋 详细 JSON 报告已保存至: ${jsonPath}`));
        }
    });

program.parse(process.argv);
