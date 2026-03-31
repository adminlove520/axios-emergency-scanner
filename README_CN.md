# axios 供应链投毒应急扫描工具 (2026-03-31)

这是一个专为应对 2026 年 3 月 31 日爆发的 `axios` 供应链投毒事件开发的应急扫描与修复工具。该工具支持扫描本地项目、全局 NPM 包、系统恶意软件留痕（RAT）及 NPM 缓存污染。

## 🔍 事件背景

2026 年 3 月 31 日，流行的 `axios` 库的一个维护者账户被黑客入侵。黑客发布了含有恶意后门的版本 `1.14.1` 和 `0.30.4`。这些版本通过 `postinstall` 脚本和恶意依赖项 `plain-crypto-js` 在用户系统中安装远程访问木马（RAT）。

## ✨ 核心功能

- **多平台深度审计**: 支持 Windows (PowerShell), Linux/macOS (Bash) 以及全功能的 Node.js CLI。
- **项目级扫描**: 递归查找工作目录下的所有 `package.json` 和 Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)，分析直接及间接依赖。
- **全局包审计**: 检查系统中全局安装的 NPM 包是否受影响。
- **后门留痕 (RAT) 检测**: 扫描已知的恶意文件路径：
    - `/tmp/ld.py` (Linux)
    - `/Library/Caches/com.apple.act.mond` (macOS)
    - `$PROGRAMDATA\wt.exe` (Windows)
    - 其他已知的威胁指标 (IOCs)。
- **NPM 缓存完整性审计**: 检测 NPM 本地缓存中是否存在 `plain-crypto-js` 恶意包残留。
- **网络配置审计**: 检查系统 `hosts` 文件是否包含恶意劫持。
- **自动修复与加固**: 
    - 自动降级 `axios` 到安全版本 (`1.14.0` 或 `0.30.3`)。
    - 自动移除恶意依赖项 `plain-crypto-js`。
    - 在 `package.json` 中自动添加 `overrides` 或 `resolutions` 配置，强制锁定安全版本。

## 🚀 使用指南

### 使用 Node.js (推荐，功能最全)

```bash
# 安装依赖
npm install

# 扫描当前目录
npm run scan

# 扫描指定目录并自动修复
node bin/axios-scan.js /path/to/projects --fix

# 导出 JSON 审计报告
node bin/axios-scan.js . --json
```

### 使用 Bash (Linux/macOS)

```bash
chmod +x scripts/axios-security-scan.sh
./scripts/axios-security-scan.sh [扫描路径]
```

### 使用 PowerShell (Windows)

```powershell
.\scripts\axios-security-scan.ps1 [扫描路径]
```

## 🛡️ 应急处置建议

如果扫描器发现风险，请立即采取以下措施：
1. **网络隔离**: 立即断开受感染主机的网络连接。
2. **凭证轮换**: 立即更改所有敏感服务的密码和 Token（包括 npm tokens, AWS keys, SSH keys, 数据库凭据等）。
3. **系统清理**: 删除扫描器指出的所有恶意文件和目录。
4. **重新构建**: 建议从已知的安全快照中重新构建受感染的系统。
5. **版本锁定**: 强制将 `axios` 锁定为安全版本（`1.14.0` 或 `0.30.3`）。

## 📝 更新日志

请参阅 [CHANGELOG.md](./CHANGELOG.md)。

## 📄 许可证

MIT
