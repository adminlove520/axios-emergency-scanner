# axios & OpenClaw 供应链投毒应急扫描工具 (2026-03-31)

这是一个专为应对 2026 年 3 月 31 日爆发的 `axios` 供应链投毒事件以及伴随的 `OpenClaw` 恶意软件危机而开发的应急扫描与修复工具。该工具支持扫描本地项目、全局 NPM 包、系统恶意软件留痕（RAT/OpenClaw）及 NPM 缓存污染。

## 🔍 事件背景

2026 年初至 3 月底，由于 `axios` 库和 `OpenClaw` AI 助手平台的供应链漏洞，黑客发布了大量含有恶意后门的版本（如 `axios@1.14.1` 和 `axios@0.30.4`）以及伪装成 `openclaw` 的恶意包。这些版本会在用户系统中安装远程访问木马（RAT），窃取敏感数据，并可能接管 AI 代理。

## ✨ 核心功能

- **OpenClaw 专项审计**: 检测 `openclaw`, `open-claw`, `@openclaw/core` 等数百个已知的恶意衍生包。
- **多平台深度审计**: 支持 Windows (PowerShell), Linux/macOS (Bash) 以及全功能的 Node.js CLI。
- **项目级扫描**: 递归查找工作目录下的所有 `package.json` 和 Lockfiles 分析直接及间接依赖。
- **后门留痕 (RAT/OpenClaw) 检测**: 扫描已知的恶意文件路径，包括 `~/.openclaw` 等。
- **恶意域名检测**: 检查代码及配置中是否引用了 `open-claw.com` 等 C2 域名。
- **自动修复与加固**: 
    - 自动降级 `axios` 到安全版本。
    - 自动移除所有识别出的 OpenClaw 恶意依赖。
    - 在 `package.json` 中自动添加 `overrides` 或 `resolutions` 配置，强制锁定安全版本。

## 🚀 使用指南

### 快速安装 (推荐)

如果你已安装 Node.js，可以直接通过 npm 全局安装此工具，以便在任何地方使用：

```bash
# 全局安装
npm install -g axios-emergency-scanner

# 运行扫描 (当前目录)
axios-scan

# 运行扫描并自动修复
axios-scan . --fix
```

### 源码运行 (适合开发者)

```bash
# 安装依赖
npm install

# 扫描当前目录
npm run scan

# 扫描指定目录并自动修复
node bin/axios-scan.js /path/to/projects --fix

# 导出详细审计报告 (JSON & Markdown)
axios-scan . --json
axios-scan . --md
```

### 报告示例 (Markdown)

生成的 Markdown 审计报告包含：
- **审计结论**: 明确标注系统是否安全 (🟢/🔴)。
- **资产盘点**: 汇总所有受扫描的项目、包和系统配置状态。
- **修复方案**: 提供分阶段（紧急清理、项目修复、凭证保护）的详细处置建议。

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
