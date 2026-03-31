# 更新日志 (CHANGELOG)

所有对 `axios-emergency-scanner` 的重要更改都记录在本文档中。

## [1.3.0] - 2026-03-31

### ✨ 新特性
- **OpenClaw 专项检测**:
    - 增加了对恶意包 `openclaw`、`open-claw`、`@openclaw/core` 等的专项扫描。
    - 增加了对 OpenClaw 恶意域名的检测（如 `open-claw.com`, `claw-sync.net` 等）。
    - 增加了系统级 OpenClaw 留痕检测（如 `~/.openclaw` 目录）。
- **增强的修复逻辑**:
    - `--fix` 模式下现在会自动移除所有识别出的 OpenClaw 相关恶意依赖。
- **脚本同步更新**:
    - `scripts/` 下的 Bash 和 PowerShell 脚本均已同步 OpenClaw 检测逻辑。

## [1.2.0] - 2026-03-31

### ✨ 新特性
- **结构优化**:
    - 将 CLI 核心移动至 `bin/axios-scan.js`。
    - 将辅助脚本移动至 `scripts/` 目录。
- **CI/CD 自动化**:
    - 新增 GitHub Actions 工作流 `.github/workflows/release.yml`，支持在推送版本标签（如 `v1.2.0`）时自动发布到 NPM 并创建 GitHub Release。
- **发布配置**:
    - 在 `package.json` 中配置了 `files` 字段，确保发布到 NPM 的包体积最小化，仅包含核心功能。
    - 添加了 `publishConfig` 确保默认发布到 NPM 公共仓库。

## [1.1.0] - 2026-03-31

### ✨ 新特性
- **增强型 Node.js CLI**:
    - **深度审计**: 递归搜索 `package.json` 并同时扫描 Lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`)。
    - **恶意域名扫描**: 检查 `package.json` 脚本 (如 `postinstall`) 中是否包含已知的恶意 C2 域名。
    - **网络配置审计**: 检查系统 `hosts` 文件是否包含恶意劫持配置。
    - **增强的 RAT 留痕检测**: 增加了针对 Windows、macOS 和 Linux 的多种新后门文件检测路径。
    - **NPM 缓存审计**: 扫描全局 NPM 缓存中是否存在 `plain-crypto-js` 投毒包。
    - **自动修复与加固**: 增加了 `--fix` 选项，不仅可以修复 `package.json` 中的版本，还可以在 `package.json` 中添加 `overrides` 配置防止依赖链被再次污染。
    - **JSON 审计报告**: 支持导出详细的 JSON 格式审计报告。

### 📚 文档
- **中文 README**: 添加了完整的中文 README (`README_CN.md`)。
- **更新日志**: 初始化 `CHANGELOG.md`。

### ⚙️ 优化
- 改进了跨平台路径处理逻辑。
- 优化了全局包扫描的容错处理，当 JSON 解析失败时自动回退至快速命令检查。
- 更新了 `.gitignore`，增加了报告和备份文件的忽略规则。

---

## [1.0.0] - 2026-03-31

### ✨ 初始版本
- 基础 Bash (`axios-security-scan.sh`) 和 PowerShell (`axios-security-scan.ps1`) 脚本。
- 基础 Node.js 扫描逻辑 (`index.js`)。
- 检测恶意版本 (`1.14.1`, `0.30.4`) 和恶意依赖项 `plain-crypto-js`。
- 基本的后门文件检测。
