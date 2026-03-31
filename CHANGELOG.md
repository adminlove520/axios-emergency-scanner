# 更新日志 (CHANGELOG)

所有对 `axios-emergency-scanner` 的重要更改都记录在本文档中。

## [1.5.4] - 2026-03-31

### ✨ 威胁研判优化 (Cloud Intelligence Refined)
- **按需研判机制**: 默认情况下 `--judge` 仅对本地黑名单命中的 IP 进行二次云端校验，节省 API 配额。
- **目标 IP 列表**: 支持通过 `--judge 1.1.1.1,2.2.2.2` 指定特定 IP 进行研判。
- **详尽输出**: 研判结果现在包含威胁来源、风险等级及恶意得分的实时日志输出。

## [1.5.2] - 2026-03-31

### ✨ 云端威胁研判 (Cloud Intelligence)
- **集成 ThreatFox (abuse.ch)**: 增加 `--judge` 选项。开启后，对于未命中本地特征库的未知外联 IP，工具会自动查询 ThreatFox C2 数据库进行实时研判。
- **集成 AbuseIPDB**: 支持通过环境变量 `ABUSEIPDB_API_KEY` 接入 AbuseIPDB。开启研判后可自动获取 IP 的恶意得分（Abuse Confidence Score）。
- **智能过滤**: 自动排除回环地址 (127.0.0.1) 和私有局域网地址，专注于外网异常连接的研判。

## [1.5.1] - 2026-03-31

### ✨ 威胁情报更新 (Threat Intel Update)
- **集成 StepSecurity 深度分析成果**:
    - **新增 C2 域名**: `sfrclak.com`。
    - **新增 C2 IP 审计**: 扫描活动网络连接中的恶意 IP `142.11.206.73`。
    - **新增活动 ID 审计**: 扫描包含恶意 Campaign ID `6202033` 的脚本和临时文件。
- **增强型反取证审计**:
    - 即使 `plain-crypto-js` 的 `package.json` 被恶意脚本清理覆盖，工具现在也能通过检测 `node_modules/plain-crypto-js` 目录及反取证残留文件 `package.md` 来确认投毒迹象。
- **系统级 RAT 指标增强**:
    - Windows 平台：增加了对 `%TEMP%` 目录下 `6202033.vbs` 和 `6202033.ps1` 临时文件的扫描。
    - 增强了对 `%PROGRAMDATA%\wt.exe` (伪装成终端的 PowerShell 拷贝) 的检测。

## [1.5.0] - 2026-03-31

### ✨ 新特性
- **活动网络 C2 外联审计**: 
    - 增加了对活跃 TCP/UDP 连接的扫描，通过执行 `netstat` (Windows/macOS) 或 `ss`/`netstat` (Linux) 实时检测系统是否正在与已知的恶意 C2 域名通信。
    - 自动识别并记录发生外联的原始连接信息。
- **系统 DNS 缓存审计 (Windows 专项)**:
    - 增加了对 Windows 系统 DNS 缓存 (`ipconfig /displaydns`) 的深度分析，能够检测出近期内系统是否曾解析过任何已知的恶意投毒相关域名，即使当前连接已断开也能发现历史痕迹。
- **增强型审计报告**:
    - 在 Markdown 和 JSON 报告中增加了“网络实时审计”章节，汇总展示活动连接和 DNS 解析历史。

## [1.4.1] - 2026-03-31

### 🛠️ 优化
- **报告输出路径优化**: 默认情况下，生成的 JSON 和 Markdown 报告现在会保存到**被扫描的根目录**（`scanRoot`）下，而不是固定在执行命令的当前工作目录。这使得在扫描多个独立项目时，报告能自动归档到对应的项目目录中。

## [1.4.0] - 2026-03-31

### ✨ 新特性
- **精美 Markdown 审计报告**: 增加了 `--md [file]` 选项，支持生成符合专业审计规范的漏洞报告。报告包含审计结论、环境信息、详细发现项（表格化展示）以及分阶段的处置与加固建议。
- **报告逻辑优化**: 将 JSON 报告与 Markdown 报告的输出逻辑解耦，并增加了网络配置审计的汇总展示。
- **UI 增强**: 更新了扫描器的 Header 品牌展示，提升了用户体验。

## [1.3.4] - 2026-03-31

### 🛠️ 优化
- **动态路径解析**: 改进了 CLI 默认路径的处理逻辑，使用 `.` 作为默认参数并在运行时动态解析为 `process.cwd()`，避免了潜在的静态路径绑定问题，确保在全局安装场景下行为更符合预期。

## [1.3.2] - 2026-03-31

### 🛠️ 优化与修复 (误报处理)
- **OpenClaw 专项审计逻辑优化**: 
    - 移除了将 `openclaw` 全局包直接标记为“严重风险”的逻辑。
    - 移除了将 `~/.openclaw` 等标准数据目录直接标记为“RAT 留痕”的逻辑。
    - **新增深度审计模式**: 扫描器现在会识别 OpenClaw 平台实例，并对其内部依赖进行递归安全扫描。只有在 OpenClaw 内部发现被投毒的 `axios` 版本或 `plain-crypto-js` 时，才会触发警告。
- **UI 改进**: 为合法平台组件增加了 `ℹ️ 识别到平台组件` 蓝色提示，以区分于 `❌ 严重风险` 红色警告。

## [1.3.1] - 2026-03-31

### ⚙️ 优化与修复
- **修复 Windows 权限错误**: 改进了 `glob` 扫描逻辑，增加了 `strict: false`、`silent: true` 和 `follow: false` 配置。
- **防止循环路径**: 在 Windows 环境下，现在会跳过 `AppData` 等可能导致 `EPERM` 或死循环的特殊系统连接点，从而支持在用户根目录 (`C:\Users\Name`) 下直接运行。

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
