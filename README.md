# axios Supply Chain Poisoning Emergency Scanner

An emergency security tool to scan systems and projects for axios supply chain poisoning (versions `1.14.1` and `0.30.4`).

## Background

On March 31, 2026, a maintainer account of the popular `axios` library was compromised. Malicious versions `1.14.1` and `0.30.4` were published to npm, injecting a Remote Access Trojan (RAT) via a `postinstall` script and the malicious package `plain-crypto-js`.

## Features

- **StepSecurity Threat Intel Integration (v1.5.1+)**: Includes confirmed C2 domain `sfrclak.com`, malicious IP `142.11.206.73`, and campaign ID `6202033`.
- **Anti-Forensics Cleanup Detection (v1.5.1+)**: Detects infections even if the malicious script attempted to hide its tracks by overwriting `package.json`.
- **Multi-platform support**: Includes scripts for Windows (PowerShell), Linux/macOS (Bash), and a unified Node.js CLI.
- **Network C2 Live Audit (v1.5.0+)**: Real-time detection of active C2 outbound connections (e.g., `axios-updates.com`).
- **Process-File Correlation (v1.5.0+)**: Automatically maps active malicious connections to their originating local processes and filesystem paths.
- **Continuous Watch Mode**: Use `--watch [interval]` to monitor network activity in the background.
- **System DNS Cache Audit (v1.5.0+)**: Deeply analyzes system resolution history for malicious domain records (Windows only).
- **Global Package Scan**: Checks globally installed npm packages for compromised axios versions.
- **Project-level Scan**: Recursively finds all `package.json` files in your workspace and audits dependencies.
- **RAT Detection**: Scans for known malicious artifacts:
    - `/tmp/ld.py` (Linux)
    - `/Library/Caches/com.apple.act.mond` (macOS)
    - `$PROGRAMDATA\wt.exe` (Windows)
- **NPM Cache Audit**: Checks npm cache for the `plain-crypto-js` malicious package.
- **Backup & Restore**: Supports backing up current axios versions before attempting fixes.
- **Automatic Remediation**: Provides a `--fix` option to update axios to safe versions (1.14.0 or 0.30.3).

## Usage

### Quick Installation (Recommended)

If you have Node.js installed, you can install the tool globally via npm for easy access:

```bash
# Install globally
npm install -g axios-emergency-scanner

# Run scan (current directory)
axios-scan

# Run scan with automatic fix
axios-scan . --fix

# Enable continuous watch mode (e.g., scan network activity every 5s)
axios-scan --watch 5 --md
```

### Run from Source (For Developers)

```bash
# Install dependencies
npm install

# Run scanner
npm run scan

# Run scanner on a specific directory
node bin/axios-scan.js /path/to/projects

# Automatic fix
npm run fix
```

### Using Bash (Linux/macOS)

```bash
./scripts/axios-security-scan.sh [project_path]
```

### Using PowerShell (Windows)

```powershell
.\scripts\axios-security-scan.ps1 [project_path]
```

## Remediation Steps

If the scanner finds issues:
1. **Isolate** the infected machine.
2. **Rotate** all sensitive credentials (npm tokens, AWS keys, etc.).
3. **Rebuild** your systems from a known good state.
4. **Lock** axios to a safe version (`1.14.0` or `0.30.3`) in `package.json`.

## License

MIT
