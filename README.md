# axios Supply Chain Poisoning Emergency Scanner

An emergency security tool to scan systems and projects for axios supply chain poisoning (versions `1.14.1` and `0.30.4`).

## Background

On March 31, 2026, a maintainer account of the popular `axios` library was compromised. Malicious versions `1.14.1` and `0.30.4` were published to npm, injecting a Remote Access Trojan (RAT) via a `postinstall` script and the malicious package `plain-crypto-js`.

## Features

- **Multi-platform support**: Includes scripts for Windows (PowerShell), Linux/macOS (Bash), and a unified Node.js CLI.
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
