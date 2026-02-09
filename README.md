<p align="center">
  <h1 align="center">🛡️ 0xAudit Security Scanner</h1>
  <p align="center">Free, open-source CLI tool for instant website security audits</p>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@0xaudit/scanner"><img src="https://img.shields.io/npm/v/@0xaudit/scanner.svg" alt="npm version"></a>
  <a href="https://github.com/HelloWaord1/0xaudit-scanner/actions"><img src="https://github.com/HelloWaord1/0xaudit-scanner/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://github.com/HelloWaord1/0xaudit-scanner"><img src="https://img.shields.io/github/stars/HelloWaord1/0xaudit-scanner.svg?style=social" alt="GitHub stars"></a>
</p>

---

## What it does

Scans any website and checks for:

| Check | What it tests |
|-------|---------------|
| 🔒 **SSL/TLS** | Certificate validity, expiry, TLS version, weak ciphers |
| 📋 **Security Headers** | HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 🌐 **CORS** | Wildcard origins, credential leaks, origin reflection |
| 📧 **DNS Security** | SPF, DMARC, DKIM records |
| 📁 **File Exposure** | .env, .git, phpinfo, server-status, swagger, backup files |

**Zero dependencies.** Pure Node.js. Works on Node 16+.

## Quick Start

```bash
# Run instantly (no install)
npx @0xaudit/scanner https://your-site.com

# Or install globally
npm install -g @0xaudit/scanner
0xaudit scan https://your-site.com
```

## Usage

```bash
# Terminal output (default — with colors)
0xaudit scan https://example.com

# JSON output (for CI/CD pipelines)
0xaudit scan https://example.com --format json

# Markdown report
0xaudit scan https://example.com --format md

# Custom timeout
0xaudit scan https://example.com --timeout 15000
```

## Example Output

```
  🛡️  0xAudit Security Scanner v1.0

  Target: https://example.com
  Score:  B (82/100)
  Scan time: 2341ms

  ──────────────────────────────────────────────────

  HIGH (1):
    ✗ Missing HSTS header
      → Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

  MEDIUM (2):
    ✗ Missing Content-Security-Policy
      → Implement a Content-Security-Policy header
    ✗ No DMARC record
      → Add a DMARC TXT record at _dmarc.domain

  PASSED (8):
    ✓ Valid SSL certificate
    ✓ TLS 1.3 supported
    ✓ No CORS headers (default same-origin)
    ✓ SPF record configured
    ...

  ──────────────────────────────────────────────────
  Full audit? Visit https://0-x-audit.com
  or connect via MCP: mcp.0-x-audit.com
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Score ≥ 70 (passing) |
| 1 | Score 40-69 (needs work) |
| 2 | Score < 40 or error |

Perfect for CI/CD pipelines — fail builds on poor security scores.

## Grading Scale

| Grade | Score | Meaning |
|-------|-------|---------|
| A | 90-100 | Excellent security posture |
| B | 80-89 | Good, minor improvements needed |
| C | 70-79 | Acceptable, several issues |
| D | 50-69 | Poor, significant issues |
| F | 0-49 | Critical security problems |

## Need a Full Audit?

This scanner covers the basics. For a comprehensive security audit including:

- 🔍 Deep vulnerability assessment
- 📝 Smart contract auditing
- 🏗️ Architecture review
- 📊 Detailed remediation report

Visit **[0-x-audit.com](https://0-x-audit.com)** or connect via MCP: `mcp.0-x-audit.com`

## Contributing

PRs welcome! Please open an issue first to discuss changes.

## License

[MIT](LICENSE) © [0xAudit](https://0-x-audit.com)
