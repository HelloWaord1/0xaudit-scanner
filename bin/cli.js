#!/usr/bin/env node

'use strict';

const { scan } = require('../src/scanner');
const { formatReport } = require('../src/report');

const VERSION = '1.0.0';

const HELP = `
🛡️  0xAudit Security Scanner v${VERSION}

Usage:
  0xaudit scan <url> [options]
  0xaudit <url> [options]

Options:
  --format <terminal|json|md>   Output format (default: terminal)
  --timeout <ms>                Request timeout in ms (default: 10000)
  --no-color                    Disable colored output
  -h, --help                    Show this help
  -v, --version                 Show version

Examples:
  0xaudit scan https://example.com
  0xaudit https://example.com --format json
  0xaudit scan https://example.com --format md --timeout 15000

More info: https://0-x-audit.com
`;

function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = { format: 'terminal', timeout: 10000, noColor: false };
  let url = null;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      console.log(HELP);
      process.exit(0);
    }
    if (arg === '-v' || arg === '--version') {
      console.log(VERSION);
      process.exit(0);
    }
    if (arg === '--format' && args[i + 1]) {
      opts.format = args[++i];
      continue;
    }
    if (arg === '--timeout' && args[i + 1]) {
      opts.timeout = parseInt(args[++i], 10);
      continue;
    }
    if (arg === '--no-color') {
      opts.noColor = true;
      continue;
    }
    if (arg === 'scan') continue;
    if (arg.startsWith('http://') || arg.startsWith('https://')) {
      url = arg;
    } else if (!arg.startsWith('-')) {
      url = arg.startsWith('//') ? `https:${arg}` : `https://${arg}`;
    }
  }

  return { url, opts };
}

async function main() {
  const { url, opts } = parseArgs(process.argv);

  if (!url) {
    console.log(HELP);
    process.exit(1);
  }

  try {
    const results = await scan(url, { timeout: opts.timeout });
    const output = formatReport(results, opts.format, opts.noColor);
    console.log(output);

    // Exit code based on score
    const score = results.score;
    if (score < 40) process.exit(2);
    if (score < 70) process.exit(1);
    process.exit(0);
  } catch (err) {
    console.error(`\n  ✗ Error: ${err.message}\n`);
    process.exit(2);
  }
}

main();
