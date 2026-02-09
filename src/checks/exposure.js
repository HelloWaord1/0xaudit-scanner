'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');

function probe(url, timeout) {
  const parsed = new URL(url);
  const mod = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = mod.request(parsed, {
      method: 'GET',
      timeout,
      rejectUnauthorized: false,
      headers: { 'User-Agent': '0xAudit-Scanner/1.0' },
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf-8').slice(0, 5000),
        });
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end();
  });
}

const SENSITIVE_PATHS = [
  { path: '/.env', id: 'env-exposed', title: '.env file exposed', severity: 'CRITICAL', match: (body) => /DB_|API_KEY|SECRET|PASSWORD|TOKEN/i.test(body) },
  { path: '/.git/config', id: 'git-exposed', title: '.git directory exposed', severity: 'CRITICAL', match: (body) => /\[core\]|\[remote/.test(body) },
  { path: '/.git/HEAD', id: 'git-head-exposed', title: '.git/HEAD exposed', severity: 'CRITICAL', match: (body) => /^ref: refs\//.test(body.trim()) },
  { path: '/wp-config.php.bak', id: 'wp-config-bak', title: 'WordPress config backup exposed', severity: 'CRITICAL', match: (body) => /DB_NAME|DB_PASSWORD/.test(body) },
  { path: '/.DS_Store', id: 'ds-store', title: '.DS_Store file exposed', severity: 'LOW', match: (body) => body.includes('Bud1') },
  { path: '/server-status', id: 'server-status', title: 'Apache server-status exposed', severity: 'MEDIUM', match: (body) => /Apache Server Status/.test(body) },
  { path: '/phpinfo.php', id: 'phpinfo', title: 'phpinfo() exposed', severity: 'HIGH', match: (body) => /phpinfo|PHP Version/.test(body) },
  { path: '/api/docs', id: 'api-docs', title: 'API documentation publicly accessible', severity: 'LOW', match: (body, status) => status === 200 && (body.includes('swagger') || body.includes('openapi') || body.includes('API')) },
  { path: '/swagger.json', id: 'swagger-json', title: 'Swagger JSON exposed', severity: 'MEDIUM', match: (body, status) => status === 200 && body.includes('"swagger"') },
  { path: '/robots.txt', id: 'robots-secrets', title: 'Sensitive paths in robots.txt', severity: 'LOW', match: (body, status) => status === 200 && /admin|secret|backup|\.sql|private/i.test(body) },
  { path: '/sitemap.xml', id: 'sitemap', title: 'Sitemap found', severity: 'INFO', match: (body, status) => status === 200 && body.includes('<urlset') },
  { path: '/.well-known/security.txt', id: 'security-txt', title: 'security.txt present', severity: 'PASS', match: (body, status) => status === 200 && /Contact:/i.test(body) },
  { path: '/security.txt', id: 'security-txt-root', title: 'security.txt present (root)', severity: 'PASS', match: (body, status) => status === 200 && /Contact:/i.test(body) },
];

async function checkExposure(baseUrl, timeout = 10000) {
  const findings = [];
  const base = baseUrl.replace(/\/+$/, '');

  // Check paths in parallel (batched to avoid hammering)
  const batchSize = 5;
  for (let i = 0; i < SENSITIVE_PATHS.length; i += batchSize) {
    const batch = SENSITIVE_PATHS.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (check) => {
        const res = await probe(`${base}${check.path}`, timeout);
        if (!res) return null;

        if (check.severity === 'PASS' || check.severity === 'INFO') {
          if (check.match(res.body, res.status)) {
            return { id: check.id, severity: check.severity, title: check.title, description: `Found at ${check.path}` };
          }
          return null;
        }

        if (res.status === 200 && check.match(res.body, res.status)) {
          return {
            id: check.id, severity: check.severity, title: check.title,
            description: `${check.path} is accessible and contains sensitive data.`,
            recommendation: `Block access to ${check.path}`
          };
        }
        return null;
      })
    );
    findings.push(...results.filter(Boolean));
  }

  // Check if security.txt is missing
  const hasSecTxt = findings.some(f => f.id === 'security-txt' || f.id === 'security-txt-root');
  if (!hasSecTxt) {
    findings.push({ id: 'no-security-txt', severity: 'INFO', title: 'No security.txt found', description: 'Consider adding a security.txt for responsible disclosure.', recommendation: 'Create /.well-known/security.txt with contact info' });
  }

  return findings;
}

module.exports = { checkExposure };
