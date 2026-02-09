'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');
const { checkHeaders } = require('./checks/headers');
const { checkSSL } = require('./checks/ssl');
const { checkCORS } = require('./checks/cors');
const { checkDNS } = require('./checks/dns');
const { checkExposure } = require('./checks/exposure');

/**
 * Fetch a URL and return { statusCode, headers, body, timings }
 */
function fetch(url, options = {}) {
  const timeout = options.timeout || 10000;
  const parsed = new URL(url);
  const mod = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve, reject) => {
    const start = Date.now();
    const req = mod.request(parsed, {
      method: options.method || 'GET',
      headers: options.headers || {},
      timeout,
      rejectUnauthorized: false,
    }, (res) => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        resolve({
          statusCode: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks).toString('utf-8').slice(0, 50000),
          responseTime: Date.now() - start,
          socket: res.socket,
        });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    req.end();
  });
}

/**
 * Main scan function
 */
async function scan(targetUrl, options = {}) {
  const timeout = options.timeout || 10000;

  // Normalize URL
  let url = targetUrl;
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = `https://${url}`;
  }

  const parsed = new URL(url);
  const startTime = Date.now();

  console.log(`\n  Scanning ${url}...\n`);

  // Initial fetch
  let response;
  try {
    response = await fetch(url, { timeout });
  } catch (err) {
    throw new Error(`Cannot reach ${url}: ${err.message}`);
  }

  // Run all checks in parallel
  const [headerFindings, sslFindings, corsFindings, dnsFindings, exposureFindings] = await Promise.all([
    checkHeaders(response, parsed),
    checkSSL(parsed, timeout),
    checkCORS(url, timeout),
    checkDNS(parsed.hostname),
    checkExposure(url, timeout),
  ]);

  const allFindings = [
    ...headerFindings,
    ...sslFindings,
    ...corsFindings,
    ...dnsFindings,
    ...exposureFindings,
  ];

  // Calculate score
  const score = calculateScore(allFindings);
  const grade = scoreToGrade(score);

  return {
    target: url,
    hostname: parsed.hostname,
    timestamp: new Date().toISOString(),
    scanDuration: Date.now() - startTime,
    score,
    grade,
    findings: allFindings,
    summary: {
      critical: allFindings.filter(f => f.severity === 'CRITICAL').length,
      high: allFindings.filter(f => f.severity === 'HIGH').length,
      medium: allFindings.filter(f => f.severity === 'MEDIUM').length,
      low: allFindings.filter(f => f.severity === 'LOW').length,
      info: allFindings.filter(f => f.severity === 'INFO').length,
      pass: allFindings.filter(f => f.severity === 'PASS').length,
    },
  };
}

function calculateScore(findings) {
  let score = 100;
  const penalties = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0, PASS: 0 };
  for (const f of findings) {
    score -= (penalties[f.severity] || 0);
  }
  return Math.max(0, Math.min(100, score));
}

function scoreToGrade(score) {
  if (score >= 90) return 'A';
  if (score >= 80) return 'B';
  if (score >= 70) return 'C';
  if (score >= 50) return 'D';
  return 'F';
}

module.exports = { scan, fetch };
