'use strict';

const https = require('https');
const http = require('http');
const { URL } = require('url');

function corsRequest(url, origin, timeout) {
  const parsed = new URL(url);
  const mod = parsed.protocol === 'https:' ? https : http;

  return new Promise((resolve) => {
    const req = mod.request(parsed, {
      method: 'OPTIONS',
      headers: { 'Origin': origin, 'Access-Control-Request-Method': 'GET' },
      timeout,
      rejectUnauthorized: false,
    }, (res) => {
      res.on('data', () => {});
      res.on('end', () => resolve(res.headers));
    });
    req.on('error', () => resolve({}));
    req.on('timeout', () => { req.destroy(); resolve({}); });
    req.end();
  });
}

async function checkCORS(url, timeout = 10000) {
  const findings = [];

  // Test with wildcard origin
  const evilOrigin = 'https://evil-attacker.com';
  const headers = await corsRequest(url, evilOrigin, timeout);

  const acao = headers['access-control-allow-origin'];
  const acac = headers['access-control-allow-credentials'];

  if (acao === '*') {
    if (acac === 'true') {
      findings.push({
        id: 'cors-wildcard-creds', severity: 'CRITICAL',
        title: 'Wildcard CORS with credentials',
        description: 'Access-Control-Allow-Origin: * with credentials enabled. Any site can steal authenticated data.',
        recommendation: 'Never combine wildcard origin with credentials'
      });
    } else {
      findings.push({
        id: 'cors-wildcard', severity: 'HIGH',
        title: 'Wildcard CORS (*)',
        description: 'Access-Control-Allow-Origin: * allows any website to read responses.',
        recommendation: 'Restrict CORS to specific trusted origins'
      });
    }
  } else if (acao === evilOrigin) {
    if (acac === 'true') {
      findings.push({
        id: 'cors-reflect-creds', severity: 'CRITICAL',
        title: 'CORS reflects arbitrary origin with credentials',
        description: 'Server reflects any Origin header and allows credentials. Critical data theft risk.',
        recommendation: 'Whitelist specific allowed origins'
      });
    } else {
      findings.push({
        id: 'cors-reflect', severity: 'HIGH',
        title: 'CORS reflects arbitrary origin',
        description: 'Server reflects the Origin header from untrusted domains.',
        recommendation: 'Implement a strict origin whitelist'
      });
    }
  } else if (acao) {
    findings.push({ id: 'cors-ok', severity: 'PASS', title: `CORS restricted to: ${acao}` });
  } else {
    findings.push({ id: 'cors-none', severity: 'PASS', title: 'No CORS headers (default same-origin)' });
  }

  return findings;
}

module.exports = { checkCORS };
