'use strict';

/**
 * Check security headers
 */
function checkHeaders(response, parsed) {
  const findings = [];
  const h = response.headers;

  // HSTS
  if (parsed.protocol === 'https:') {
    const hsts = h['strict-transport-security'];
    if (!hsts) {
      findings.push({ id: 'hsts-missing', severity: 'HIGH', title: 'Missing HSTS header', description: 'Strict-Transport-Security header is not set. Users can be downgraded to HTTP.', recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' });
    } else {
      const maxAge = parseInt((hsts.match(/max-age=(\d+)/) || [])[1] || '0', 10);
      if (maxAge < 31536000) {
        findings.push({ id: 'hsts-short', severity: 'MEDIUM', title: 'HSTS max-age too short', description: `HSTS max-age is ${maxAge}s (recommended: 31536000)`, recommendation: 'Set max-age to at least 31536000 (1 year)' });
      } else {
        findings.push({ id: 'hsts-ok', severity: 'PASS', title: 'HSTS properly configured', description: `HSTS: ${hsts}` });
      }
    }
  }

  // Content-Security-Policy
  if (!h['content-security-policy']) {
    findings.push({ id: 'csp-missing', severity: 'MEDIUM', title: 'Missing Content-Security-Policy', description: 'No CSP header found. XSS and injection attacks are harder to mitigate.', recommendation: 'Implement a Content-Security-Policy header' });
  } else {
    const csp = h['content-security-policy'];
    if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
      findings.push({ id: 'csp-unsafe', severity: 'MEDIUM', title: 'CSP uses unsafe directives', description: `CSP contains unsafe-inline or unsafe-eval`, recommendation: 'Remove unsafe-inline and unsafe-eval from CSP' });
    } else {
      findings.push({ id: 'csp-ok', severity: 'PASS', title: 'CSP header present', description: `CSP configured` });
    }
  }

  // X-Frame-Options
  if (!h['x-frame-options'] && !(h['content-security-policy'] || '').includes('frame-ancestors')) {
    findings.push({ id: 'xfo-missing', severity: 'MEDIUM', title: 'Missing X-Frame-Options', description: 'No clickjacking protection detected.', recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN' });
  } else {
    findings.push({ id: 'xfo-ok', severity: 'PASS', title: 'Clickjacking protection present' });
  }

  // X-Content-Type-Options
  if (!h['x-content-type-options']) {
    findings.push({ id: 'xcto-missing', severity: 'LOW', title: 'Missing X-Content-Type-Options', description: 'MIME type sniffing is not prevented.', recommendation: 'Add: X-Content-Type-Options: nosniff' });
  } else {
    findings.push({ id: 'xcto-ok', severity: 'PASS', title: 'X-Content-Type-Options: nosniff' });
  }

  // Referrer-Policy
  if (!h['referrer-policy']) {
    findings.push({ id: 'rp-missing', severity: 'LOW', title: 'Missing Referrer-Policy', description: 'Browser may leak referrer information.', recommendation: 'Add: Referrer-Policy: strict-origin-when-cross-origin' });
  } else {
    findings.push({ id: 'rp-ok', severity: 'PASS', title: 'Referrer-Policy configured' });
  }

  // Permissions-Policy
  if (!h['permissions-policy'] && !h['feature-policy']) {
    findings.push({ id: 'pp-missing', severity: 'LOW', title: 'Missing Permissions-Policy', description: 'No Permissions-Policy header to restrict browser features.', recommendation: 'Add a Permissions-Policy header' });
  } else {
    findings.push({ id: 'pp-ok', severity: 'PASS', title: 'Permissions-Policy configured' });
  }

  // Server header disclosure
  if (h['server']) {
    const server = h['server'];
    if (/[\d.]/.test(server)) {
      findings.push({ id: 'server-version', severity: 'LOW', title: `Server header discloses version: ${server}`, description: 'Server version information can help attackers target known vulnerabilities.', recommendation: 'Remove version info from Server header' });
    } else {
      findings.push({ id: 'server-name', severity: 'INFO', title: `Server header: ${server}`, description: 'Server type disclosed (no version)' });
    }
  }

  // X-Powered-By
  if (h['x-powered-by']) {
    findings.push({ id: 'xpb-disclosed', severity: 'LOW', title: `X-Powered-By disclosed: ${h['x-powered-by']}`, description: 'Technology stack information leaked.', recommendation: 'Remove X-Powered-By header' });
  }

  return findings;
}

module.exports = { checkHeaders };
