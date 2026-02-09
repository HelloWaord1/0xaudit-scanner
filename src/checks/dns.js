'use strict';

const dns = require('dns');
const { promisify } = require('util');

const resolveTxt = promisify(dns.resolveTxt);

async function checkDNS(hostname) {
  const findings = [];
  let txtRecords = [];

  try {
    txtRecords = await resolveTxt(hostname);
  } catch (e) {
    // No TXT records
  }

  const flat = txtRecords.map(r => r.join('')).join('\n');

  // SPF
  const spf = flat.split('\n').find(r => r.startsWith('v=spf1'));
  if (!spf) {
    findings.push({ id: 'dns-no-spf', severity: 'MEDIUM', title: 'No SPF record', description: 'No SPF record found. Domain can be spoofed for phishing.', recommendation: 'Add a TXT record with SPF policy (v=spf1 ...)' });
  } else {
    if (spf.includes('+all')) {
      findings.push({ id: 'dns-spf-permissive', severity: 'HIGH', title: 'SPF too permissive (+all)', description: 'SPF record allows all senders.', recommendation: 'Change +all to ~all or -all' });
    } else {
      findings.push({ id: 'dns-spf-ok', severity: 'PASS', title: 'SPF record configured' });
    }
  }

  // DMARC (check _dmarc subdomain)
  let dmarcRecords = [];
  try {
    dmarcRecords = await resolveTxt(`_dmarc.${hostname}`);
  } catch (e) {}

  const dmarcFlat = dmarcRecords.map(r => r.join('')).join('\n');
  const dmarc = dmarcFlat.split('\n').find(r => r.startsWith('v=DMARC1'));

  if (!dmarc) {
    findings.push({ id: 'dns-no-dmarc', severity: 'MEDIUM', title: 'No DMARC record', description: 'No DMARC policy found. Email spoofing protection is incomplete.', recommendation: 'Add a DMARC TXT record at _dmarc.domain' });
  } else {
    if (dmarc.includes('p=none')) {
      findings.push({ id: 'dns-dmarc-none', severity: 'LOW', title: 'DMARC policy is "none" (monitoring only)', description: 'DMARC is set to none — emails are not rejected.', recommendation: 'Upgrade to p=quarantine or p=reject' });
    } else {
      findings.push({ id: 'dns-dmarc-ok', severity: 'PASS', title: 'DMARC policy configured' });
    }
  }

  // DKIM — we can only check if selector is known; check common ones
  const selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 'mail'];
  let dkimFound = false;
  for (const sel of selectors) {
    try {
      const dkim = await resolveTxt(`${sel}._domainkey.${hostname}`);
      if (dkim.length > 0) {
        dkimFound = true;
        break;
      }
    } catch (e) {}
  }

  if (dkimFound) {
    findings.push({ id: 'dns-dkim-ok', severity: 'PASS', title: 'DKIM record found' });
  } else {
    findings.push({ id: 'dns-no-dkim', severity: 'LOW', title: 'No DKIM record found (common selectors)', description: 'Could not find DKIM records for common selectors.', recommendation: 'Configure DKIM for email authentication' });
  }

  return findings;
}

module.exports = { checkDNS };
