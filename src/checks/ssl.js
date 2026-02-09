'use strict';

const tls = require('tls');
const https = require('https');

function checkSSL(parsed, timeout = 10000) {
  return new Promise((resolve) => {
    if (parsed.protocol !== 'https:') {
      resolve([{
        id: 'no-https', severity: 'CRITICAL', title: 'No HTTPS',
        description: 'Site is not using HTTPS. All traffic is unencrypted.',
        recommendation: 'Enable HTTPS with a valid TLS certificate'
      }]);
      return;
    }

    const port = parsed.port || 443;
    const findings = [];

    const socket = tls.connect({
      host: parsed.hostname,
      port,
      servername: parsed.hostname,
      rejectUnauthorized: false,
      timeout,
    }, () => {
      try {
        const cert = socket.getPeerCertificate(true);
        const cipher = socket.getCipher();
        const protocol = socket.getProtocol();

        // Check if cert is valid
        if (!socket.authorized) {
          const err = socket.authorizationError;
          if (err === 'CERT_HAS_EXPIRED') {
            findings.push({ id: 'ssl-expired', severity: 'CRITICAL', title: 'SSL certificate expired', description: `Certificate expired: ${cert.valid_to}`, recommendation: 'Renew the SSL certificate immediately' });
          } else if (err === 'DEPTH_ZERO_SELF_SIGNED_CERT' || err === 'SELF_SIGNED_CERT_IN_CHAIN') {
            findings.push({ id: 'ssl-self-signed', severity: 'HIGH', title: 'Self-signed certificate', description: 'Certificate is self-signed and not trusted by browsers.', recommendation: 'Use a certificate from a trusted CA (e.g., Let\'s Encrypt)' });
          } else {
            findings.push({ id: 'ssl-untrusted', severity: 'HIGH', title: `SSL certificate issue: ${err}`, description: `TLS authorization failed: ${err}`, recommendation: 'Fix certificate chain issues' });
          }
        } else {
          findings.push({ id: 'ssl-valid', severity: 'PASS', title: 'Valid SSL certificate' });
        }

        // Check expiry proximity
        if (cert.valid_to) {
          const daysLeft = Math.floor((new Date(cert.valid_to) - Date.now()) / 86400000);
          if (daysLeft > 0 && daysLeft < 30) {
            findings.push({ id: 'ssl-expiring', severity: 'MEDIUM', title: `Certificate expires in ${daysLeft} days`, description: `Certificate valid until ${cert.valid_to}`, recommendation: 'Renew certificate before expiry' });
          } else if (daysLeft > 0) {
            findings.push({ id: 'ssl-expiry-ok', severity: 'PASS', title: `Certificate valid for ${daysLeft} days` });
          }
        }

        // Protocol version
        if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
          findings.push({ id: 'ssl-old-tls', severity: 'HIGH', title: `Outdated TLS version: ${protocol}`, description: `${protocol} is deprecated and insecure.`, recommendation: 'Upgrade to TLS 1.2 or 1.3' });
        } else if (protocol === 'TLSv1.3') {
          findings.push({ id: 'ssl-tls13', severity: 'PASS', title: 'TLS 1.3 supported' });
        } else {
          findings.push({ id: 'ssl-tls12', severity: 'PASS', title: `TLS version: ${protocol}` });
        }

        // Weak ciphers
        if (cipher && cipher.name) {
          const weak = /RC4|DES|MD5|NULL|EXPORT|anon/i;
          if (weak.test(cipher.name)) {
            findings.push({ id: 'ssl-weak-cipher', severity: 'HIGH', title: `Weak cipher: ${cipher.name}`, description: 'Weak cipher suite in use.', recommendation: 'Disable weak cipher suites' });
          }
        }
      } catch (e) {
        // ignore parse errors
      }
      socket.end();
      resolve(findings);
    });

    socket.on('error', (err) => {
      findings.push({ id: 'ssl-error', severity: 'HIGH', title: `SSL connection error`, description: err.message, recommendation: 'Verify SSL/TLS configuration' });
      resolve(findings);
    });

    socket.on('timeout', () => {
      socket.destroy();
      findings.push({ id: 'ssl-timeout', severity: 'MEDIUM', title: 'SSL handshake timeout', description: 'Could not complete TLS handshake in time.' });
      resolve(findings);
    });
  });
}

module.exports = { checkSSL };
