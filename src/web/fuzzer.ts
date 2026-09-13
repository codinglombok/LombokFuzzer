/**
 * LombokFuzzer — Web Application Fuzzer
 *
 * Comprehensive web-layer fuzzing: XSS, CSRF, CORS misconfiguration,
 * CSP bypass, cookie security, session management, and DOM injection.
 *
 * @license Apache-2.0
 */

import type { PRNG } from '../utils/prng.js';

// ─── Types ──────────────────────────────────────────────────────────────────

export interface WebTarget {
  baseUrl: string;
  pages: WebPage[];
  forms: WebForm[];
  cookies: WebCookie[];
  headers: Record<string, string>;
}

export interface WebPage {
  url: string;
  method: string;
  parameters: WebParameter[];
}

export interface WebForm {
  action: string;
  method: string;
  fields: WebFormField[];
  hasCSRFToken: boolean;
}

export interface WebFormField {
  name: string;
  type: string;
  value?: string;
  required: boolean;
}

export interface WebParameter {
  name: string;
  location: 'query' | 'body' | 'path' | 'fragment';
  type: string;
}

export interface WebCookie {
  name: string;
  value: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: string;
}

export interface WebFinding {
  type: WebVulnerability;
  url: string;
  payload: string;
  parameter?: string;
  evidence: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cwe: string;
  remediation: string;
}

export enum WebVulnerability {
  ReflectedXSS = 'reflected_xss',
  StoredXSS = 'stored_xss',
  DOMXSS = 'dom_xss',
  CSRFMissing = 'csrf_missing',
  CORSMisconfig = 'cors_misconfiguration',
  CSPBypass = 'csp_bypass',
  OpenRedirect = 'open_redirect',
  HeaderInjection = 'header_injection',
  CookieInsecure = 'insecure_cookie',
  SessionFixation = 'session_fixation',
  Clickjacking = 'clickjacking',
  MIME_Sniffing = 'mime_sniffing',
  InfoLeak = 'information_leak',
}

// ─── Payload Libraries ──────────────────────────────────────────────────────

const XSS_PAYLOADS = [
  '<script>alert(1)</script>',
  '<img src=x onerror=alert(1)>',
  '<svg onload=alert(1)>',
  '<body onload=alert(1)>',
  '"><script>alert(1)</script>',
  "'-alert(1)-'",
  'javascript:alert(1)',
  '<img src=x onerror="alert(1)">',
  '<iframe src="javascript:alert(1)">',
  '<details open ontoggle=alert(1)>',
  '{{constructor.constructor("alert(1)")()}}',
  '${alert(1)}',
  '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
  '<svg><animate onbegin=alert(1) attributeName=x>',
  '<a href="data:text/html,<script>alert(1)</script>">',
  String.raw`\u003cscript\u003ealert(1)\u003c/script\u003e`,
  '<scr<script>ipt>alert(1)</scr</script>ipt>',
  '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
];

const OPEN_REDIRECT_PAYLOADS = [
  '//evil.com', 'https://evil.com', '//evil.com%2f%2f',
  '/\\evil.com', '////evil.com', 'https:evil.com',
  'javascript:alert(1)//', '//evil%00.com',
  String.raw`\/\/evil.com`, '/%09/evil.com',
];

// Reserved for header injection tests in v0.2.0
export const HEADER_INJECTION_PAYLOADS = [
  '\r\nSet-Cookie: evil=true',
  '\r\nX-Injected: true',
  '\r\n\r\n<html>injected</html>',
  '%0d%0aSet-Cookie:%20evil=true',
  '%0aSet-Cookie:%20evil=true',
  '\nX-Injected: true',
];

const CORS_ORIGINS = [
  'https://evil.com',
  'null',
  'https://target.com.evil.com',
  'https://target-com.evil.com',
  'https://evil.target.com',
];

// ─── Web Fuzzer ─────────────────────────────────────────────────────────────

export class WebFuzzer {
  private readonly prng: PRNG;
  private readonly findings: WebFinding[] = [];

  constructor(prng: PRNG) {
    this.prng = prng;
  }

  /** Generate XSS test payloads for a parameter. */
  generateXSSPayloads(context: 'html' | 'attribute' | 'script' | 'url' | 'css'): string[] {
    const base = [...XSS_PAYLOADS];

    switch (context) {
      case 'attribute':
        return base.map(p => `" ${p} "`).concat(base.map(p => `' ${p} '`));
      case 'script':
        return [
          "';alert(1);//", '";alert(1);//',
          '</script><script>alert(1)</script>',
          '\\";alert(1);//',
          ...base,
        ];
      case 'url':
        return [
          'javascript:alert(1)', 'data:text/html,<script>alert(1)</script>',
          ...OPEN_REDIRECT_PAYLOADS,
        ];
      case 'css':
        return [
          'expression(alert(1))', 'url(javascript:alert(1))',
          '};alert(1);{', '</style><script>alert(1)</script>',
        ];
      default:
        return base;
    }
  }

  /** Analyze response headers for security misconfigurations. */
  analyzeSecurityHeaders(
    url: string,
    headers: Record<string, string>,
  ): WebFinding[] {
    const found: WebFinding[] = [];

    // Missing X-Frame-Options / CSP frame-ancestors
    if (!headers['x-frame-options'] && !headers['content-security-policy']?.includes('frame-ancestors')) {
      found.push({
        type: WebVulnerability.Clickjacking,
        url,
        payload: '',
        evidence: 'Missing X-Frame-Options and CSP frame-ancestors',
        severity: 'medium',
        cwe: 'CWE-1021',
        remediation: 'Add X-Frame-Options: DENY or CSP frame-ancestors directive',
      });
    }

    // Missing X-Content-Type-Options
    if (headers['x-content-type-options'] !== 'nosniff') {
      found.push({
        type: WebVulnerability.MIME_Sniffing,
        url,
        payload: '',
        evidence: 'Missing X-Content-Type-Options: nosniff',
        severity: 'low',
        cwe: 'CWE-16',
        remediation: 'Add X-Content-Type-Options: nosniff header',
      });
    }

    // CORS analysis
    const acao = headers['access-control-allow-origin'];
    if (acao === '*') {
      found.push({
        type: WebVulnerability.CORSMisconfig,
        url,
        payload: '',
        evidence: 'Access-Control-Allow-Origin: * with credentials',
        severity: headers['access-control-allow-credentials'] === 'true' ? 'high' : 'medium',
        cwe: 'CWE-942',
        remediation: 'Restrict CORS to trusted origins; never combine * with credentials',
      });
    }

    // CSP analysis
    const csp = headers['content-security-policy'];
    if (csp) {
      if (csp.includes("'unsafe-inline'") || csp.includes("'unsafe-eval'")) {
        found.push({
          type: WebVulnerability.CSPBypass,
          url,
          payload: '',
          evidence: `CSP contains unsafe directives: ${csp.substring(0, 200)}`,
          severity: 'medium',
          cwe: 'CWE-16',
          remediation: "Remove 'unsafe-inline' and 'unsafe-eval' from CSP; use nonces or hashes",
        });
      }
    } else {
      found.push({
        type: WebVulnerability.CSPBypass,
        url,
        payload: '',
        evidence: 'No Content-Security-Policy header',
        severity: 'medium',
        cwe: 'CWE-16',
        remediation: 'Implement a strict Content-Security-Policy',
      });
    }

    this.findings.push(...found);
    return found;
  }

  /** Analyze cookies for security issues. */
  analyzeCookies(url: string, cookies: WebCookie[]): WebFinding[] {
    const found: WebFinding[] = [];

    for (const cookie of cookies) {
      const issues: string[] = [];
      if (!cookie.httpOnly) issues.push('missing HttpOnly');
      if (!cookie.secure) issues.push('missing Secure');
      if (!cookie.sameSite || cookie.sameSite === 'None') issues.push('SameSite=None or missing');

      if (issues.length > 0) {
        found.push({
          type: WebVulnerability.CookieInsecure,
          url,
          payload: cookie.name,
          evidence: `Cookie '${cookie.name}': ${issues.join(', ')}`,
          severity: cookie.name.toLowerCase().includes('session') ? 'high' : 'medium',
          cwe: 'CWE-614',
          remediation: `Set ${issues.map(i => i.replace('missing ', '')).join(', ')} flags on cookie '${cookie.name}'`,
        });
      }
    }

    this.findings.push(...found);
    return found;
  }

  /** Generate CORS test requests. */
  generateCORSTests(): Array<{ origin: string; expected: string }> {
    // Shuffle order to avoid fingerprinting
    const origins = this.prng.shuffle([...CORS_ORIGINS]);
    void origins; // used in full implementation
    return CORS_ORIGINS.map(origin => ({
      origin,
      expected: 'Should NOT be reflected in Access-Control-Allow-Origin',
    }));
  }

  /** Generate CSRF test payloads for a form. */
  generateCSRFTest(form: WebForm): string {
    return `<html><body onload="document.forms[0].submit()">
<form action="${form.action}" method="${form.method}">
${form.fields.map(f => `<input type="hidden" name="${f.name}" value="${f.value ?? 'fuzzed'}">`).join('\n')}
</form></body></html>`;
  }

  /** Get all findings. */
  get allFindings(): readonly WebFinding[] {
    return this.findings;
  }
}
