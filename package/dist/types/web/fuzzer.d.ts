/**
 * LombokFuzzer — Web Application Fuzzer
 *
 * Comprehensive web-layer fuzzing: XSS, CSRF, CORS misconfiguration,
 * CSP bypass, cookie security, session management, and DOM injection.
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
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
export declare enum WebVulnerability {
    ReflectedXSS = "reflected_xss",
    StoredXSS = "stored_xss",
    DOMXSS = "dom_xss",
    CSRFMissing = "csrf_missing",
    CORSMisconfig = "cors_misconfiguration",
    CSPBypass = "csp_bypass",
    OpenRedirect = "open_redirect",
    HeaderInjection = "header_injection",
    CookieInsecure = "insecure_cookie",
    SessionFixation = "session_fixation",
    Clickjacking = "clickjacking",
    MIME_Sniffing = "mime_sniffing",
    InfoLeak = "information_leak"
}
export declare const HEADER_INJECTION_PAYLOADS: string[];
export declare class WebFuzzer {
    private readonly prng;
    private readonly findings;
    constructor(prng: PRNG);
    /** Generate XSS test payloads for a parameter. */
    generateXSSPayloads(context: 'html' | 'attribute' | 'script' | 'url' | 'css'): string[];
    /** Analyze response headers for security misconfigurations. */
    analyzeSecurityHeaders(url: string, headers: Record<string, string>): WebFinding[];
    /** Analyze cookies for security issues. */
    analyzeCookies(url: string, cookies: WebCookie[]): WebFinding[];
    /** Generate CORS test requests. */
    generateCORSTests(): Array<{
        origin: string;
        expected: string;
    }>;
    /** Generate CSRF test payloads for a form. */
    generateCSRFTest(form: WebForm): string;
    /** Get all findings. */
    get allFindings(): readonly WebFinding[];
}
//# sourceMappingURL=fuzzer.d.ts.map