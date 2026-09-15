/**
 * LombokFuzzer — API Fuzzer
 *
 * Fuzz REST APIs, GraphQL endpoints, and OpenAPI-defined services.
 * Features:
 * - OpenAPI/Swagger spec-driven request generation
 * - GraphQL introspection + query mutation
 * - Authentication state tracking (JWT, API key, OAuth)
 * - Response validation against schema
 * - Rate-limit-aware throttling
 * - IDOR / BOLA / mass assignment detection
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
export interface ApiEndpoint {
    method: string;
    path: string;
    parameters: ApiParameter[];
    requestBody?: ApiSchema;
    responseSchemas: Map<number, ApiSchema>;
    authentication?: AuthConfig;
    tags: string[];
}
export interface ApiParameter {
    name: string;
    in: 'query' | 'header' | 'path' | 'cookie';
    required: boolean;
    schema: ApiSchema;
}
export interface ApiSchema {
    type: string;
    format?: string;
    properties?: Record<string, ApiSchema>;
    items?: ApiSchema;
    enum?: unknown[];
    minimum?: number;
    maximum?: number;
    minLength?: number;
    maxLength?: number;
    pattern?: string;
    required?: string[];
    nullable?: boolean;
}
export interface AuthConfig {
    type: 'bearer' | 'apiKey' | 'basic' | 'oauth2';
    location?: 'header' | 'query' | 'cookie';
    name?: string;
    token?: string;
}
export interface ApiRequest {
    method: string;
    url: string;
    headers: Record<string, string>;
    query: Record<string, string>;
    body?: unknown;
}
export interface ApiResponse {
    status: number;
    headers: Record<string, string>;
    body: unknown;
    durationMs: number;
}
export interface ApiFinding {
    type: ApiVulnerability;
    endpoint: string;
    request: ApiRequest;
    response?: ApiResponse;
    description: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
}
export declare enum ApiVulnerability {
    SQLInjection = "sql_injection",
    XSS = "xss",
    IDOR = "idor",
    MassAssignment = "mass_assignment",
    BrokenAuth = "broken_auth",
    ExcessiveData = "excessive_data",
    RateLimit = "rate_limit_bypass",
    SSRF = "ssrf",
    Injection = "injection",
    SchemaViolation = "schema_violation",
    ServerError = "server_error",
    InformationDisclosure = "info_disclosure"
}
export declare class ApiFuzzer {
    private readonly prng;
    private readonly endpoints;
    private readonly findings;
    private auth;
    constructor(prng: PRNG);
    /** Load endpoints from an OpenAPI 3.x spec object. */
    loadOpenApiSpec(spec: Record<string, unknown>): void;
    /** Generate a fuzzed API request for a given endpoint. */
    generateRequest(endpoint: ApiEndpoint, baseUrl: string): ApiRequest;
    /** Generate a fuzzed value from schema. */
    generateValue(schema: ApiSchema): unknown;
    /** Check an API response for vulnerabilities. */
    analyzeResponse(endpoint: ApiEndpoint, request: ApiRequest, response: ApiResponse): ApiFinding[];
    /** Set authentication config. */
    setAuth(auth: AuthConfig): void;
    /** Get all findings. */
    get allFindings(): readonly ApiFinding[];
    /** Get all loaded endpoints. */
    get allEndpoints(): readonly ApiEndpoint[];
    private generateString;
    private generateNumber;
    private generateArray;
    private generateObjectFromSchema;
    private attackPayload;
    private applyAuth;
    private extractSchema;
    private hasInfoDisclosure;
    private hasReflectedPayload;
}
//# sourceMappingURL=fuzzer.d.ts.map