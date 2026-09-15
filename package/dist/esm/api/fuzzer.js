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
export var ApiVulnerability;
(function (ApiVulnerability) {
    ApiVulnerability["SQLInjection"] = "sql_injection";
    ApiVulnerability["XSS"] = "xss";
    ApiVulnerability["IDOR"] = "idor";
    ApiVulnerability["MassAssignment"] = "mass_assignment";
    ApiVulnerability["BrokenAuth"] = "broken_auth";
    ApiVulnerability["ExcessiveData"] = "excessive_data";
    ApiVulnerability["RateLimit"] = "rate_limit_bypass";
    ApiVulnerability["SSRF"] = "ssrf";
    ApiVulnerability["Injection"] = "injection";
    ApiVulnerability["SchemaViolation"] = "schema_violation";
    ApiVulnerability["ServerError"] = "server_error";
    ApiVulnerability["InformationDisclosure"] = "info_disclosure";
})(ApiVulnerability || (ApiVulnerability = {}));
// ─── API Fuzzer ─────────────────────────────────────────────────────────────
export class ApiFuzzer {
    prng;
    endpoints = [];
    findings = [];
    auth = null;
    constructor(prng) {
        this.prng = prng;
    }
    /** Load endpoints from an OpenAPI 3.x spec object. */
    loadOpenApiSpec(spec) {
        const paths = spec['paths'] ?? {};
        for (const [path, methods] of Object.entries(paths)) {
            for (const [method, operation] of Object.entries(methods)) {
                if (!['get', 'post', 'put', 'delete', 'patch'].includes(method))
                    continue;
                const op = operation;
                const params = op['parameters'] ?? [];
                const reqBody = op['requestBody'];
                const endpoint = {
                    method: method.toUpperCase(),
                    path,
                    parameters: params.map(p => ({
                        name: p['name'],
                        in: p['in'],
                        required: p['required'] ?? false,
                        schema: p['schema'] ?? { type: 'string' },
                    })),
                    requestBody: reqBody
                        ? this.extractSchema(reqBody)
                        : undefined,
                    responseSchemas: new Map(),
                    tags: op['tags'] ?? [],
                };
                this.endpoints.push(endpoint);
            }
        }
    }
    /** Generate a fuzzed API request for a given endpoint. */
    generateRequest(endpoint, baseUrl) {
        const headers = {
            'User-Agent': 'LombokFuzzer/0.1.0',
        };
        const query = {};
        let path = endpoint.path;
        // Parameters
        for (const param of endpoint.parameters) {
            const value = this.generateValue(param.schema);
            if (param.in === 'path') {
                path = path.replace(`{${param.name}}`, String(value));
            }
            else if (param.in === 'query') {
                query[param.name] = String(value);
            }
            else if (param.in === 'header') {
                headers[param.name] = String(value);
            }
        }
        // Request body
        let body;
        if (endpoint.requestBody) {
            body = this.generateObjectFromSchema(endpoint.requestBody);
            headers['Content-Type'] = 'application/json';
        }
        // Authentication
        if (this.auth) {
            this.applyAuth(headers, query);
        }
        return {
            method: endpoint.method,
            url: `${baseUrl}${path}`,
            headers,
            query,
            body,
        };
    }
    /** Generate a fuzzed value from schema. */
    generateValue(schema) {
        // 20% chance of attack payload
        if (this.prng.nextBool(0.2)) {
            return this.attackPayload(schema.type);
        }
        switch (schema.type) {
            case 'string':
                return this.generateString(schema);
            case 'integer':
            case 'number':
                return this.generateNumber(schema);
            case 'boolean':
                return this.prng.nextBool();
            case 'array':
                return this.generateArray(schema);
            case 'object':
                return this.generateObjectFromSchema(schema);
            default:
                return null;
        }
    }
    /** Check an API response for vulnerabilities. */
    analyzeResponse(endpoint, request, response) {
        const found = [];
        // 5xx = server error (potential crash)
        if (response.status >= 500) {
            found.push({
                type: ApiVulnerability.ServerError,
                endpoint: `${endpoint.method} ${endpoint.path}`,
                request,
                response,
                description: `Server error ${response.status} — potential unhandled exception`,
                severity: 'high',
            });
        }
        // Check for information disclosure in error responses
        const bodyStr = typeof response.body === 'string'
            ? response.body
            : JSON.stringify(response.body ?? '');
        if (this.hasInfoDisclosure(bodyStr)) {
            found.push({
                type: ApiVulnerability.InformationDisclosure,
                endpoint: `${endpoint.method} ${endpoint.path}`,
                request,
                response,
                description: 'Response contains sensitive information (stack trace, SQL query, or internal path)',
                severity: 'medium',
            });
        }
        // Check for reflected injection
        if (this.hasReflectedPayload(request, bodyStr)) {
            found.push({
                type: ApiVulnerability.XSS,
                endpoint: `${endpoint.method} ${endpoint.path}`,
                request,
                response,
                description: 'Input payload reflected in response without encoding',
                severity: 'high',
            });
        }
        this.findings.push(...found);
        return found;
    }
    /** Set authentication config. */
    setAuth(auth) {
        this.auth = auth;
    }
    /** Get all findings. */
    get allFindings() {
        return this.findings;
    }
    /** Get all loaded endpoints. */
    get allEndpoints() {
        return this.endpoints;
    }
    // ─── Internal ───────────────────────────────────────────────────────────
    generateString(schema) {
        if (schema.enum)
            return String(this.prng.pick(schema.enum));
        const minLen = schema.minLength ?? 1;
        const maxLen = Math.min(schema.maxLength ?? 50, 1000);
        const len = minLen + this.prng.nextRange(maxLen - minLen + 1);
        let s = '';
        for (let i = 0; i < len; i++)
            s += String.fromCharCode(97 + this.prng.nextRange(26));
        return s;
    }
    generateNumber(schema) {
        const min = schema.minimum ?? -2147483648;
        const max = schema.maximum ?? 2147483647;
        const val = min + this.prng.nextRange(max - min + 1);
        return schema.type === 'integer' ? Math.floor(val) : val + this.prng.nextFloat();
    }
    generateArray(schema) {
        const len = this.prng.nextRange(5);
        const items = [];
        for (let i = 0; i < len; i++) {
            items.push(schema.items ? this.generateValue(schema.items) : null);
        }
        return items;
    }
    generateObjectFromSchema(schema) {
        const obj = {};
        if (schema.properties) {
            for (const [key, propSchema] of Object.entries(schema.properties)) {
                // Include required fields always, optional 50% of the time
                if (schema.required?.includes(key) || this.prng.nextBool(0.5)) {
                    obj[key] = this.generateValue(propSchema);
                }
            }
            // Mass assignment: add unexpected fields
            if (this.prng.nextBool(0.1)) {
                const smuggleKeys = ['role', 'admin', 'isAdmin', 'id', 'userId',
                    'permissions', 'privilege', '__proto__', 'constructor'];
                obj[this.prng.pick(smuggleKeys)] = this.prng.pick([true, 'admin', 1, 0]);
            }
        }
        return obj;
    }
    attackPayload(type) {
        const strPayloads = [
            "' OR 1=1 --", '" OR 1=1 --', "'; DROP TABLE users; --",
            '<script>alert(1)</script>', '{{7*7}}', '${7*7}',
            '../../../etc/passwd', '%00', '\r\nInjected: true',
            'http://169.254.169.254/latest/meta-data/',
            'A'.repeat(10000), '\x00\x00\x00\x00',
        ];
        const numPayloads = [0, -1, -2147483648, 2147483647, NaN, Infinity, 1e308, 9999999999];
        if (type === 'string')
            return this.prng.pick(strPayloads);
        if (type === 'integer' || type === 'number')
            return this.prng.pick(numPayloads);
        return null;
    }
    applyAuth(headers, query) {
        if (!this.auth)
            return;
        switch (this.auth.type) {
            case 'bearer':
                headers['Authorization'] = `Bearer ${this.auth.token ?? 'FUZZED_TOKEN'}`;
                break;
            case 'apiKey':
                if (this.auth.location === 'query') {
                    query[this.auth.name ?? 'api_key'] = this.auth.token ?? 'FUZZED_KEY';
                }
                else {
                    headers[this.auth.name ?? 'X-API-Key'] = this.auth.token ?? 'FUZZED_KEY';
                }
                break;
            case 'basic':
                headers['Authorization'] = `Basic ${btoa(this.auth.token ?? 'admin:admin')}`;
                break;
        }
    }
    extractSchema(reqBody) {
        const content = reqBody['content'];
        if (content?.['application/json']?.['schema']) {
            return content['application/json']['schema'];
        }
        return { type: 'object' };
    }
    hasInfoDisclosure(body) {
        const patterns = [
            /at\s+\w+\s+\(.+:\d+:\d+\)/, // Stack trace
            /SELECT\s+.+\s+FROM\s+/i, // SQL query
            /\/usr\/|\/var\/|\/home\/|C:\\/, // Internal paths
            /password|secret|private_key/i, // Sensitive keywords
        ];
        return patterns.some(p => p.test(body));
    }
    hasReflectedPayload(request, body) {
        const payloads = [
            ...Object.values(request.query),
            typeof request.body === 'string' ? request.body : '',
        ];
        return payloads.some(p => p.length > 5 && body.includes(p));
    }
}
//# sourceMappingURL=fuzzer.js.map