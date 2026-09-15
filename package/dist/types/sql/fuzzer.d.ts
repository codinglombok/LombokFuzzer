/**
 * LombokFuzzer — SQL Injection Fuzzer
 *
 * AST-aware SQL injection testing with dialect support for PostgreSQL, MySQL,
 * MSSQL, SQLite, and Oracle. Goes beyond string replacement: understands SQL
 * syntax trees to generate contextually valid injection payloads.
 *
 * @license Apache-2.0
 */
import type { PRNG } from '../utils/prng.js';
export declare enum SQLDialect {
    PostgreSQL = "postgresql",
    MySQL = "mysql",
    MSSQL = "mssql",
    SQLite = "sqlite",
    Oracle = "oracle",
    Generic = "generic"
}
export interface SQLInjectionResult {
    payload: string;
    context: string;
    dialect: SQLDialect;
    technique: string;
    description: string;
}
export declare class SQLFuzzer {
    private readonly prng;
    private readonly dialect;
    constructor(prng: PRNG, dialect?: SQLDialect);
    /** Generate injection payloads for a given context. */
    generatePayloads(context: 'string' | 'numeric' | 'column' | 'table' | 'order', count?: number): SQLInjectionResult[];
    /** Get all payload generators for a context. */
    private getGeneratorsForContext;
    private tautology;
    private unionBased;
    private errorBased;
    private timeBased;
    private booleanBased;
    private stackedQuery;
    private commentInjection;
    private encodingBypass;
    private pgSpecific;
    private mysqlSpecific;
    private mssqlSpecific;
    private commentSuffix;
}
//# sourceMappingURL=fuzzer.d.ts.map