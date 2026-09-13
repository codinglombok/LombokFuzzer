/**
 * LombokFuzzer — Grammar Engine
 *
 * Grammar-based input generation supporting ABNF, PEG, JSON Schema, and
 * custom DSL grammars. Generates syntactically valid inputs with targeted
 * semantic mutations.
 *
 * @license Apache-2.0
 */

import type { PRNG } from '../utils/prng.js';

// ─── Grammar AST ────────────────────────────────────────────────────────────

export enum NodeKind {
  Literal = 'literal',
  CharRange = 'char_range',
  Sequence = 'sequence',
  Alternative = 'alternative',
  Repeat = 'repeat',
  Optional = 'optional',
  Reference = 'reference',
}

export interface GrammarNode {
  kind: NodeKind;
  value?: string;
  children?: GrammarNode[];
  min?: number;
  max?: number;
  name?: string;
  weight?: number;
}

export interface Grammar {
  name: string;
  rules: Map<string, GrammarNode>;
  startRule: string;
}

export class GrammarEngine {
  private readonly prng: PRNG;
  private readonly maxDepth: number;
  private readonly maxLength: number;

  constructor(prng: PRNG, maxDepth = 20, maxLength = 65536) {
    this.prng = prng;
    this.maxDepth = maxDepth;
    this.maxLength = maxLength;
  }

  /** Generate an input from a grammar. */
  generate(grammar: Grammar): Uint8Array {
    const startNode = grammar.rules.get(grammar.startRule);
    if (!startNode) throw new Error(`Start rule '${grammar.startRule}' not found`);

    const result = this.expand(startNode, grammar, 0);
    return new TextEncoder().encode(result);
  }

  /** Expand a grammar node into a string. */
  private expand(node: GrammarNode, grammar: Grammar, depth: number): string {
    if (depth > this.maxDepth) return '';

    switch (node.kind) {
      case NodeKind.Literal:
        return node.value ?? '';

      case NodeKind.CharRange: {
        const [lo, hi] = parseCharRange(node.value ?? 'a-z');
        const code = lo + this.prng.nextRange(hi - lo + 1);
        return String.fromCharCode(code);
      }

      case NodeKind.Sequence: {
        let result = '';
        for (const child of node.children ?? []) {
          result += this.expand(child, grammar, depth + 1);
          if (result.length > this.maxLength) break;
        }
        return result;
      }

      case NodeKind.Alternative: {
        const children = node.children ?? [];
        if (children.length === 0) return '';
        // Weighted selection if weights are provided
        const weights = children.map(c => c.weight ?? 1);
        const child = weightedPick(children, weights, this.prng);
        return this.expand(child, grammar, depth + 1);
      }

      case NodeKind.Repeat: {
        const min = node.min ?? 0;
        const max = Math.min(node.max ?? 10, 100);
        const count = min + this.prng.nextRange(max - min + 1);
        let result = '';
        const child = node.children?.[0];
        if (!child) return '';
        for (let i = 0; i < count; i++) {
          result += this.expand(child, grammar, depth + 1);
          if (result.length > this.maxLength) break;
        }
        return result;
      }

      case NodeKind.Optional: {
        if (this.prng.nextBool(0.5)) {
          const child = node.children?.[0];
          return child ? this.expand(child, grammar, depth + 1) : '';
        }
        return '';
      }

      case NodeKind.Reference: {
        const rule = grammar.rules.get(node.name ?? '');
        if (!rule) return '';
        return this.expand(rule, grammar, depth + 1);
      }

      default:
        return '';
    }
  }

  /** Mutate a generated input while preserving grammar structure. */
  mutateGrammarInput(
    input: string,
    grammar: Grammar,
  ): string {
    // Regenerate a random subtree
    const rules = [...grammar.rules.keys()];
    const rule = this.prng.pick(rules);
    const ruleNode = grammar.rules.get(rule)!;
    const newFragment = this.expand(ruleNode, grammar, 0);

    // Insert/replace at a random position
    const pos = this.prng.nextRange(input.length);
    const replaceLen = this.prng.nextRange(Math.min(newFragment.length, input.length - pos));

    return input.substring(0, pos) + newFragment + input.substring(pos + replaceLen);
  }

  // ─── Grammar Builders (convenience) ─────────────────────────────────────

  /** Build a JSON grammar. */
  static jsonGrammar(): Grammar {
    const rules = new Map<string, GrammarNode>();

    rules.set('value', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Reference, name: 'string', weight: 3 },
        { kind: NodeKind.Reference, name: 'number', weight: 2 },
        { kind: NodeKind.Reference, name: 'object', weight: 2 },
        { kind: NodeKind.Reference, name: 'array', weight: 2 },
        { kind: NodeKind.Literal, value: 'true', weight: 1 },
        { kind: NodeKind.Literal, value: 'false', weight: 1 },
        { kind: NodeKind.Literal, value: 'null', weight: 1 },
      ],
    });

    rules.set('string', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: '"' },
        { kind: NodeKind.Repeat, min: 0, max: 20, children: [
          { kind: NodeKind.CharRange, value: ' -~' },
        ]},
        { kind: NodeKind.Literal, value: '"' },
      ],
    });

    rules.set('number', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Literal, value: '-' },
        ]},
        { kind: NodeKind.Repeat, min: 1, max: 10, children: [
          { kind: NodeKind.CharRange, value: '0-9' },
        ]},
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Literal, value: '.' },
            { kind: NodeKind.Repeat, min: 1, max: 5, children: [
              { kind: NodeKind.CharRange, value: '0-9' },
            ]},
          ]},
        ]},
      ],
    });

    rules.set('object', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: '{' },
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Reference, name: 'string' },
            { kind: NodeKind.Literal, value: ':' },
            { kind: NodeKind.Reference, name: 'value' },
            { kind: NodeKind.Repeat, min: 0, max: 5, children: [
              { kind: NodeKind.Sequence, children: [
                { kind: NodeKind.Literal, value: ',' },
                { kind: NodeKind.Reference, name: 'string' },
                { kind: NodeKind.Literal, value: ':' },
                { kind: NodeKind.Reference, name: 'value' },
              ]},
            ]},
          ]},
        ]},
        { kind: NodeKind.Literal, value: '}' },
      ],
    });

    rules.set('array', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: '[' },
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Reference, name: 'value' },
            { kind: NodeKind.Repeat, min: 0, max: 5, children: [
              { kind: NodeKind.Sequence, children: [
                { kind: NodeKind.Literal, value: ',' },
                { kind: NodeKind.Reference, name: 'value' },
              ]},
            ]},
          ]},
        ]},
        { kind: NodeKind.Literal, value: ']' },
      ],
    });

    return { name: 'JSON', rules, startRule: 'value' };
  }

  /** Build an HTTP request grammar. */
  static httpRequestGrammar(): Grammar {
    const rules = new Map<string, GrammarNode>();

    rules.set('request', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Reference, name: 'method' },
        { kind: NodeKind.Literal, value: ' ' },
        { kind: NodeKind.Reference, name: 'path' },
        { kind: NodeKind.Literal, value: ' HTTP/1.1\r\n' },
        { kind: NodeKind.Reference, name: 'headers' },
        { kind: NodeKind.Literal, value: '\r\n' },
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Reference, name: 'body' },
        ]},
      ],
    });

    rules.set('method', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Literal, value: 'GET' },
        { kind: NodeKind.Literal, value: 'POST' },
        { kind: NodeKind.Literal, value: 'PUT' },
        { kind: NodeKind.Literal, value: 'DELETE' },
        { kind: NodeKind.Literal, value: 'PATCH' },
        { kind: NodeKind.Literal, value: 'HEAD' },
        { kind: NodeKind.Literal, value: 'OPTIONS' },
      ],
    });

    rules.set('path', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: '/' },
        { kind: NodeKind.Repeat, min: 0, max: 5, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Repeat, min: 1, max: 15, children: [
              { kind: NodeKind.CharRange, value: 'a-z' },
            ]},
            { kind: NodeKind.Optional, children: [
              { kind: NodeKind.Literal, value: '/' },
            ]},
          ]},
        ]},
      ],
    });

    rules.set('headers', {
      kind: NodeKind.Repeat, min: 1, max: 10,
      children: [{
        kind: NodeKind.Sequence,
        children: [
          { kind: NodeKind.Reference, name: 'headerName' },
          { kind: NodeKind.Literal, value: ': ' },
          { kind: NodeKind.Repeat, min: 1, max: 50, children: [
            { kind: NodeKind.CharRange, value: ' -~' },
          ]},
          { kind: NodeKind.Literal, value: '\r\n' },
        ],
      }],
    });

    rules.set('headerName', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Literal, value: 'Host' },
        { kind: NodeKind.Literal, value: 'Content-Type' },
        { kind: NodeKind.Literal, value: 'Content-Length' },
        { kind: NodeKind.Literal, value: 'Accept' },
        { kind: NodeKind.Literal, value: 'Authorization' },
        { kind: NodeKind.Literal, value: 'User-Agent' },
        { kind: NodeKind.Literal, value: 'Cookie' },
        { kind: NodeKind.Literal, value: 'X-Custom' },
      ],
    });

    rules.set('body', {
      kind: NodeKind.Repeat, min: 0, max: 500,
      children: [{ kind: NodeKind.CharRange, value: ' -~' }],
    });

    return { name: 'HTTP', rules, startRule: 'request' };
  }

  /** Build an SQL query grammar. */
  static sqlGrammar(): Grammar {
    const rules = new Map<string, GrammarNode>();

    rules.set('query', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Reference, name: 'select' },
        { kind: NodeKind.Reference, name: 'insert' },
        { kind: NodeKind.Reference, name: 'update' },
        { kind: NodeKind.Reference, name: 'delete' },
      ],
    });

    rules.set('select', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: 'SELECT ' },
        { kind: NodeKind.Reference, name: 'columns' },
        { kind: NodeKind.Literal, value: ' FROM ' },
        { kind: NodeKind.Reference, name: 'tableName' },
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Literal, value: ' WHERE ' },
            { kind: NodeKind.Reference, name: 'condition' },
          ]},
        ]},
      ],
    });

    rules.set('insert', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: 'INSERT INTO ' },
        { kind: NodeKind.Reference, name: 'tableName' },
        { kind: NodeKind.Literal, value: ' VALUES (' },
        { kind: NodeKind.Reference, name: 'valueList' },
        { kind: NodeKind.Literal, value: ')' },
      ],
    });

    rules.set('update', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: 'UPDATE ' },
        { kind: NodeKind.Reference, name: 'tableName' },
        { kind: NodeKind.Literal, value: ' SET ' },
        { kind: NodeKind.Reference, name: 'columnName' },
        { kind: NodeKind.Literal, value: ' = ' },
        { kind: NodeKind.Reference, name: 'value' },
      ],
    });

    rules.set('delete', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Literal, value: 'DELETE FROM ' },
        { kind: NodeKind.Reference, name: 'tableName' },
        { kind: NodeKind.Optional, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Literal, value: ' WHERE ' },
            { kind: NodeKind.Reference, name: 'condition' },
          ]},
        ]},
      ],
    });

    rules.set('columns', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Literal, value: '*' },
        { kind: NodeKind.Reference, name: 'columnName' },
      ],
    });

    rules.set('condition', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Reference, name: 'columnName' },
        { kind: NodeKind.Alternative, children: [
          { kind: NodeKind.Literal, value: ' = ' },
          { kind: NodeKind.Literal, value: ' != ' },
          { kind: NodeKind.Literal, value: ' > ' },
          { kind: NodeKind.Literal, value: ' < ' },
          { kind: NodeKind.Literal, value: ' LIKE ' },
        ]},
        { kind: NodeKind.Reference, name: 'value' },
      ],
    });

    rules.set('tableName', {
      kind: NodeKind.Repeat, min: 3, max: 12,
      children: [{ kind: NodeKind.CharRange, value: 'a-z' }],
    });

    rules.set('columnName', {
      kind: NodeKind.Repeat, min: 2, max: 10,
      children: [{ kind: NodeKind.CharRange, value: 'a-z' }],
    });

    rules.set('value', {
      kind: NodeKind.Alternative,
      children: [
        { kind: NodeKind.Sequence, children: [
          { kind: NodeKind.Literal, value: "'" },
          { kind: NodeKind.Repeat, min: 1, max: 20, children: [
            { kind: NodeKind.CharRange, value: 'a-z' },
          ]},
          { kind: NodeKind.Literal, value: "'" },
        ]},
        { kind: NodeKind.Repeat, min: 1, max: 5, children: [
          { kind: NodeKind.CharRange, value: '0-9' },
        ]},
      ],
    });

    rules.set('valueList', {
      kind: NodeKind.Sequence,
      children: [
        { kind: NodeKind.Reference, name: 'value' },
        { kind: NodeKind.Repeat, min: 0, max: 5, children: [
          { kind: NodeKind.Sequence, children: [
            { kind: NodeKind.Literal, value: ', ' },
            { kind: NodeKind.Reference, name: 'value' },
          ]},
        ]},
      ],
    });

    return { name: 'SQL', rules, startRule: 'query' };
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────

function parseCharRange(spec: string): [number, number] {
  const match = spec.match(/^(.)-(.)/);
  if (match) {
    return [match[1]!.charCodeAt(0), match[2]!.charCodeAt(0)];
  }
  return [32, 126]; // printable ASCII
}

function weightedPick<T>(items: T[], weights: number[], prng: PRNG): T {
  let total = 0;
  for (const w of weights) total += w;
  let target = prng.nextFloat() * total;
  for (let i = 0; i < items.length; i++) {
    target -= weights[i]!;
    if (target <= 0) return items[i]!;
  }
  return items[items.length - 1]!;
}
