import { DataFrame, FieldType, createDataFrame } from '@grafana/data';

import { FieldDef, Metric, QualysQuery, QueryType, Row } from '../types';
import { AGE_BUCKETS, DEFAULT_DISTINCT, FIELDS, fieldDef, severityLabel } from './fields';

const NONE = '(none)';
const DAY = 24 * 3600 * 1000;

// ---------------------------------------------------------------------------
// Filter expressions:  status=Fixed; severity>=4; os~windows; tags!=DMZ
// Conditions are AND-combined (separated by ";" or newlines). "=" and "!=" accept
// comma separated value lists. "~" / "!~" are case-insensitive "contains".
// ---------------------------------------------------------------------------

type Op = '=' | '!=' | '>=' | '<=' | '>' | '<' | '~' | '!~';

interface Condition {
  field: string;
  op: Op;
  values: string[];
}

export function parseFilter(expr: string | undefined): Condition[] {
  if (!expr || !expr.trim()) {
    return [];
  }
  return expr
    .split(/;|\n|\s+AND\s+/i)
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      const m = /^([\w.]+)\s*(!=|>=|<=|!~|=|>|<|~)\s*(.*)$/.exec(part);
      if (!m) {
        throw new Error(`Invalid filter condition "${part}". Expected e.g. severity>=4 or status=New,Active`);
      }
      const raw = m[3].trim().replace(/^["']|["']$/g, '');
      return {
        field: m[1],
        op: m[2] as Op,
        values: m[2] === '=' || m[2] === '!=' ? raw.split(',').map((v) => v.trim()) : [raw],
      };
    });
}

function cmp(a: unknown, b: string): number {
  const na = Number(a);
  const nb = Number(b);
  if (a !== null && a !== '' && b !== '' && !isNaN(na) && !isNaN(nb)) {
    return na - nb;
  }
  return String(a ?? '').localeCompare(b, undefined, { sensitivity: 'base' });
}

function matchOne(v: unknown, c: Condition): boolean {
  const s = v === null || v === undefined ? '' : String(v);
  switch (c.op) {
    case '=':
      return c.values.some((x) =>
        x === '' || x === NONE ? s === '' : s !== '' && (cmp(v, x) === 0 || s.toLowerCase() === x.toLowerCase())
      );
    case '~':
      return s.toLowerCase().includes(c.values[0].toLowerCase());
    case '>':
      return v !== null && v !== undefined && cmp(v, c.values[0]) > 0;
    case '>=':
      return v !== null && v !== undefined && cmp(v, c.values[0]) >= 0;
    case '<':
      return v !== null && v !== undefined && cmp(v, c.values[0]) < 0;
    case '<=':
      return v !== null && v !== undefined && cmp(v, c.values[0]) <= 0;
    default:
      return false;
  }
}

function matches(row: Row, c: Condition): boolean {
  const v = row[c.field];
  const vals = Array.isArray(v) ? (v.length ? v : [null]) : [v];
  if (c.op === '!=') {
    return !vals.some((x) => matchOne(x, { ...c, op: '=' }));
  }
  if (c.op === '!~') {
    return !vals.some((x) => matchOne(x, { ...c, op: '~' }));
  }
  return vals.some((x) => matchOne(x, c));
}

export function applyFilter(rows: Row[], expr: string | undefined): Row[] {
  const conds = parseFilter(expr);
  if (!conds.length) {
    return rows;
  }
  return rows.filter((r) => conds.every((c) => matches(r, c)));
}

export function applyRange(rows: Row[], field: string | undefined, from: number, to: number): Row[] {
  if (!field) {
    return rows;
  }
  return rows.filter((r) => {
    const t = r[field] as number | null;
    return typeof t === 'number' && t >= from && t <= to;
  });
}

// ---------------------------------------------------------------------------
// Aggregation
// ---------------------------------------------------------------------------

export function aggregate(rows: Row[], metric: Metric, field: string | undefined): number | null {
  if (metric === 'count') {
    return rows.length;
  }
  const f = field || '';
  if (metric === 'distinct') {
    const set = new Set<unknown>();
    for (const r of rows) {
      const v = r[f];
      if (Array.isArray(v)) {
        v.forEach((x) => set.add(x));
      } else if (v !== null && v !== undefined && v !== '') {
        set.add(v);
      }
    }
    return set.size;
  }
  const nums = rows.map((r) => Number(r[f])).filter((n) => isNum(n));
  if (!nums.length) {
    return null;
  }
  switch (metric) {
    case 'sum':
      return nums.reduce((a, b) => a + b, 0);
    case 'avg':
      return Math.round((nums.reduce((a, b) => a + b, 0) / nums.length) * 10) / 10;
    case 'max':
      return Math.max(...nums);
    case 'min':
      return Math.min(...nums);
    default:
      return null;
  }
}

function isNum(n: number) {
  return typeof n === 'number' && !isNaN(n) && isFinite(n);
}

function metricField(q: QualysQuery): string | undefined {
  if (q.metric === 'distinct') {
    return q.metricField || DEFAULT_DISTINCT[q.queryType];
  }
  return q.metricField;
}

function valuesOf(row: Row, field: string): string[] {
  const v = row[field];
  if (Array.isArray(v)) {
    return v.length ? v.map((x) => labelFor(field, x)) : [NONE];
  }
  return [labelFor(field, v)];
}

function labelFor(field: string, v: unknown): string {
  if (v === null || v === undefined || v === '') {
    return NONE;
  }
  if (field === 'severity') {
    return severityLabel(v);
  }
  if (typeof v === 'boolean') {
    return v ? 'Yes' : 'No';
  }
  return String(v);
}

/** Natural ordering for a few well known fields, otherwise undefined (=> sort by value). */
function orderFor(field: string): ((a: string, b: string) => number) | undefined {
  if (field === 'severity') {
    return (a, b) => b.localeCompare(a);
  }
  if (field === 'age_bucket') {
    return (a, b) => AGE_BUCKETS.indexOf(a) - AGE_BUCKETS.indexOf(b);
  }
  return undefined;
}

function groupRows(rows: Row[], field: string): Map<string, Row[]> {
  const groups = new Map<string, Row[]>();
  for (const r of rows) {
    for (const key of new Set(valuesOf(r, field))) {
      let g = groups.get(key);
      if (!g) {
        g = [];
        groups.set(key, g);
      }
      g.push(r);
    }
  }
  return groups;
}

function splitKeys(rows: Row[], splitBy: string): string[] {
  const keys = [...groupRows(rows, splitBy).keys()];
  const order = orderFor(splitBy);
  return order ? keys.sort(order) : keys.sort();
}

function metricName(q: QualysQuery): string {
  const m = q.metric ?? 'count';
  if (m === 'count') {
    return 'count';
  }
  return `${m}_${metricField(q) ?? ''}`;
}

// ---------------------------------------------------------------------------
// Frame builders
// ---------------------------------------------------------------------------

function fieldType(def: FieldDef | undefined): FieldType {
  switch (def?.kind) {
    case 'number':
      return FieldType.number;
    case 'time':
      return FieldType.time;
    case 'boolean':
      return FieldType.boolean;
    default:
      return FieldType.string;
  }
}

export function toTable(rows: Row[], q: QualysQuery): DataFrame {
  const defs = FIELDS[q.queryType];
  const cols = q.columns?.length ? q.columns : defs.filter((d) => d.default).map((d) => d.name);
  const sorted = [...rows].sort((a, b) => {
    const s = Number(b.severity ?? 0) - Number(a.severity ?? 0);
    if (s !== 0) {
      return s;
    }
    return Number(b.last_found ?? 0) - Number(a.last_found ?? 0);
  });
  const limited = q.limit && q.limit > 0 ? sorted.slice(0, q.limit) : sorted;
  return createDataFrame({
    refId: q.refId,
    meta: { preferredVisualisationType: 'table' },
    fields: cols.map((name) => {
      const def = fieldDef(q.queryType, name);
      return {
        name,
        type: fieldType(def),
        values: limited.map((r) => {
          const v = r[name];
          if (Array.isArray(v)) {
            return v.join(', ');
          }
          return v === undefined ? null : v;
        }),
        config: def?.description ? { description: def.description } : {},
      };
    }),
  });
}

export function toCount(rows: Row[], q: QualysQuery): DataFrame {
  const metric = q.metric ?? 'count';
  const field = metricField(q);
  if (!q.splitBy) {
    return createDataFrame({
      refId: q.refId,
      fields: [{ name: metricName(q), type: FieldType.number, values: [aggregate(rows, metric, field)] }],
    });
  }
  const groups = groupRows(rows, q.splitBy);
  return createDataFrame({
    refId: q.refId,
    fields: splitKeys(rows, q.splitBy).map((k) => ({
      name: k,
      type: FieldType.number,
      values: [aggregate(groups.get(k) ?? [], metric, field)],
    })),
  });
}

export function toGroupBy(rows: Row[], q: QualysQuery): DataFrame {
  const by = q.groupBy || 'severity';
  const metric = q.metric ?? 'count';
  const field = metricField(q);
  const groups = groupRows(rows, by);
  let keys = [...groups.keys()];
  const totals = new Map(keys.map((k) => [k, aggregate(groups.get(k)!, metric, field) ?? 0]));
  const order = orderFor(by);
  keys = order ? keys.sort(order) : keys.sort((a, b) => totals.get(b)! - totals.get(a)! || a.localeCompare(b));
  if (q.limit && q.limit > 0) {
    keys = keys.slice(0, q.limit);
  }

  const fields: DataFrame['fields'] = [{ name: by, type: FieldType.string, values: keys, config: {} }];
  if (q.splitBy) {
    const splits = splitKeys(rows, q.splitBy);
    for (const s of splits) {
      fields.push({
        name: s,
        type: FieldType.number,
        values: keys.map((k) => {
          const sub = groups.get(k)!.filter((r) => valuesOf(r, q.splitBy!).includes(s));
          return aggregate(sub, metric, field) ?? 0;
        }),
        config: {},
      });
    }
  } else {
    fields.push({ name: metricName(q), type: FieldType.number, values: keys.map((k) => totals.get(k)), config: {} });
  }
  return createDataFrame({ refId: q.refId, fields });
}

/** Picks a bucket size that keeps the series readable. */
export function bucketSize(from: number, to: number): number {
  const span = to - from;
  if (span <= 2 * DAY) {
    return 3600 * 1000;
  }
  if (span <= 120 * DAY) {
    return DAY;
  }
  if (span <= 730 * DAY) {
    return 7 * DAY;
  }
  return 30 * DAY;
}

export function toTimeSeries(rows: Row[], q: QualysQuery, from: number, to: number): DataFrame {
  const step = bucketSize(from, to);
  const start = Math.floor(from / step) * step;
  const buckets: number[] = [];
  for (let t = start; t <= to; t += step) {
    buckets.push(t);
  }
  const metric = q.metric ?? 'count';
  const field = metricField(q);
  const timeField = q.timeField || 'first_found';

  const series: Array<{ name: string; rows: Row[] }> = q.splitBy
    ? (() => {
        const g = groupRows(rows, q.splitBy!);
        return splitKeys(rows, q.splitBy!).map((k) => ({ name: k, rows: g.get(k)! }));
      })()
    : [{ name: metricName(q), rows }];

  const fields: DataFrame['fields'] = [{ name: 'Time', type: FieldType.time, values: buckets, config: {} }];

  for (const s of series) {
    let values: Array<number | null>;
    if (timeField === 'open_backlog') {
      // number of findings open at the end of every bucket
      values = buckets.map((b) => {
        const end = Math.min(b + step, to);
        const open = s.rows.filter((r) => {
          const first = r.first_found as number | null;
          if (first === null || first === undefined || first > end) {
            return false;
          }
          const closed = String(r.status ?? '').toUpperCase() === 'FIXED' ? (r.last_fixed as number | null) : null;
          return closed === null || closed === undefined || closed > end;
        });
        return aggregate(open, metric, field);
      });
    } else {
      const perBucket = new Map<number, Row[]>();
      for (const r of s.rows) {
        const t = r[timeField];
        if (typeof t !== 'number' || t < from || t > to) {
          continue;
        }
        const b = Math.floor(t / step) * step;
        let arr = perBucket.get(b);
        if (!arr) {
          arr = [];
          perBucket.set(b, arr);
        }
        arr.push(r);
      }
      values = buckets.map((b) => {
        const arr = perBucket.get(b);
        if (!arr) {
          return metric === 'count' || metric === 'distinct' ? 0 : null;
        }
        return aggregate(arr, metric, field);
      });
    }
    fields.push({ name: s.name, type: FieldType.number, values, config: {} });
  }
  return createDataFrame({ refId: q.refId, fields });
}

export function toFrame(rows: Row[], q: QualysQuery, from: number, to: number): DataFrame {
  switch (q.format) {
    case 'count':
      return toCount(rows, q);
    case 'groupBy':
      return toGroupBy(rows, q);
    case 'timeseries':
      return toTimeSeries(rows, q, from, to);
    default:
      return toTable(rows, q);
  }
}

export function distinctValues(rows: Row[], field: string): string[] {
  const set = new Set<string>();
  for (const r of rows) {
    const v = r[field];
    for (const x of Array.isArray(v) ? v : [v]) {
      if (x !== null && x !== undefined && x !== '') {
        set.add(String(x));
      }
    }
  }
  return [...set].sort((a, b) => a.localeCompare(b));
}

export function isQueryType(v: string): v is QueryType {
  return v in FIELDS;
}
