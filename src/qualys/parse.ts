import { Row } from '../types';
import { ageBucket } from './fields';

// ---------------------------------------------------------------------------
// Small XML helpers (DOMParser is available in every browser and in jsdom)
// ---------------------------------------------------------------------------

export class QualysApiError extends Error {
  constructor(
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = 'QualysApiError';
  }
}

export function parseXml(text: string): Document {
  const doc = new DOMParser().parseFromString(text, 'application/xml');
  const err = doc.getElementsByTagName('parsererror')[0];
  if (err) {
    const snippet = text.slice(0, 200).replace(/\s+/g, ' ');
    throw new QualysApiError(`Qualys returned no valid XML: ${snippet}`);
  }
  return doc;
}

function child(el: Element | null | undefined, name: string): Element | undefined {
  if (!el) {
    return undefined;
  }
  for (let i = 0; i < el.children.length; i++) {
    if (el.children[i].tagName === name) {
      return el.children[i];
    }
  }
  return undefined;
}

function children(el: Element | null | undefined, name: string): Element[] {
  const out: Element[] = [];
  if (!el) {
    return out;
  }
  for (let i = 0; i < el.children.length; i++) {
    if (el.children[i].tagName === name) {
      out.push(el.children[i]);
    }
  }
  return out;
}

function text(el: Element | null | undefined, name: string): string | undefined {
  const c = child(el, name);
  const t = c?.textContent?.trim();
  return t === undefined || t === '' ? undefined : t;
}

function num(v: unknown): number | null {
  if (v === undefined || v === null || v === '') {
    return null;
  }
  const n = Number(v);
  return isNaN(n) ? null : n;
}

export function toTime(v: unknown): number | null {
  if (v === undefined || v === null || v === '') {
    return null;
  }
  if (typeof v === 'number') {
    return v;
  }
  const t = Date.parse(String(v));
  return isNaN(t) ? null : t;
}

function bool(v: unknown): boolean {
  return v === true || v === '1' || v === 1 || v === 'true' || v === 'TRUE';
}

const DAY = 24 * 3600 * 1000;

function ageDays(first: number | null, fixed: number | null, status: string | undefined, now: number): number | null {
  if (first === null) {
    return null;
  }
  const end = status && status.toUpperCase() === 'FIXED' && fixed !== null ? fixed : now;
  return Math.max(0, Math.floor((end - first) / DAY));
}

/** Throws for <SIMPLE_RETURN> error documents. */
export function assertNoSimpleReturnError(doc: Document) {
  const root = doc.documentElement;
  if (root?.tagName === 'SIMPLE_RETURN') {
    const resp = child(root, 'RESPONSE');
    const code = text(resp, 'CODE');
    const msg = text(resp, 'TEXT') ?? 'Unknown Qualys error';
    throw new QualysApiError(code ? `Qualys error ${code}: ${msg}` : msg, code);
  }
}

/** Extracts the id_min of the next page from the truncation <WARNING>. */
export function nextIdMin(doc: Document): string | undefined {
  const resp = child(doc.documentElement, 'RESPONSE');
  const warning = child(resp, 'WARNING');
  const url = text(warning, 'URL');
  if (!url) {
    return undefined;
  }
  const m = /[?&]id_min=([^&]+)/.exec(url);
  return m ? decodeURIComponent(m[1]) : undefined;
}

function hostBase(host: Element): Row {
  const ip = text(host, 'IP') ?? text(host, 'IPV6');
  const dns = text(host, 'DNS') ?? text(child(host, 'DNS_DATA'), 'FQDN') ?? text(child(host, 'DNS_DATA'), 'HOSTNAME');
  const netbios = text(host, 'NETBIOS');
  const tags = children(child(host, 'TAGS'), 'TAG')
    .map((t) => text(t, 'NAME'))
    .filter((t): t is string => !!t);
  return {
    host_id: num(text(host, 'ID')),
    ip: ip ?? null,
    dns: dns ?? null,
    netbios: netbios ?? null,
    host: dns || netbios || ip || null,
    os: text(host, 'OS') ?? null,
    tracking_method: text(host, 'TRACKING_METHOD') ?? null,
    tags,
  };
}

// ---------------------------------------------------------------------------
// VMDR
// ---------------------------------------------------------------------------

/** Parses /api/2.0/fo/asset/host/vm/detection/ output into one row per detection. */
export function parseDetections(doc: Document, now = Date.now()): Row[] {
  assertNoSimpleReturnError(doc);
  const rows: Row[] = [];
  const resp = child(doc.documentElement, 'RESPONSE');
  for (const host of children(child(resp, 'HOST_LIST'), 'HOST')) {
    const base = hostBase(host);
    for (const det of children(child(host, 'DETECTION_LIST'), 'DETECTION')) {
      const status = text(det, 'STATUS');
      const first = toTime(text(det, 'FIRST_FOUND_DATETIME'));
      const fixed = toTime(text(det, 'LAST_FIXED_DATETIME'));
      const qdsEl = child(det, 'QDS');
      const age = ageDays(first, fixed, status, now);
      rows.push({
        ...base,
        tags: [...((base.tags as string[]) ?? [])],
        qid: num(text(det, 'QID')),
        type: text(det, 'TYPE') ?? null,
        severity: num(text(det, 'SEVERITY')),
        port: num(text(det, 'PORT')),
        protocol: text(det, 'PROTOCOL') ?? null,
        ssl: bool(text(det, 'SSL')),
        status: status ?? null,
        first_found: first,
        last_found: toTime(text(det, 'LAST_FOUND_DATETIME')),
        last_fixed: fixed,
        times_found: num(text(det, 'TIMES_FOUND')),
        qds: num(qdsEl?.textContent?.trim()),
        qds_severity: qdsEl?.getAttribute('severity') ?? null,
        is_ignored: bool(text(det, 'IS_IGNORED')),
        is_disabled: bool(text(det, 'IS_DISABLED')),
        age_days: age,
        age_bucket: ageBucket(age),
        // filled by KnowledgeBase enrichment
        title: null,
        category: null,
        cves: [],
        rti: [],
        cvss3: null,
        patchable: null,
      });
    }
  }
  return rows;
}

/** Parses /api/2.0/fo/asset/host/ output (with show_tags=1). */
export function parseHosts(doc: Document, now = Date.now()): Row[] {
  assertNoSimpleReturnError(doc);
  const resp = child(doc.documentElement, 'RESPONSE');
  return children(child(resp, 'HOST_LIST'), 'HOST').map((host) => {
    const lastScan = toTime(text(host, 'LAST_VULN_SCAN_DATETIME') ?? text(host, 'LAST_SCAN_DATETIME'));
    return {
      ...hostBase(host),
      last_vuln_scan: lastScan,
      last_activity: toTime(text(host, 'LAST_ACTIVITY') ?? text(host, 'LAST_ACTIVITY_DATETIME')),
      scan_age_days: lastScan === null ? null : Math.max(0, Math.floor((now - lastScan) / DAY)),
    };
  });
}

export interface KbEntry {
  title: string | null;
  category: string | null;
  cves: string[];
  rti: string[];
  cvss3: number | null;
  patchable: string | null;
}

/** Parses /api/2.0/fo/knowledge_base/vuln/ output. */
export function parseKnowledgeBase(doc: Document): Map<number, KbEntry> {
  assertNoSimpleReturnError(doc);
  const out = new Map<number, KbEntry>();
  const resp = child(doc.documentElement, 'RESPONSE');
  for (const v of children(child(resp, 'VULN_LIST'), 'VULN')) {
    const qid = num(text(v, 'QID'));
    if (qid === null) {
      continue;
    }
    const cves = children(child(v, 'CVE_LIST'), 'CVE')
      .map((c) => text(c, 'ID'))
      .filter((c): c is string => !!c);
    const rti = children(child(v, 'THREAT_INTELLIGENCE'), 'THREAT_INTEL')
      .map((t) => t.textContent?.trim())
      .filter((t): t is string => !!t);
    const patchable = text(v, 'PATCHABLE');
    out.set(qid, {
      title: text(v, 'TITLE') ?? null,
      category: text(v, 'CATEGORY') ?? null,
      cves,
      rti,
      cvss3: num(text(child(v, 'CVSS_V3'), 'BASE')),
      patchable: patchable === undefined ? null : bool(patchable) ? 'Yes' : 'No',
    });
  }
  return out;
}

// ---------------------------------------------------------------------------
// TAS (TotalAppSec) – WAS QPS REST API, JSON flavour
// ---------------------------------------------------------------------------

interface QpsResponse {
  ServiceResponse?: {
    responseCode?: string;
    count?: number | string;
    hasMoreRecords?: string | boolean;
    lastId?: number | string;
    data?: Array<Record<string, any>>;
    responseErrorDetails?: { errorMessage?: string; errorResolution?: string };
  };
}

export interface QpsPage<T> {
  items: T[];
  hasMore: boolean;
  lastId: number | null;
  count: number;
}

export function parseQps(json: unknown, entity: string): QpsPage<Record<string, any>> {
  const body: QpsResponse = typeof json === 'string' ? JSON.parse(json) : (json as QpsResponse);
  const sr = body?.ServiceResponse;
  if (!sr) {
    throw new QualysApiError('Unexpected response from the Qualys QPS API (no ServiceResponse).');
  }
  if (sr.responseCode && sr.responseCode !== 'SUCCESS') {
    const details = sr.responseErrorDetails;
    throw new QualysApiError(
      `Qualys ${sr.responseCode}: ${details?.errorMessage ?? 'request failed'}${
        details?.errorResolution ? ` (${details.errorResolution})` : ''
      }`,
      sr.responseCode
    );
  }
  const items = (sr.data ?? []).map((d) => d?.[entity]).filter(Boolean);
  return {
    items,
    hasMore: bool(sr.hasMoreRecords),
    lastId: num(sr.lastId),
    count: num(sr.count) ?? items.length,
  };
}

/** QPS lists look like { count: 2, list: [ { Tag: {...} }, ... ] } – unwrap them. */
function qpsList(v: any, entity?: string): any[] {
  if (!v) {
    return [];
  }
  const list = Array.isArray(v) ? v : Array.isArray(v.list) ? v.list : [];
  return list.map((x: any) => (entity && x && typeof x === 'object' && entity in x ? x[entity] : x));
}

function names(v: any, entity: string, fmt: (x: any) => string | undefined): string[] {
  return qpsList(v, entity)
    .map((x) => (x === null || x === undefined ? undefined : typeof x === 'object' ? fmt(x) : String(x)))
    .filter((x): x is string => !!x);
}

export function mapTasFinding(f: Record<string, any>, now = Date.now()): Row {
  const status: string | undefined = f.status;
  const first = toTime(f.firstDetectedDate);
  const fixed = toTime(f.fixedDate ?? f.lastFixedDate);
  const age = ageDays(first, fixed, status, now);
  const owasp = names(f.owasp, 'OWASP', (o) =>
    o.code ? `A${String(o.code).padStart(2, '0')} ${o.name ?? ''}`.trim() : o.name
  );
  const wasc = names(f.wasc, 'WASC', (w) => (w.code ? `WASC-${w.code} ${w.name ?? ''}`.trim() : w.name));
  const cwe = names(f.cwe, 'CWE', (c) => (c.id ? `CWE-${c.id}` : undefined)).map((c) =>
    /^\d+$/.test(c) ? `CWE-${c}` : c
  );
  return {
    finding_id: num(f.id),
    unique_id: f.uniqueId ?? null,
    qid: num(f.qid),
    name: f.name ?? null,
    type: f.type ?? null,
    finding_type: f.findingType ?? null,
    group: f.group ?? null,
    severity: num(f.severity),
    status: status ?? null,
    potential: f.potential === undefined ? null : bool(f.potential) ? 'Yes' : 'No',
    url: f.url ?? null,
    webapp: f.webApp?.name ?? null,
    webapp_id: num(f.webApp?.id),
    webapp_url: f.webApp?.url ?? null,
    webapp_tags: names(f.webApp?.tags, 'Tag', (t) => t.name),
    owasp,
    wasc,
    cwe,
    cvss3: num(f.cvssV3?.base),
    first_found: first,
    last_found: toTime(f.lastDetectedDate),
    last_tested: toTime(f.lastTestedDate),
    last_fixed: fixed,
    times_detected: num(f.timesDetected),
    age_days: age,
    age_bucket: ageBucket(age),
    is_ignored: bool(f.isIgnored),
  };
}

export function mapTasWebApp(w: Record<string, any>): Row {
  const lastScan = w.lastScan ?? {};
  return {
    webapp_id: num(w.id),
    webapp: w.name ?? null,
    url: w.url ?? null,
    tags: names(w.tags, 'Tag', (t) => t.name),
    owner: w.owner ? [w.owner.firstName, w.owner.lastName].filter(Boolean).join(' ') || w.owner.username || null : null,
    created: toTime(w.createdDate),
    updated: toTime(w.updatedDate),
    last_scan: toTime(lastScan.launchedDate ?? lastScan.summary?.launchedDate ?? lastScan.endScanDate),
    last_scan_status: lastScan.status ?? lastScan.summary?.resultsStatus ?? null,
  };
}
