import { Row } from '../types';
import {
  KbEntry,
  QualysApiError,
  mapTasFinding,
  mapTasWebApp,
  nextIdMin,
  parseDetections,
  parseHosts,
  parseKnowledgeBase,
  parseQps,
  parseXml,
} from './parse';

export interface HttpRequest {
  method: 'GET' | 'POST';
  /** Path below the Qualys API base, e.g. /api/2.0/fo/asset/host/ */
  path: string;
  params?: Record<string, string>;
  body?: string;
  headers?: Record<string, string>;
}

export interface HttpResponse {
  status: number;
  data: string;
}

/** Transport; in Grafana this goes through the data source proxy. Must throw HttpError on non-2xx. */
export type HttpFn = (req: HttpRequest) => Promise<HttpResponse>;

export class HttpError extends Error {
  constructor(
    public status: number,
    public body: string,
    message?: string
  ) {
    super(message ?? `HTTP ${status}`);
  }
}

export interface ClientOptions {
  pageSize: number;
  maxPages: number;
  cacheTtlMs: number;
  concurrency: number;
  enrichKb: boolean;
  /** Delay function, overridable for tests. */
  sleep?: (ms: number) => Promise<void>;
}

export interface VmdrDetectionFilter {
  severities: string[];
  statuses: string[];
  vulnTypes: string[];
  qids?: string;
  ips?: string;
  tags?: string;
  includeIgnored?: boolean;
  includeDisabled?: boolean;
}

export interface VmdrHostFilter {
  ips?: string;
  tags?: string;
}

export interface TasFindingFilter {
  severities: string[];
  statuses: string[];
  types: string[];
  webAppName?: string;
  webAppTag?: string;
  includeIgnored?: boolean;
}

export interface TasWebAppFilter {
  webAppName?: string;
  webAppTag?: string;
}

const KB_TTL_MS = 12 * 3600 * 1000;
const KB_CHUNK = 250;

/** Simple FIFO semaphore to respect the Qualys concurrency limit. */
class Semaphore {
  private active = 0;
  private queue: Array<() => void> = [];
  constructor(private max: number) {}

  async run<T>(fn: () => Promise<T>): Promise<T> {
    if (this.active >= this.max) {
      await new Promise<void>((resolve) => this.queue.push(resolve));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.queue.shift()?.();
    }
  }
}

function errorText(body: string): string {
  const m = /<TEXT>([\s\S]*?)<\/TEXT>/.exec(body);
  if (m) {
    return m[1].replace(/<!\[CDATA\[|\]\]>/g, '').trim();
  }
  try {
    const j = JSON.parse(body);
    const msg = j?.ServiceResponse?.responseErrorDetails?.errorMessage ?? j?.message ?? j?.error;
    if (msg) {
      return String(msg);
    }
  } catch {
    // not JSON
  }
  return body.slice(0, 300);
}

function tagParams(tags: string | undefined, params: Record<string, string>) {
  if (tags && tags.trim()) {
    params.use_tags = '1';
    params.tag_set_by = 'name';
    params.tag_include_selector = 'any';
    params.tag_set_include = tags
      .split(',')
      .map((t) => t.trim())
      .filter(Boolean)
      .join(',');
  }
}

function csv(values: string[]): string {
  return values
    .map((v) => v.trim())
    .filter(Boolean)
    .join(',');
}

/**
 * Qualys API client. All data sets are cached for `cacheTtlMs`, keyed by the API filter,
 * so the many panels of a dashboard share a single download.
 */
export class QualysClient {
  private cache = new Map<string, { expires: number; promise: Promise<Row[]> }>();
  private kb = new Map<number, { expires: number; entry: KbEntry }>();
  private sem: Semaphore;
  private sleep: (ms: number) => Promise<void>;

  constructor(
    private http: HttpFn,
    private opts: ClientOptions
  ) {
    this.sem = new Semaphore(Math.max(1, opts.concurrency));
    this.sleep = opts.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms)));
  }

  clearCache() {
    this.cache.clear();
  }

  /** Performs a request honouring the concurrency limit and retrying on Qualys concurrency errors (HTTP 409). */
  async request(req: HttpRequest): Promise<string> {
    let attempt = 0;
    for (;;) {
      try {
        const res = await this.sem.run(() => this.http(req));
        return res.data;
      } catch (e) {
        if (e instanceof HttpError) {
          const msg = errorText(e.body);
          const isConcurrency = e.status === 409 && /concurren|1965|1920/i.test(e.body);
          if (isConcurrency && attempt < 4) {
            attempt++;
            await this.sleep(5000 * attempt);
            continue;
          }
          if (e.status === 401) {
            throw new QualysApiError('Qualys rejected the credentials (HTTP 401). Check user name and password.');
          }
          if (e.status === 409) {
            throw new QualysApiError(`Qualys API limit reached (HTTP 409): ${msg}`);
          }
          throw new QualysApiError(`Qualys API error (HTTP ${e.status}): ${msg}`);
        }
        throw e;
      }
    }
  }

  private cached(key: string, load: () => Promise<Row[]>): Promise<Row[]> {
    const now = Date.now();
    const hit = this.cache.get(key);
    if (hit && hit.expires > now) {
      return hit.promise;
    }
    const promise = load();
    this.cache.set(key, { expires: now + this.opts.cacheTtlMs, promise });
    promise.catch(() => this.cache.delete(key));
    return promise;
  }

  // ------------------------------------------------------------------ VMDR

  getDetections(f: VmdrDetectionFilter): Promise<Row[]> {
    const params: Record<string, string> = {
      action: 'list',
      output_format: 'XML',
      show_results: '0',
      show_tags: '1',
      show_qds: '1',
      truncation_limit: String(this.opts.pageSize),
    };
    const statuses = csv(f.statuses);
    if (statuses) {
      params.status = statuses;
    }
    const sev = csv(f.severities);
    if (sev) {
      params.severities = sev;
    }
    const types = f.vulnTypes.map((t) => t.toLowerCase());
    const confirmed = types.includes('confirmed');
    const potential = types.includes('potential');
    if (confirmed !== potential) {
      params.include_vuln_type = confirmed ? 'confirmed' : 'potential';
    }
    if (types.includes('info')) {
      params.show_igs = '1';
    }
    if (f.qids?.trim()) {
      params.qids = f.qids.replace(/\s+/g, '');
    }
    if (f.ips?.trim()) {
      params.ips = f.ips.replace(/\s+/g, '');
    }
    tagParams(f.tags, params);
    if (f.includeIgnored) {
      params.include_ignored = '1';
    }
    if (f.includeDisabled) {
      params.include_disabled = '1';
    }

    const key = 'vmdr_detections:' + JSON.stringify(params) + ':' + types.join(',');
    return this.cached(key, async () => {
      const rows = await this.paginateXml('/api/2.0/fo/asset/host/vm/detection/', params, parseDetections);
      // Client-side safety net for the vuln type selection (API can't express every combination).
      const wanted = new Set(types.map((t) => (t === 'info' ? 'info' : t)));
      const filtered = wanted.size
        ? rows.filter((r) => {
            const t = String(r.type ?? '').toLowerCase();
            return wanted.has(t === 'ig' ? 'info' : t);
          })
        : rows;
      if (this.opts.enrichKb) {
        await this.enrich(filtered);
      }
      return filtered;
    });
  }

  getHosts(f: VmdrHostFilter): Promise<Row[]> {
    const params: Record<string, string> = {
      action: 'list',
      details: 'All',
      show_tags: '1',
      truncation_limit: String(this.opts.pageSize),
    };
    if (f.ips?.trim()) {
      params.ips = f.ips.replace(/\s+/g, '');
    }
    tagParams(f.tags, params);
    const key = 'vmdr_hosts:' + JSON.stringify(params);
    return this.cached(key, () => this.paginateXml('/api/2.0/fo/asset/host/', params, parseHosts));
  }

  private async paginateXml(
    path: string,
    baseParams: Record<string, string>,
    parse: (doc: Document) => Row[]
  ): Promise<Row[]> {
    const all: Row[] = [];
    let idMin: string | undefined;
    for (let page = 0; page < this.opts.maxPages; page++) {
      const params = idMin ? { ...baseParams, id_min: idMin } : baseParams;
      const doc = parseXml(await this.request({ method: 'GET', path, params }));
      const rows = parse(doc);
      for (const r of rows) {
        all.push(r);
      }
      idMin = nextIdMin(doc);
      if (!idMin) {
        return all;
      }
    }
    console.warn(`[qualys] stopped after maxPages=${this.opts.maxPages} pages for ${path}; data is incomplete`);
    return all;
  }

  /** Adds title, category, CVEs, CVSS, RTI and patchable from the KnowledgeBase (cached for 12h). */
  async enrich(rows: Row[]) {
    const now = Date.now();
    const missing = new Set<number>();
    for (const r of rows) {
      const q = r.qid as number | null;
      if (q !== null && q !== undefined) {
        const hit = this.kb.get(q);
        if (!hit || hit.expires < now) {
          missing.add(q);
        }
      }
    }
    const ids = [...missing];
    const chunks: number[][] = [];
    for (let i = 0; i < ids.length; i += KB_CHUNK) {
      chunks.push(ids.slice(i, i + KB_CHUNK));
    }
    await Promise.all(
      chunks.map(async (chunk) => {
        const doc = parseXml(
          await this.request({
            method: 'GET',
            path: '/api/2.0/fo/knowledge_base/vuln/',
            params: { action: 'list', details: 'All', ids: chunk.join(',') },
          })
        );
        for (const [qid, entry] of parseKnowledgeBase(doc)) {
          this.kb.set(qid, { expires: now + KB_TTL_MS, entry });
        }
      })
    );
    for (const r of rows) {
      const e = this.kb.get(r.qid as number)?.entry;
      if (e) {
        r.title = e.title;
        r.category = e.category;
        r.cves = e.cves;
        r.rti = e.rti;
        r.cvss3 = e.cvss3;
        r.patchable = e.patchable;
      }
    }
  }

  // ------------------------------------------------------------------- TAS

  getTasFindings(f: TasFindingFilter): Promise<Row[]> {
    const criteria: Array<{ field: string; operator: string; value: string }> = [];
    const statuses = csv(f.statuses);
    if (statuses) {
      criteria.push({ field: 'status', operator: 'IN', value: statuses });
    }
    const sev = csv(f.severities);
    if (sev) {
      criteria.push({ field: 'severity', operator: 'IN', value: sev });
    }
    const types = csv(f.types);
    if (types) {
      criteria.push({ field: 'type', operator: 'IN', value: types });
    }
    if (f.webAppName?.trim()) {
      criteria.push({ field: 'webApp.name', operator: 'CONTAINS', value: f.webAppName.trim() });
    }
    if (f.webAppTag?.trim()) {
      criteria.push({ field: 'webApp.tags.name', operator: 'EQUALS', value: f.webAppTag.trim() });
    }
    if (!f.includeIgnored) {
      criteria.push({ field: 'isIgnored', operator: 'EQUALS', value: 'false' });
    }
    const key = 'tas_findings:' + JSON.stringify(criteria);
    return this.cached(key, async () => {
      const now = Date.now();
      const items = await this.paginateQps('/qps/rest/3.0/search/was/finding', 'Finding', criteria);
      return items.map((i) => mapTasFinding(i, now));
    });
  }

  getTasWebApps(f: TasWebAppFilter): Promise<Row[]> {
    const criteria: Array<{ field: string; operator: string; value: string }> = [];
    if (f.webAppName?.trim()) {
      criteria.push({ field: 'name', operator: 'CONTAINS', value: f.webAppName.trim() });
    }
    if (f.webAppTag?.trim()) {
      criteria.push({ field: 'tags.name', operator: 'EQUALS', value: f.webAppTag.trim() });
    }
    const key = 'tas_webapps:' + JSON.stringify(criteria);
    return this.cached(key, async () => {
      const items = await this.paginateQps('/qps/rest/3.0/search/was/webapp', 'WebApp', criteria);
      return items.map(mapTasWebApp);
    });
  }

  private async paginateQps(
    path: string,
    entity: string,
    criteria: Array<{ field: string; operator: string; value: string }>
  ): Promise<Array<Record<string, any>>> {
    const all: Array<Record<string, any>> = [];
    let lastId: number | null = null;
    const limit = Math.min(1000, this.opts.pageSize);
    for (let page = 0; page < this.opts.maxPages; page++) {
      const crit =
        lastId !== null ? [...criteria, { field: 'id', operator: 'GREATER', value: String(lastId) }] : criteria;
      const body = {
        ServiceRequest: {
          preferences: { verbose: 'true', limitResults: String(limit) },
          ...(crit.length ? { filters: { Criteria: crit } } : {}),
        },
      };
      const text = await this.request({
        method: 'POST',
        path,
        body: JSON.stringify(body),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      });
      const res = parseQps(text, entity);
      all.push(...res.items);
      if (!res.hasMore) {
        return all;
      }
      const maxId = res.items.reduce((m, i) => Math.max(m, Number(i.id) || 0), 0);
      const next = res.lastId ?? (maxId || null);
      if (next === null || next === lastId) {
        return all;
      }
      lastId = next;
    }
    console.warn(`[qualys] stopped after maxPages=${this.opts.maxPages} pages for ${path}; data is incomplete`);
    return all;
  }

  // ---------------------------------------------------------------- health

  async testVmdr(): Promise<string> {
    const doc = parseXml(
      await this.request({
        method: 'GET',
        path: '/api/2.0/fo/asset/host/',
        params: { action: 'list', truncation_limit: '1', details: 'Basic' },
      })
    );
    parseHosts(doc);
    return 'VMDR API OK';
  }

  async testTas(): Promise<string> {
    const text = await this.request({
      method: 'POST',
      path: '/qps/rest/3.0/search/was/webapp',
      body: JSON.stringify({ ServiceRequest: { preferences: { verbose: 'false', limitResults: '1' } } }),
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
    });
    parseQps(text, 'WebApp');
    return 'TotalAppSec (WAS) API OK';
  }
}
