import { HttpError, HttpRequest, QualysClient } from './client';
import { parseDetections, parseXml, mapTasFinding, QualysApiError } from './parse';
import { applyFilter, toCount, toGroupBy, toTable, toTimeSeries } from './transform';
import {
  DETECTIONS_PAGE_1,
  DETECTIONS_PAGE_2,
  HOSTS,
  KB,
  SIMPLE_RETURN_ERROR,
  TAS_ERROR,
  TAS_FINDINGS_PAGE_1,
  TAS_FINDINGS_PAGE_2,
} from './__fixtures__/samples';
import { QualysQuery } from '../types';

const NOW = Date.parse('2026-10-01T00:00:00Z');

function fakeHttp(handler: (req: HttpRequest) => string | HttpError) {
  const calls: HttpRequest[] = [];
  const fn = async (req: HttpRequest) => {
    calls.push(req);
    const res = handler(req);
    if (res instanceof HttpError) {
      throw res;
    }
    return { status: 200, data: res };
  };
  return { fn, calls };
}

const opts = { pageSize: 1, maxPages: 10, cacheTtlMs: 60000, concurrency: 2, enrichKb: true, sleep: async () => {} };

function vmdrHandler(req: HttpRequest) {
  if (req.path.includes('knowledge_base')) {
    return KB;
  }
  if (req.path.includes('detection')) {
    return req.params?.id_min === '1002' ? DETECTIONS_PAGE_2 : DETECTIONS_PAGE_1;
  }
  return HOSTS;
}

const q = (p: Partial<QualysQuery>): QualysQuery => ({
  refId: 'A',
  queryType: 'vmdr_detections',
  format: 'table',
  ...p,
});

describe('VMDR parsing', () => {
  it('parses detections with host data', () => {
    const rows = parseDetections(parseXml(DETECTIONS_PAGE_1), NOW);
    expect(rows).toHaveLength(2);
    expect(rows[0]).toMatchObject({
      host: 'srv-app01.corp.local',
      ip: '10.0.0.10',
      os: 'Windows Server 2019',
      qid: 91234,
      severity: 5,
      status: 'Active',
      qds: 95,
      qds_severity: 'CRITICAL',
      tags: ['Server', 'DMZ'],
      age_days: 61,
      age_bucket: '61-90 days',
    });
    expect(rows[1]).toMatchObject({ port: 443, ssl: true, type: 'Potential' });
  });

  it('computes the age of fixed detections until the fix date', () => {
    const rows = parseDetections(parseXml(DETECTIONS_PAGE_2), NOW);
    expect(rows[0]).toMatchObject({ status: 'Fixed', age_days: 41, host: '10.0.0.20' });
  });

  it('throws Qualys SIMPLE_RETURN errors', () => {
    expect(() => parseDetections(parseXml(SIMPLE_RETURN_ERROR))).toThrow(/1965/);
  });
});

describe('QualysClient', () => {
  it('paginates detections via id_min, enriches from the KnowledgeBase and caches', async () => {
    const http = fakeHttp(vmdrHandler);
    const client = new QualysClient(http.fn, opts);
    const filter = {
      severities: ['3', '4', '5'],
      statuses: ['New', 'Active', 'Fixed'],
      vulnTypes: ['Confirmed', 'Potential'],
    };
    const rows = await client.getDetections(filter);
    expect(rows).toHaveLength(3);
    expect(rows[0]).toMatchObject({
      title: 'Microsoft Windows Security Update - September 2026',
      cves: ['CVE-2026-1111', 'CVE-2026-2222'],
      cvss3: 9.8,
      rti: ['Zero_Day', 'Exploit_Public'],
      patchable: 'Yes',
    });
    const det = http.calls.filter((c) => c.path.includes('detection'));
    expect(det).toHaveLength(2);
    expect(det[0].params).toMatchObject({ status: 'New,Active,Fixed', severities: '3,4,5', show_results: '0' });
    expect(det[0].params?.include_vuln_type).toBeUndefined();
    expect(det[1].params?.id_min).toBe('1002');

    // second call is served from cache
    await client.getDetections(filter);
    expect(http.calls.filter((c) => c.path.includes('detection'))).toHaveLength(2);
  });

  it('sends tag and vuln type filters', async () => {
    const http = fakeHttp(vmdrHandler);
    const client = new QualysClient(http.fn, { ...opts, enrichKb: false });
    const rows = await client.getDetections({
      severities: [],
      statuses: [],
      vulnTypes: ['Confirmed'],
      tags: 'Server, DMZ',
    });
    expect(rows.every((r) => r.type === 'Confirmed')).toBe(true);
    expect(http.calls[0].params).toMatchObject({
      include_vuln_type: 'confirmed',
      use_tags: '1',
      tag_set_by: 'name',
      tag_set_include: 'Server,DMZ',
    });
  });

  it('retries on concurrency limit (409) and then succeeds', async () => {
    let n = 0;
    const http = fakeHttp((req) => (n++ === 0 ? new HttpError(409, SIMPLE_RETURN_ERROR) : vmdrHandler(req)));
    const client = new QualysClient(http.fn, { ...opts, enrichKb: false });
    const rows = await client.getHosts({});
    expect(rows).toHaveLength(1);
    expect(n).toBe(2);
  });

  it('reports 401 clearly', async () => {
    const http = fakeHttp(() => new HttpError(401, 'Unauthorized'));
    const client = new QualysClient(http.fn, opts);
    await expect(client.testVmdr()).rejects.toThrow(/credentials/);
  });

  it('paginates TAS findings with id GREATER lastId', async () => {
    const http = fakeHttp((req) => {
      const body = JSON.parse(req.body!);
      const crit = body.ServiceRequest.filters.Criteria;
      return crit.some((c: any) => c.field === 'id') ? TAS_FINDINGS_PAGE_2 : TAS_FINDINGS_PAGE_1;
    });
    const client = new QualysClient(http.fn, opts);
    const rows = await client.getTasFindings({
      severities: ['3', '4', '5'],
      statuses: ['NEW', 'ACTIVE', 'FIXED'],
      types: [],
    });
    expect(rows).toHaveLength(3);
    expect(http.calls).toHaveLength(2);
    const second = JSON.parse(http.calls[1].body!).ServiceRequest.filters.Criteria;
    expect(second).toContainEqual({ field: 'id', operator: 'GREATER', value: '502' });
    expect(second).toContainEqual({ field: 'isIgnored', operator: 'EQUALS', value: 'false' });
    expect(http.calls[0].headers?.Accept).toBe('application/json');
  });

  it('surfaces QPS errors', async () => {
    const http = fakeHttp(() => TAS_ERROR);
    const client = new QualysClient(http.fn, opts);
    await expect(client.testTas()).rejects.toBeInstanceOf(QualysApiError);
    await expect(client.testTas()).rejects.toThrow(/WAS module/);
  });
});

describe('TAS mapping', () => {
  it('maps OWASP, CWE, web app and tags', () => {
    const f = JSON.parse(TAS_FINDINGS_PAGE_1).ServiceResponse.data[0].Finding;
    expect(mapTasFinding(f, NOW)).toMatchObject({
      webapp: 'Webshop',
      webapp_tags: ['Prod'],
      severity: 5,
      owasp: ['A03 Injection'],
      cwe: ['CWE-79'],
      wasc: ['WASC-8 CROSS-SITE SCRIPTING'],
      cvss3: 6.1,
      potential: 'No',
      age_days: 29,
    });
  });
});

describe('transformations', () => {
  let rows: any[];
  beforeAll(async () => {
    const client = new QualysClient(fakeHttp(vmdrHandler).fn, opts);
    rows = await client.getDetections({ severities: [], statuses: [], vulnTypes: [] });
  });

  it('filters with expressions', () => {
    expect(applyFilter(rows, 'severity>=5')).toHaveLength(2);
    expect(applyFilter(rows, 'status=New,Active; os~windows')).toHaveLength(2);
    expect(applyFilter(rows, 'tags=DMZ')).toHaveLength(2);
    expect(applyFilter(rows, 'tags!=DMZ')).toHaveLength(1);
    expect(applyFilter(rows, 'cves!=(none)')).toHaveLength(2);
    expect(applyFilter(rows, 'last_fixed=')).toHaveLength(2);
    expect(() => applyFilter(rows, 'nonsense')).toThrow(/Invalid filter/);
  });

  it('counts distinct hosts split by severity', () => {
    const frame = toCount(rows, q({ format: 'count', metric: 'distinct', splitBy: 'severity' }));
    expect(frame.fields.map((f) => f.name)).toEqual(['5 - Urgent', '3 - Serious']);
    expect(frame.fields.map((f) => f.values[0])).toEqual([2, 1]);
  });

  it('groups by exploded multi-value fields', () => {
    const frame = toGroupBy(rows, q({ format: 'groupBy', groupBy: 'cves', limit: 5 }));
    expect(frame.fields[0].values).toEqual(['CVE-2026-1111', 'CVE-2026-2222', '(none)']);
    expect(frame.fields[1].values).toEqual([2, 2, 1]);
  });

  it('groups with split columns', () => {
    const frame = toGroupBy(rows, q({ format: 'groupBy', groupBy: 'host', splitBy: 'severity' }));
    expect(frame.fields.map((f) => f.name)).toEqual(['host', '5 - Urgent', '3 - Serious']);
    expect(frame.fields[0].values[0]).toBe('srv-app01.corp.local');
  });

  it('builds time series and open backlog', () => {
    const from = Date.parse('2026-06-01T00:00:00Z');
    const to = NOW;
    const fs = toTimeSeries(rows, q({ format: 'timeseries', timeField: 'first_found' }), from, to);
    expect(fs.fields[0].name).toBe('Time');
    expect((fs.fields[1].values as number[]).reduce((a, b) => a + b, 0)).toBe(3);

    const backlog = toTimeSeries(rows, q({ format: 'timeseries', timeField: 'open_backlog' }), from, to);
    const vals = backlog.fields[1].values as number[];
    expect(vals[vals.length - 1]).toBe(2); // fixed one closed again
    expect(Math.max(...vals)).toBe(2);
  });

  it('renders tables sorted by severity with joined arrays', () => {
    const frame = toTable(rows, q({ columns: ['host', 'severity', 'cves'], limit: 2 }));
    expect(frame.length).toBe(2);
    expect(frame.fields[1].values).toEqual([5, 5]);
    expect(frame.fields[2].values[0]).toBe('CVE-2026-1111, CVE-2026-2222');
  });
});
