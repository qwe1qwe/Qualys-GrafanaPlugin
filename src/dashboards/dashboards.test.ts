/**
 * Runs every query of the bundled dashboards against sample Qualys responses and checks that
 * the panels get the fields they reference. Guards against dashboards drifting from the code.
 */
import vmdr from './vmdr-overview.json';
import tas from './tas-overview.json';
import pluginJson from '../plugin.json';
import { HttpRequest, QualysClient } from '../qualys/client';
import { applyFilter, applyRange, toFrame } from '../qualys/transform';
import { QualysQuery } from '../types';
import {
  DETECTIONS_PAGE_1,
  DETECTIONS_PAGE_2,
  HOSTS,
  KB,
  TAS_FINDINGS_PAGE_1,
  TAS_FINDINGS_PAGE_2,
} from '../qualys/__fixtures__/samples';

const http = async (req: HttpRequest) => {
  let data: string;
  if (req.path.includes('knowledge_base')) {
    data = KB;
  } else if (req.path.includes('detection')) {
    data = req.params?.id_min ? DETECTIONS_PAGE_2 : DETECTIONS_PAGE_1;
  } else if (req.path.includes('was/finding')) {
    data = req.body!.includes('GREATER') ? TAS_FINDINGS_PAGE_2 : TAS_FINDINGS_PAGE_1;
  } else if (req.path.includes('was/webapp')) {
    data = JSON.stringify({
      ServiceResponse: {
        responseCode: 'SUCCESS',
        hasMoreRecords: 'false',
        data: [{ WebApp: { id: 11, name: 'Webshop' } }],
      },
    });
  } else {
    data = HOSTS;
  }
  return { status: 200, data };
};

/** Minimal stand-in for Grafana's template service using the dashboard defaults. */
function interpolator(dash: any) {
  const values: Record<string, string> = {};
  for (const v of dash.templating.list) {
    const cur = v.current?.value;
    const val = Array.isArray(cur) ? cur.join(',') : (cur ?? '');
    values[v.name] = val === '$__all' ? '' : val;
  }
  const rep = (s: string) => s.replace(/\$(\w+)/g, (_, n) => values[n] ?? '');
  const list = (a?: string[]) => (a ?? []).flatMap((x) => rep(x).split(',')).filter(Boolean);
  return (t: any): QualysQuery => ({
    ...t,
    filter: rep(t.filter ?? ''),
    tags: rep(t.tags ?? ''),
    webAppName: rep(t.webAppName ?? ''),
    webAppTag: rep(t.webAppTag ?? ''),
    severities: list(t.severities),
    statuses: list(t.statuses),
    vulnTypes: list(t.vulnTypes),
    tasSeverities: list(t.tasSeverities),
    tasStatuses: list(t.tasStatuses),
    tasTypes: list(t.tasTypes),
  });
}

async function rowsFor(client: QualysClient, q: QualysQuery) {
  switch (q.queryType) {
    case 'vmdr_hosts':
      return client.getHosts({ tags: q.tags });
    case 'tas_findings':
      return client.getTasFindings({ severities: q.tasSeverities!, statuses: q.tasStatuses!, types: q.tasTypes! });
    case 'tas_webapps':
      return client.getTasWebApps({});
    default:
      return client.getDetections({ severities: q.severities!, statuses: q.statuses!, vulnTypes: q.vulnTypes! });
  }
}

describe.each([
  ['VMDR', vmdr],
  ['TAS', tas],
])('%s dashboard', (_name, dash: any) => {
  const from = Date.parse('2026-06-01T00:00:00Z');
  const to = Date.parse('2026-10-01T00:00:00Z');

  it('is listed in plugin.json', () => {
    const paths = pluginJson.includes.map((i) => i.path);
    expect(paths.some((p) => dash === (p.includes('vmdr') ? vmdr : tas))).toBe(true);
  });

  it('has no overlapping panels and unique ids', () => {
    const ids = new Set<number>();
    const cells = new Set<string>();
    for (const p of dash.panels) {
      expect(ids.has(p.id)).toBe(false);
      ids.add(p.id);
      for (let x = p.gridPos.x; x < p.gridPos.x + p.gridPos.w; x++) {
        for (let y = p.gridPos.y; y < p.gridPos.y + p.gridPos.h; y++) {
          const k = `${x}:${y}`;
          if (cells.has(k)) {
            throw new Error(`panel "${p.title}" overlaps at ${k}`);
          }
          cells.add(k);
        }
      }
      expect(p.gridPos.x + p.gridPos.w).toBeLessThanOrEqual(24);
    }
  });

  it('every panel query produces the fields the panel uses', async () => {
    const client = new QualysClient(http, {
      pageSize: 1000,
      maxPages: 5,
      cacheTtlMs: 60000,
      concurrency: 2,
      enrichKb: true,
    });
    const interpolate = interpolator(dash);
    for (const panel of dash.panels.filter((p: any) => p.type !== 'row')) {
      expect(panel.targets?.length).toBeGreaterThan(0);
      for (const t of panel.targets) {
        expect(t.datasource.type).toBe(pluginJson.id);
        const q = interpolate(t);
        let rows = await rowsFor(client, q);
        rows = applyRange(rows, q.rangeField, from, to);
        rows = applyFilter(rows, q.filter);
        const frame = toFrame(rows, q, from, to);
        expect(frame.fields.length).toBeGreaterThan(0);
        if (panel.type === 'barchart') {
          expect(frame.fields.map((f) => f.name)).toContain(panel.options.xField);
        }
        if (panel.type === 'timeseries') {
          expect(frame.fields[0].name).toBe('Time');
        }
      }
    }
  });
});
