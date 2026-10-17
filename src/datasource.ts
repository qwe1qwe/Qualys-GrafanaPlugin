import { getBackendSrv, getTemplateSrv, isFetchError } from '@grafana/runtime';
import {
  CoreApp,
  DataQueryRequest,
  DataQueryResponse,
  DataSourceApi,
  DataSourceInstanceSettings,
  MetricFindValue,
  ScopedVars,
  TestDataSourceResponse,
} from '@grafana/data';
import { lastValueFrom } from 'rxjs';

import { DEFAULT_QUERY, QualysDataSourceOptions, QualysQuery, QueryType, Row } from './types';
import { HttpError, HttpFn, QualysClient } from './qualys/client';
import { applyFilter, applyRange, distinctValues, isQueryType, toFrame } from './qualys/transform';

/** Route path declared in plugin.json – the data proxy adds auth and forwards to the Qualys API URL. */
export const PROXY_ROUTE = '/qualys';

const ALL_TOKENS = new Set(['ALL', '$__all', '*', '']);

const DATASET_ALIASES: Record<string, QueryType> = {
  vmdr: 'vmdr_hosts',
  hosts: 'vmdr_hosts',
  detections: 'vmdr_detections',
  tas: 'tas_webapps',
  webapps: 'tas_webapps',
  findings: 'tas_findings',
};

export class DataSource extends DataSourceApi<QualysQuery, QualysDataSourceOptions> {
  baseUrl: string;
  client: QualysClient;
  configured: boolean;

  constructor(instanceSettings: DataSourceInstanceSettings<QualysDataSourceOptions>) {
    super(instanceSettings);
    this.baseUrl = instanceSettings.url ?? '';
    const j = instanceSettings.jsonData ?? {};
    this.configured = !!j.apiUrl;
    this.client = new QualysClient(this.http, {
      pageSize: j.pageSize || 500,
      maxPages: j.maxPages || 200,
      cacheTtlMs: (j.cacheTtlMinutes ?? 15) * 60 * 1000,
      concurrency: j.concurrency || 2,
      enrichKb: j.enrichKb !== false,
    });
  }

  private http: HttpFn = async (req) => {
    try {
      const res = await lastValueFrom(
        getBackendSrv().fetch<string>({
          url: `${this.baseUrl}${PROXY_ROUTE}${req.path}`,
          method: req.method,
          params: req.params,
          data: req.body,
          headers: req.headers,
          responseType: 'text',
          showErrorAlert: false,
          showSuccessAlert: false,
        })
      );
      return { status: res.status, data: typeof res.data === 'string' ? res.data : JSON.stringify(res.data) };
    } catch (e) {
      if (isFetchError(e)) {
        const body = typeof e.data === 'string' ? e.data : JSON.stringify(e.data ?? '');
        if (e.status === 502 || e.status === 504) {
          throw new HttpError(
            e.status,
            body,
            'Qualys did not answer in time via the Grafana data proxy. Lower the page size or raise [dataproxy] timeout.'
          );
        }
        throw new HttpError(e.status, body, e.statusText);
      }
      throw e;
    }
  };

  getDefaultQuery(_: CoreApp): Partial<QualysQuery> {
    return DEFAULT_QUERY;
  }

  filterQuery(query: QualysQuery): boolean {
    return !query.hide;
  }

  // ------------------------------------------------------------- templating

  private str(v: string | undefined, scopedVars?: ScopedVars): string {
    if (!v) {
      return '';
    }
    const out = getTemplateSrv().replace(v, scopedVars, 'csv').trim();
    return ALL_TOKENS.has(out) ? '' : out;
  }

  private list(values: string[] | undefined, scopedVars?: ScopedVars): string[] {
    const out: string[] = [];
    for (const v of values ?? []) {
      for (const part of getTemplateSrv().replace(v, scopedVars, 'csv').split(',')) {
        const p = part.trim();
        if (!ALL_TOKENS.has(p)) {
          out.push(p);
        }
      }
    }
    return [...new Set(out)];
  }

  private interpolate(q: QualysQuery, scopedVars?: ScopedVars): QualysQuery {
    const d = DEFAULT_QUERY;
    return {
      ...q,
      queryType: q.queryType ?? d.queryType,
      format: q.format ?? d.format,
      filter: this.str(q.filter, scopedVars),
      qids: this.str(q.qids, scopedVars),
      ips: this.str(q.ips, scopedVars),
      tags: this.str(q.tags, scopedVars),
      webAppName: this.str(q.webAppName, scopedVars),
      webAppTag: this.str(q.webAppTag, scopedVars),
      severities: this.list(q.severities ?? d.severities, scopedVars),
      statuses: this.list(q.statuses ?? d.statuses, scopedVars),
      vulnTypes: this.list(q.vulnTypes ?? d.vulnTypes, scopedVars),
      tasSeverities: this.list(q.tasSeverities ?? d.tasSeverities, scopedVars),
      tasStatuses: this.list(q.tasStatuses ?? d.tasStatuses, scopedVars),
      tasTypes: this.list(q.tasTypes ?? d.tasTypes, scopedVars),
    };
  }

  // ------------------------------------------------------------------ data

  /** Loads the (cached) rows for a query's API filter. */
  async fetchRows(q: QualysQuery): Promise<Row[]> {
    switch (q.queryType) {
      case 'vmdr_hosts':
        return this.client.getHosts({ ips: q.ips, tags: q.tags });
      case 'tas_findings':
        return this.client.getTasFindings({
          severities: q.tasSeverities ?? [],
          statuses: q.tasStatuses ?? [],
          types: q.tasTypes ?? [],
          webAppName: q.webAppName,
          webAppTag: q.webAppTag,
          includeIgnored: q.tasIncludeIgnored,
        });
      case 'tas_webapps':
        return this.client.getTasWebApps({ webAppName: q.webAppName, webAppTag: q.webAppTag });
      case 'vmdr_detections':
      default:
        return this.client.getDetections({
          severities: q.severities ?? [],
          statuses: q.statuses ?? [],
          vulnTypes: q.vulnTypes ?? [],
          qids: q.qids,
          ips: q.ips,
          tags: q.tags,
          includeIgnored: q.includeIgnored,
          includeDisabled: q.includeDisabled,
        });
    }
  }

  async query(options: DataQueryRequest<QualysQuery>): Promise<DataQueryResponse> {
    const from = options.range.from.valueOf();
    const to = options.range.to.valueOf();
    if (!this.configured) {
      return { data: [], errors: [{ message: 'Qualys data source is not configured (API URL missing).' }] };
    }

    const results = await Promise.all(
      options.targets
        .filter((t) => !t.hide)
        .map(async (target) => {
          const q = this.interpolate(target, options.scopedVars);
          try {
            let rows = await this.fetchRows(q);
            rows = applyRange(rows, q.rangeField, from, to);
            rows = applyFilter(rows, q.filter);
            return { frame: toFrame(rows, q, from, to) };
          } catch (e) {
            return { error: { refId: target.refId, message: e instanceof Error ? e.message : String(e) } };
          }
        })
    );

    return {
      data: results.filter((r) => r.frame).map((r) => r.frame!),
      errors: results.filter((r) => r.error).map((r) => r.error!),
    };
  }

  /**
   * Template variable support. Query syntax: `<dataset>:<field>`, e.g.
   *   vmdr:tags        – asset tags of all hosts
   *   vmdr:os          – operating systems
   *   tas:webapp       – TotalAppSec web application names
   *   tas:tags         – TotalAppSec web application tags
   *   detections:title – titles of open detections (uses default filters)
   */
  async metricFindQuery(query: string, options?: { scopedVars?: ScopedVars }): Promise<MetricFindValue[]> {
    const interpolated = getTemplateSrv().replace(query ?? '', options?.scopedVars);
    const [rawSet, rawField] = interpolated.split(':').map((s) => s.trim());
    const dataset = DATASET_ALIASES[rawSet] ?? (isQueryType(rawSet) ? rawSet : undefined);
    if (!dataset || !rawField) {
      throw new Error('Variable query must look like "vmdr:tags", "vmdr:os", "tas:webapp" or "tas:tags".');
    }
    const q = this.interpolate({ ...(DEFAULT_QUERY as QualysQuery), refId: 'var', queryType: dataset });
    const rows = await this.fetchRows(q);
    return distinctValues(rows, rawField).map((text) => ({ text, value: text }));
  }

  async testDatasource(): Promise<TestDataSourceResponse> {
    if (!this.configured) {
      return { status: 'error', message: 'Please enter the Qualys API URL.' };
    }
    this.client.clearCache();
    const [vmdr, tas] = await Promise.allSettled([this.client.testVmdr(), this.client.testTas()]);
    const msg = (r: PromiseSettledResult<string>, name: string) =>
      r.status === 'fulfilled' ? r.value : `${name}: ${r.reason instanceof Error ? r.reason.message : r.reason}`;
    if (vmdr.status === 'rejected' && tas.status === 'rejected') {
      return { status: 'error', message: `${msg(vmdr, 'VMDR')} | ${msg(tas, 'TAS')}` };
    }
    return {
      status: 'success',
      message: `${msg(vmdr, 'VMDR')} | ${msg(tas, 'TAS')}`,
    };
  }
}
