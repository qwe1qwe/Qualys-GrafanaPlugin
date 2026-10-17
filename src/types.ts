import { DataSourceJsonData } from '@grafana/data';
import { DataQuery } from '@grafana/schema';

/** Which Qualys data set a query reads. */
export type QueryType = 'vmdr_detections' | 'vmdr_hosts' | 'tas_findings' | 'tas_webapps';

/**
 * How the fetched rows are returned to Grafana.
 * - table:      one row per record
 * - count:      a single value (optionally split into one column per value of `splitBy`)
 * - groupBy:    one row per value of `groupBy` (optionally split into columns by `splitBy`)
 * - timeseries: rows bucketed over the dashboard time range by `timeField`
 */
export type OutputFormat = 'table' | 'count' | 'groupBy' | 'timeseries';

/** Aggregation applied in count / groupBy / timeseries formats. */
export type Metric = 'count' | 'distinct' | 'avg' | 'max' | 'min' | 'sum';

export interface QualysQuery extends DataQuery {
  queryType: QueryType;
  format: OutputFormat;

  metric?: Metric;
  /** Field used by distinct / avg / max / min / sum */
  metricField?: string;
  groupBy?: string;
  splitBy?: string;
  /** Field used for bucketing in timeseries format. `open_backlog` is a special mode. */
  timeField?: string;
  /** Max rows (table) or groups (groupBy). */
  limit?: number;
  /** Client-side filter expression, e.g. `status=Fixed; severity>=4; os~windows` */
  filter?: string;
  /** Only keep rows whose `rangeField` lies inside the dashboard time range. */
  rangeField?: string;
  /** Columns to return in table format (empty = defaults). */
  columns?: string[];

  // ---- VMDR API filters (sent to Qualys) ----
  severities?: string[];
  statuses?: string[];
  vulnTypes?: string[];
  qids?: string;
  ips?: string;
  tags?: string;
  includeIgnored?: boolean;
  includeDisabled?: boolean;

  // ---- TAS (TotalAppSec / WAS) API filters ----
  tasSeverities?: string[];
  tasStatuses?: string[];
  tasTypes?: string[];
  webAppName?: string;
  webAppTag?: string;
  tasIncludeIgnored?: boolean;
}

export const DEFAULT_QUERY: Partial<QualysQuery> = {
  queryType: 'vmdr_detections',
  format: 'table',
  metric: 'count',
  severities: ['3', '4', '5'],
  statuses: ['New', 'Active', 'Re-Opened'],
  vulnTypes: ['Confirmed', 'Potential'],
  tasStatuses: ['NEW', 'ACTIVE', 'REOPENED'],
  tasTypes: ['VULNERABILITY', 'SENSITIVE_CONTENT'],
  tasSeverities: ['1', '2', '3', '4', '5'],
  limit: 1000,
};

/** Options configured for each data source instance (stored unencrypted). */
export interface QualysDataSourceOptions extends DataSourceJsonData {
  /** Qualys API server URL of your platform, e.g. https://qualysapi.qg2.apps.qualys.eu */
  apiUrl?: string;
  username?: string;
  /** Hosts per detection-list page (truncation_limit). */
  pageSize?: number;
  /** Safety limit for the number of pages fetched per data set. */
  maxPages?: number;
  /** How long fetched data is reused by all panels (minutes). */
  cacheTtlMinutes?: number;
  /** Max parallel requests against the Qualys API (subscription concurrency limit). */
  concurrency?: number;
  /** Enrich detections with title, CVEs, CVSS etc. from the KnowledgeBase. */
  enrichKb?: boolean;
}

/** Stored encrypted on the Grafana server and only injected by the data proxy. */
export interface QualysSecureJsonData {
  /** base64(username:password) */
  basicAuth?: string;
}

export type FieldKind = 'string' | 'number' | 'time' | 'boolean';

export interface FieldDef {
  name: string;
  kind: FieldKind;
  /** multi-valued: groupBy explodes the array */
  multi?: boolean;
  /** shown in table format by default */
  default?: boolean;
  description?: string;
}

export type Row = Record<string, string | number | boolean | string[] | null | undefined>;
