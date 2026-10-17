import { FieldDef, QueryType } from '../types';

/** Qualys severity levels (VMDR and TAS use the same 1-5 scale). */
export const SEVERITY_NAMES: Record<number, string> = {
  1: 'Minimal',
  2: 'Medium',
  3: 'Serious',
  4: 'Critical',
  5: 'Urgent',
};

export function severityLabel(sev: unknown): string {
  const n = Number(sev);
  return SEVERITY_NAMES[n] ? `${n} - ${SEVERITY_NAMES[n]}` : String(sev ?? '');
}

export const AGE_BUCKETS = ['0-30 days', '31-60 days', '61-90 days', '91-180 days', '>180 days'];

export function ageBucket(days: number | null | undefined): string | null {
  if (days === null || days === undefined || isNaN(days)) {
    return null;
  }
  if (days <= 30) {
    return AGE_BUCKETS[0];
  }
  if (days <= 60) {
    return AGE_BUCKETS[1];
  }
  if (days <= 90) {
    return AGE_BUCKETS[2];
  }
  if (days <= 180) {
    return AGE_BUCKETS[3];
  }
  return AGE_BUCKETS[4];
}

const VMDR_DETECTION_FIELDS: FieldDef[] = [
  { name: 'host', kind: 'string', default: true, description: 'DNS name, NetBIOS name or IP' },
  { name: 'ip', kind: 'string', default: true },
  { name: 'dns', kind: 'string' },
  { name: 'netbios', kind: 'string' },
  { name: 'os', kind: 'string', default: true },
  { name: 'host_id', kind: 'number' },
  { name: 'tracking_method', kind: 'string' },
  { name: 'tags', kind: 'string', multi: true },
  { name: 'qid', kind: 'number', default: true },
  { name: 'title', kind: 'string', default: true },
  { name: 'severity', kind: 'number', default: true },
  { name: 'type', kind: 'string', default: true, description: 'Confirmed / Potential / Info' },
  { name: 'status', kind: 'string', default: true },
  { name: 'category', kind: 'string' },
  { name: 'port', kind: 'number' },
  { name: 'protocol', kind: 'string' },
  { name: 'ssl', kind: 'boolean' },
  { name: 'qds', kind: 'number', default: true, description: 'Qualys Detection Score' },
  { name: 'qds_severity', kind: 'string' },
  { name: 'cvss3', kind: 'number', default: true },
  { name: 'cves', kind: 'string', multi: true, default: true },
  { name: 'rti', kind: 'string', multi: true, description: 'Real-time threat indicators' },
  { name: 'patchable', kind: 'string', default: true },
  { name: 'first_found', kind: 'time', default: true },
  { name: 'last_found', kind: 'time', default: true },
  { name: 'last_fixed', kind: 'time' },
  { name: 'times_found', kind: 'number' },
  { name: 'age_days', kind: 'number', default: true },
  { name: 'age_bucket', kind: 'string' },
  { name: 'is_ignored', kind: 'boolean' },
  { name: 'is_disabled', kind: 'boolean' },
];

const VMDR_HOST_FIELDS: FieldDef[] = [
  { name: 'host', kind: 'string', default: true },
  { name: 'ip', kind: 'string', default: true },
  { name: 'dns', kind: 'string' },
  { name: 'netbios', kind: 'string' },
  { name: 'os', kind: 'string', default: true },
  { name: 'host_id', kind: 'number' },
  { name: 'tracking_method', kind: 'string', default: true },
  { name: 'tags', kind: 'string', multi: true, default: true },
  { name: 'last_vuln_scan', kind: 'time', default: true },
  { name: 'last_activity', kind: 'time', default: true },
  { name: 'scan_age_days', kind: 'number', default: true },
];

const TAS_FINDING_FIELDS: FieldDef[] = [
  { name: 'webapp', kind: 'string', default: true },
  { name: 'webapp_id', kind: 'number' },
  { name: 'webapp_url', kind: 'string' },
  { name: 'webapp_tags', kind: 'string', multi: true },
  { name: 'finding_id', kind: 'number' },
  { name: 'qid', kind: 'number', default: true },
  { name: 'name', kind: 'string', default: true },
  { name: 'severity', kind: 'number', default: true },
  {
    name: 'type',
    kind: 'string',
    default: true,
    description: 'VULNERABILITY / SENSITIVE_CONTENT / INFORMATION_GATHERED',
  },
  { name: 'finding_type', kind: 'string', description: 'QUALYS / BURP / BUGCROWD / ...' },
  { name: 'group', kind: 'string', default: true, description: 'XSS, SQL, PATH, INFO, ...' },
  { name: 'status', kind: 'string', default: true },
  { name: 'potential', kind: 'string' },
  { name: 'url', kind: 'string', default: true },
  { name: 'owasp', kind: 'string', multi: true, default: true },
  { name: 'cwe', kind: 'string', multi: true, default: true },
  { name: 'wasc', kind: 'string', multi: true },
  { name: 'cvss3', kind: 'number', default: true },
  { name: 'first_found', kind: 'time', default: true },
  { name: 'last_found', kind: 'time', default: true },
  { name: 'last_tested', kind: 'time' },
  { name: 'last_fixed', kind: 'time' },
  { name: 'times_detected', kind: 'number' },
  { name: 'age_days', kind: 'number', default: true },
  { name: 'age_bucket', kind: 'string' },
  { name: 'is_ignored', kind: 'boolean' },
];

const TAS_WEBAPP_FIELDS: FieldDef[] = [
  { name: 'webapp', kind: 'string', default: true },
  { name: 'webapp_id', kind: 'number', default: true },
  { name: 'url', kind: 'string', default: true },
  { name: 'tags', kind: 'string', multi: true, default: true },
  { name: 'owner', kind: 'string', default: true },
  { name: 'created', kind: 'time', default: true },
  { name: 'updated', kind: 'time', default: true },
  { name: 'last_scan', kind: 'time', default: true },
  { name: 'last_scan_status', kind: 'string', default: true },
];

export const FIELDS: Record<QueryType, FieldDef[]> = {
  vmdr_detections: VMDR_DETECTION_FIELDS,
  vmdr_hosts: VMDR_HOST_FIELDS,
  tas_findings: TAS_FINDING_FIELDS,
  tas_webapps: TAS_WEBAPP_FIELDS,
};

export function fieldDef(queryType: QueryType, name: string): FieldDef | undefined {
  return FIELDS[queryType].find((f) => f.name === name);
}

/** Fields that make sense as identity for "distinct" counting, per query type. */
export const DEFAULT_DISTINCT: Record<QueryType, string> = {
  vmdr_detections: 'host_id',
  vmdr_hosts: 'host_id',
  tas_findings: 'webapp_id',
  tas_webapps: 'webapp_id',
};
