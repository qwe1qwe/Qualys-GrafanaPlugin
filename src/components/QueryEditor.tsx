import React, { ChangeEvent, useMemo } from 'react';
import { InlineField, InlineFieldRow, InlineSwitch, Input, MultiSelect, RadioButtonGroup, Select } from '@grafana/ui';
import { QueryEditorProps, SelectableValue } from '@grafana/data';
import { getTemplateSrv } from '@grafana/runtime';

import { DataSource } from '../datasource';
import { DEFAULT_QUERY, Metric, OutputFormat, QualysDataSourceOptions, QualysQuery, QueryType } from '../types';
import { FIELDS, SEVERITY_NAMES } from '../qualys/fields';

type Props = QueryEditorProps<DataSource, QualysQuery, QualysDataSourceOptions>;

const QUERY_TYPES: Array<SelectableValue<QueryType>> = [
  { label: 'VMDR detections', value: 'vmdr_detections', description: 'Host vulnerability detections' },
  { label: 'VMDR hosts', value: 'vmdr_hosts', description: 'Host assets' },
  { label: 'TAS findings', value: 'tas_findings', description: 'TotalAppSec / WAS findings' },
  { label: 'TAS web apps', value: 'tas_webapps', description: 'TotalAppSec / WAS web applications' },
];

const FORMATS: Array<SelectableValue<OutputFormat>> = [
  { label: 'Table', value: 'table' },
  { label: 'Count', value: 'count' },
  { label: 'Group by', value: 'groupBy' },
  { label: 'Time series', value: 'timeseries' },
];

const METRICS: Array<SelectableValue<Metric>> = [
  { label: 'Count', value: 'count' },
  { label: 'Distinct', value: 'distinct' },
  { label: 'Average', value: 'avg' },
  { label: 'Max', value: 'max' },
  { label: 'Min', value: 'min' },
  { label: 'Sum', value: 'sum' },
];

const SEVERITIES = [5, 4, 3, 2, 1].map((s) => ({ label: `${s} - ${SEVERITY_NAMES[s]}`, value: String(s) }));
const VMDR_STATUSES = ['New', 'Active', 'Re-Opened', 'Fixed'].map((s) => ({ label: s, value: s }));
const VMDR_TYPES = ['Confirmed', 'Potential', 'Info'].map((s) => ({ label: s, value: s }));
const TAS_STATUSES = ['NEW', 'ACTIVE', 'REOPENED', 'PROTECTED', 'FIXED'].map((s) => ({ label: s, value: s }));
const TAS_TYPES = ['VULNERABILITY', 'SENSITIVE_CONTENT', 'INFORMATION_GATHERED'].map((s) => ({ label: s, value: s }));

const LW = 16;

export function QueryEditor({ query, onChange, onRunQuery }: Props) {
  const q: QualysQuery = { ...(DEFAULT_QUERY as QualysQuery), ...query };
  const fields = FIELDS[q.queryType];

  const variables = useMemo(
    () =>
      getTemplateSrv()
        .getVariables()
        .map((v) => ({ label: `$${v.name}`, value: `$${v.name}` })),
    []
  );

  const fieldOptions = fields.map((f) => ({ label: f.name, value: f.name, description: f.description }));
  const numericOptions = fields.filter((f) => f.kind === 'number').map((f) => ({ label: f.name, value: f.name }));
  const timeOptions = fields.filter((f) => f.kind === 'time').map((f) => ({ label: f.name, value: f.name }));

  const update = (patch: Partial<QualysQuery>, run = true) => {
    onChange({ ...q, ...patch });
    if (run) {
      onRunQuery();
    }
  };
  const text = (key: keyof QualysQuery) => (e: ChangeEvent<HTMLInputElement>) =>
    update({ [key]: e.target.value } as Partial<QualysQuery>, false);
  const multi = (key: keyof QualysQuery) => (v: Array<SelectableValue<string>>) =>
    update({ [key]: v.map((x) => x.value!) } as Partial<QualysQuery>);
  const withVars = (opts: Array<SelectableValue<string>>, current?: string[]) => {
    const all = [...opts, ...variables];
    for (const c of current ?? []) {
      if (!all.some((o) => o.value === c)) {
        all.push({ label: c, value: c });
      }
    }
    return all;
  };

  const isVmdr = q.queryType === 'vmdr_detections' || q.queryType === 'vmdr_hosts';

  return (
    <>
      <InlineFieldRow>
        <InlineField label="Data set" labelWidth={LW}>
          <RadioButtonGroup
            options={QUERY_TYPES}
            value={q.queryType}
            onChange={(v) => update({ queryType: v, groupBy: undefined, splitBy: undefined, columns: [] })}
          />
        </InlineField>
      </InlineFieldRow>

      {/* ------------------------------------------------ API filters */}
      {q.queryType === 'vmdr_detections' && (
        <>
          <InlineFieldRow>
            <InlineField label="Severities" labelWidth={LW}>
              <MultiSelect
                width={40}
                options={withVars(SEVERITIES, q.severities)}
                value={q.severities}
                allowCustomValue
                onChange={multi('severities')}
              />
            </InlineField>
            <InlineField label="Status" labelWidth={10}>
              <MultiSelect
                width={40}
                options={withVars(VMDR_STATUSES, q.statuses)}
                value={q.statuses}
                allowCustomValue
                onChange={multi('statuses')}
              />
            </InlineField>
            <InlineField label="Types" labelWidth={10}>
              <MultiSelect
                width={36}
                options={withVars(VMDR_TYPES, q.vulnTypes)}
                value={q.vulnTypes}
                allowCustomValue
                onChange={multi('vulnTypes')}
              />
            </InlineField>
          </InlineFieldRow>
          <InlineFieldRow>
            <InlineField label="QIDs" labelWidth={LW} tooltip="Comma separated QIDs or ranges, e.g. 105012,38170-38180">
              <Input width={26} value={q.qids ?? ''} onChange={text('qids')} onBlur={onRunQuery} />
            </InlineField>
            <InlineField label="Include ignored" labelWidth={16}>
              <InlineSwitch
                value={!!q.includeIgnored}
                onChange={(e) => update({ includeIgnored: e.currentTarget.checked })}
              />
            </InlineField>
            <InlineField label="Include disabled" labelWidth={16}>
              <InlineSwitch
                value={!!q.includeDisabled}
                onChange={(e) => update({ includeDisabled: e.currentTarget.checked })}
              />
            </InlineField>
          </InlineFieldRow>
        </>
      )}

      {isVmdr && (
        <InlineFieldRow>
          <InlineField
            label="Asset tags"
            labelWidth={LW}
            tooltip="Comma separated asset tag names (any match). Variables allowed."
          >
            <Input
              width={40}
              value={q.tags ?? ''}
              placeholder="e.g. Server, DMZ or $tag"
              onChange={text('tags')}
              onBlur={onRunQuery}
            />
          </InlineField>
          <InlineField label="IPs" labelWidth={10} tooltip="IPs / ranges, e.g. 10.0.0.1-10.0.0.255">
            <Input width={40} value={q.ips ?? ''} onChange={text('ips')} onBlur={onRunQuery} />
          </InlineField>
        </InlineFieldRow>
      )}

      {q.queryType === 'tas_findings' && (
        <>
          <InlineFieldRow>
            <InlineField label="Severities" labelWidth={LW}>
              <MultiSelect
                width={40}
                options={withVars(SEVERITIES, q.tasSeverities)}
                value={q.tasSeverities}
                allowCustomValue
                onChange={multi('tasSeverities')}
              />
            </InlineField>
            <InlineField label="Status" labelWidth={10}>
              <MultiSelect
                width={40}
                options={withVars(TAS_STATUSES, q.tasStatuses)}
                value={q.tasStatuses}
                allowCustomValue
                onChange={multi('tasStatuses')}
              />
            </InlineField>
            <InlineField label="Types" labelWidth={10}>
              <MultiSelect
                width={50}
                options={withVars(TAS_TYPES, q.tasTypes)}
                value={q.tasTypes}
                allowCustomValue
                onChange={multi('tasTypes')}
              />
            </InlineField>
          </InlineFieldRow>
          <InlineFieldRow>
            <InlineField label="Include ignored" labelWidth={LW}>
              <InlineSwitch
                value={!!q.tasIncludeIgnored}
                onChange={(e) => update({ tasIncludeIgnored: e.currentTarget.checked })}
              />
            </InlineField>
          </InlineFieldRow>
        </>
      )}

      {!isVmdr && (
        <InlineFieldRow>
          <InlineField label="Web app name" labelWidth={LW} tooltip="Contains match. Variables allowed.">
            <Input width={40} value={q.webAppName ?? ''} onChange={text('webAppName')} onBlur={onRunQuery} />
          </InlineField>
          <InlineField label="Web app tag" labelWidth={14} tooltip="Exact tag name. Variables allowed.">
            <Input width={30} value={q.webAppTag ?? ''} onChange={text('webAppTag')} onBlur={onRunQuery} />
          </InlineField>
        </InlineFieldRow>
      )}

      {/* ------------------------------------------------ output */}
      <InlineFieldRow>
        <InlineField label="Format" labelWidth={LW}>
          <RadioButtonGroup options={FORMATS} value={q.format} onChange={(v) => update({ format: v })} />
        </InlineField>
        {q.format !== 'table' && (
          <>
            <InlineField label="Metric" labelWidth={10}>
              <Select
                width={16}
                options={METRICS}
                value={q.metric ?? 'count'}
                onChange={(v) => update({ metric: v.value })}
              />
            </InlineField>
            {q.metric && q.metric !== 'count' && (
              <InlineField label="of" labelWidth={6}>
                <Select
                  width={22}
                  options={q.metric === 'distinct' ? fieldOptions : numericOptions}
                  value={q.metricField ?? null}
                  placeholder={q.metric === 'distinct' ? 'host/web app' : 'field'}
                  onChange={(v) => update({ metricField: v?.value })}
                  isClearable
                />
              </InlineField>
            )}
          </>
        )}
      </InlineFieldRow>

      {q.format !== 'table' && (
        <InlineFieldRow>
          {q.format === 'groupBy' && (
            <InlineField label="Group by" labelWidth={LW}>
              <Select
                width={26}
                options={fieldOptions}
                value={q.groupBy ?? 'severity'}
                onChange={(v) => update({ groupBy: v.value })}
              />
            </InlineField>
          )}
          {q.format === 'timeseries' && (
            <InlineField
              label="Time field"
              labelWidth={LW}
              tooltip="Bucket records by this timestamp, or 'open_backlog' for the number of open findings over time (needs Fixed in the status filter)"
            >
              <Select
                width={26}
                options={[...timeOptions, { label: 'open_backlog', value: 'open_backlog' }]}
                value={q.timeField ?? 'first_found'}
                onChange={(v) => update({ timeField: v.value })}
              />
            </InlineField>
          )}
          <InlineField label="Split by" labelWidth={10} tooltip="One column / series per value, e.g. severity">
            <Select
              width={22}
              options={fieldOptions}
              value={q.splitBy ?? null}
              isClearable
              onChange={(v) => update({ splitBy: v?.value })}
            />
          </InlineField>
        </InlineFieldRow>
      )}

      <InlineFieldRow>
        {q.format === 'table' && (
          <InlineField label="Columns" labelWidth={LW} tooltip="Empty = default columns">
            <MultiSelect
              width={60}
              options={fieldOptions}
              value={q.columns ?? []}
              onChange={(v) => update({ columns: v.map((x) => x.value!) })}
            />
          </InlineField>
        )}
        {(q.format === 'table' || q.format === 'groupBy') && (
          <InlineField label="Limit" labelWidth={q.format === 'table' ? 10 : LW}>
            <Input
              type="number"
              width={10}
              value={q.limit ?? ''}
              onChange={(e: ChangeEvent<HTMLInputElement>) =>
                update({ limit: e.target.value === '' ? undefined : Number(e.target.value) }, false)
              }
              onBlur={onRunQuery}
            />
          </InlineField>
        )}
      </InlineFieldRow>

      <InlineFieldRow>
        <InlineField
          label="Filter"
          labelWidth={LW}
          grow
          tooltip="Client-side filter, conditions separated by ';'. Operators: = != > >= < <= ~ (contains) !~. Example: status=Fixed; severity>=4; os~windows"
        >
          <Input
            value={q.filter ?? ''}
            placeholder="severity>=4; os~windows"
            onChange={text('filter')}
            onBlur={onRunQuery}
          />
        </InlineField>
        <InlineField
          label="Only in time range"
          labelWidth={18}
          tooltip="Keep only records whose timestamp lies in the dashboard time range"
        >
          <Select
            width={20}
            options={timeOptions}
            value={q.rangeField ?? null}
            isClearable
            placeholder="off"
            onChange={(v) => update({ rangeField: v?.value })}
          />
        </InlineField>
      </InlineFieldRow>
    </>
  );
}
