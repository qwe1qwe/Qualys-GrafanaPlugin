import React, { ChangeEvent, useState } from 'react';
import { Alert, InlineField, InlineSwitch, Input, SecretInput, Select } from '@grafana/ui';
import { DataSourcePluginOptionsEditorProps, SelectableValue } from '@grafana/data';

import { QualysDataSourceOptions, QualysSecureJsonData } from '../types';

interface Props extends DataSourcePluginOptionsEditorProps<QualysDataSourceOptions, QualysSecureJsonData> {}

/** Qualys API server URLs per platform (see "Identify your Qualys platform"). */
export const PLATFORMS: Array<SelectableValue<string>> = [
  { label: 'US1', value: 'https://qualysapi.qualys.com' },
  { label: 'US2', value: 'https://qualysapi.qg2.apps.qualys.com' },
  { label: 'US3', value: 'https://qualysapi.qg3.apps.qualys.com' },
  { label: 'US4', value: 'https://qualysapi.qg4.apps.qualys.com' },
  { label: 'EU1', value: 'https://qualysapi.qualys.eu' },
  { label: 'EU2', value: 'https://qualysapi.qg2.apps.qualys.eu' },
  { label: 'EU3', value: 'https://qualysapi.qg3.apps.qualys.it' },
  { label: 'UK1', value: 'https://qualysapi.qg1.apps.qualys.co.uk' },
  { label: 'IN1', value: 'https://qualysapi.qg1.apps.qualys.in' },
  { label: 'CA1', value: 'https://qualysapi.qg1.apps.qualys.ca' },
  { label: 'AE1', value: 'https://qualysapi.qg1.apps.qualys.ae' },
  { label: 'AU1', value: 'https://qualysapi.qg1.apps.qualys.com.au' },
  { label: 'KSA1', value: 'https://qualysapi.qg1.apps.qualysksa.com' },
].map((p) => ({ ...p, description: p.value }));

export function toBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = '';
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin);
}

const LW = 22;

export function ConfigEditor(props: Props) {
  const { onOptionsChange, options } = props;
  const { jsonData, secureJsonFields } = options;
  const [password, setPassword] = useState('');

  const setJson = (patch: Partial<QualysDataSourceOptions>) =>
    onOptionsChange({ ...options, jsonData: { ...jsonData, ...patch } });

  const setNumber = (key: keyof QualysDataSourceOptions) => (e: ChangeEvent<HTMLInputElement>) =>
    setJson({ [key]: e.target.value === '' ? undefined : Number(e.target.value) } as Partial<QualysDataSourceOptions>);

  const onUsernameChange = (e: ChangeEvent<HTMLInputElement>) => {
    const username = e.target.value;
    if (password) {
      // re-encode the credentials typed in this session
      onOptionsChange({
        ...options,
        jsonData: { ...jsonData, username },
        secureJsonData: { basicAuth: toBase64(`${username}:${password}`) },
      });
    } else {
      // stored credentials no longer match the user name -> password must be entered again
      onOptionsChange({
        ...options,
        jsonData: { ...jsonData, username },
        secureJsonFields: { ...secureJsonFields, basicAuth: false },
        secureJsonData: { basicAuth: '' },
      });
    }
  };

  const onPasswordChange = (e: ChangeEvent<HTMLInputElement>) => {
    setPassword(e.target.value);
    onOptionsChange({
      ...options,
      secureJsonData: { basicAuth: toBase64(`${jsonData.username ?? ''}:${e.target.value}`) },
    });
  };

  const onPasswordReset = () => {
    setPassword('');
    onOptionsChange({
      ...options,
      secureJsonFields: { ...secureJsonFields, basicAuth: false },
      secureJsonData: { basicAuth: '' },
    });
  };

  const platformOptions = [...PLATFORMS];
  if (jsonData.apiUrl && !PLATFORMS.some((p) => p.value === jsonData.apiUrl)) {
    platformOptions.push({ label: jsonData.apiUrl, value: jsonData.apiUrl });
  }

  return (
    <>
      <h3>Qualys API</h3>
      <InlineField
        label="API server URL"
        labelWidth={LW}
        tooltip="The Qualys API server of your platform (Help > About in the Qualys UI). A custom URL can be typed in."
      >
        <Select
          inputId="qualys-api-url"
          width={60}
          options={platformOptions}
          value={jsonData.apiUrl ?? null}
          allowCustomValue
          placeholder="Select platform or enter URL"
          onChange={(v) => setJson({ apiUrl: (v?.value ?? '').replace(/\/+$/, '') })}
          onCreateOption={(v) => setJson({ apiUrl: v.trim().replace(/\/+$/, '') })}
        />
      </InlineField>
      <InlineField label="User name" labelWidth={LW} tooltip="API user with VMDR and/or TotalAppSec (WAS) API access">
        <Input id="qualys-username" width={40} value={jsonData.username ?? ''} onChange={onUsernameChange} />
      </InlineField>
      <InlineField label="Password" labelWidth={LW} tooltip="Stored encrypted; only the Grafana data proxy uses it">
        <SecretInput
          id="qualys-password"
          width={40}
          isConfigured={!!secureJsonFields?.basicAuth}
          value={password}
          placeholder="Password"
          onReset={onPasswordReset}
          onChange={onPasswordChange}
        />
      </InlineField>

      <h3 style={{ marginTop: 24 }}>Data loading</h3>
      <InlineField
        label="Page size"
        labelWidth={LW}
        tooltip="Hosts per VMDR detection page (truncation_limit) / records per TAS page (max 1000). Lower it if requests time out."
      >
        <Input
          type="number"
          width={16}
          placeholder="500"
          value={jsonData.pageSize ?? ''}
          onChange={setNumber('pageSize')}
        />
      </InlineField>
      <InlineField label="Max pages" labelWidth={LW} tooltip="Safety limit of pages per data set">
        <Input
          type="number"
          width={16}
          placeholder="200"
          value={jsonData.maxPages ?? ''}
          onChange={setNumber('maxPages')}
        />
      </InlineField>
      <InlineField
        label="Cache TTL (minutes)"
        labelWidth={LW}
        tooltip="Downloaded data sets are shared by all panels and reused for this long (per browser session)"
      >
        <Input
          type="number"
          width={16}
          placeholder="15"
          value={jsonData.cacheTtlMinutes ?? ''}
          onChange={setNumber('cacheTtlMinutes')}
        />
      </InlineField>
      <InlineField
        label="Parallel requests"
        labelWidth={LW}
        tooltip="Qualys limits concurrent API calls per subscription (default 2)"
      >
        <Input
          type="number"
          width={16}
          placeholder="2"
          value={jsonData.concurrency ?? ''}
          onChange={setNumber('concurrency')}
        />
      </InlineField>
      <InlineField
        label="KnowledgeBase enrichment"
        labelWidth={LW}
        tooltip="Look up title, category, CVEs, CVSS v3, threat indicators and patchability for every QID"
      >
        <InlineSwitch
          value={jsonData.enrichKb !== false}
          onChange={(e) => setJson({ enrichKb: e.currentTarget.checked })}
        />
      </InlineField>

      <Alert severity="info" title="Bundled dashboards" style={{ marginTop: 16 }}>
        After saving, open the <b>Dashboards</b> tab of this data source to import the VMDR and TotalAppSec dashboards.
      </Alert>
    </>
  );
}
