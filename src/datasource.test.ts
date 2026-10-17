import { of, throwError } from 'rxjs';
import { dateTime } from '@grafana/data';

import { DataSource } from './datasource';
import { DETECTIONS_PAGE_2, KB } from './qualys/__fixtures__/samples';

const fetchMock = jest.fn();
const vars: Record<string, string | string[]> = { severity: ['4', '5'], tag: '$__all', status: 'Active' };

jest.mock('@grafana/runtime', () => ({
  isFetchError: (e: any) => typeof e === 'object' && e !== null && 'status' in e && 'data' in e,
  getBackendSrv: () => ({ fetch: fetchMock }),
  getTemplateSrv: () => ({
    getVariables: () => [],
    replace: (s: string) =>
      s.replace(/\$(\w+)/g, (_: string, n: string) => {
        const v = vars[n];
        return Array.isArray(v) ? v.join(',') : (v ?? '');
      }),
  }),
}));

const settings: any = {
  id: 1,
  uid: 'qualys',
  type: 'qwe1qwe-qualys-datasource',
  name: 'Qualys',
  url: '/api/datasources/proxy/uid/qualys',
  jsonData: { apiUrl: 'https://qualysapi.qualys.eu' },
  meta: {},
};

describe('DataSource', () => {
  beforeEach(() => fetchMock.mockReset());

  it('calls the data proxy route with interpolated filters and returns frames', async () => {
    fetchMock.mockImplementation((req: any) =>
      of({ status: 200, data: req.url.includes('knowledge_base') ? KB : DETECTIONS_PAGE_2 })
    );
    const ds = new DataSource(settings);
    const res = await ds.query({
      targets: [
        {
          refId: 'A',
          queryType: 'vmdr_detections',
          format: 'count',
          severities: ['$severity'],
          statuses: ['$status'],
          tags: '$tag',
        },
      ],
      range: { from: dateTime(0), to: dateTime(), raw: { from: 'now-90d', to: 'now' } },
    } as any);

    const first = fetchMock.mock.calls[0][0];
    expect(first.url).toBe('/api/datasources/proxy/uid/qualys/qualys/api/2.0/fo/asset/host/vm/detection/');
    expect(first.responseType).toBe('text');
    expect(first.params).toMatchObject({ severities: '4,5', status: 'Active' });
    expect(first.params.use_tags).toBeUndefined(); // "All" -> no tag filter
    expect(res.errors).toHaveLength(0);
    expect(res.data[0].fields[0].values[0]).toBe(1);
  });

  it('reports API errors per query', async () => {
    fetchMock.mockImplementation(() => throwError(() => ({ status: 401, data: 'nope', statusText: 'Unauthorized' })));
    const ds = new DataSource(settings);
    const res = await ds.query({
      targets: [{ refId: 'B', queryType: 'vmdr_hosts', format: 'table' }],
      range: { from: dateTime(0), to: dateTime(), raw: { from: 'now-1d', to: 'now' } },
    } as any);
    expect(res.errors?.[0]).toMatchObject({ refId: 'B' });
    expect(res.errors?.[0].message).toMatch(/credentials/);
  });

  it('health check reports VMDR and TAS separately', async () => {
    fetchMock.mockImplementation((req: any) =>
      req.url.includes('/qps/')
        ? throwError(() => ({ status: 403, data: 'forbidden', statusText: 'Forbidden' }))
        : of({ status: 200, data: '<HOST_LIST_OUTPUT><RESPONSE><HOST_LIST/></RESPONSE></HOST_LIST_OUTPUT>' })
    );
    const ds = new DataSource(settings);
    const r = await ds.testDatasource();
    expect(r.status).toBe('success');
    expect(r.message).toMatch(/VMDR API OK/);
    expect(r.message).toMatch(/TAS: Qualys API error \(HTTP 403\)/);
  });
});
