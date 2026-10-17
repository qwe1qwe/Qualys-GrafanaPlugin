/** Trimmed but structurally faithful Qualys API responses used by the unit tests. */

export const DETECTIONS_PAGE_1 = `<?xml version="1.0" encoding="UTF-8" ?>
<!DOCTYPE HOST_LIST_VM_DETECTION_OUTPUT SYSTEM "https://qualysapi.qualys.eu/api/2.0/fo/asset/host/vm/detection/host_list_vm_detection_output.dtd">
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-01T10:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>1001</ID>
        <IP>10.0.0.10</IP>
        <TRACKING_METHOD>QAGENT</TRACKING_METHOD>
        <OS><![CDATA[Windows Server 2019]]></OS>
        <DNS><![CDATA[srv-app01.corp.local]]></DNS>
        <NETBIOS><![CDATA[SRV-APP01]]></NETBIOS>
        <LAST_SCAN_DATETIME>2026-09-30T08:00:00Z</LAST_SCAN_DATETIME>
        <TAGS>
          <TAG><TAG_ID>1</TAG_ID><NAME><![CDATA[Server]]></NAME></TAG>
          <TAG><TAG_ID>2</TAG_ID><NAME><![CDATA[DMZ]]></NAME></TAG>
        </TAGS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>91234</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <SSL>0</SSL>
            <STATUS>Active</STATUS>
            <FIRST_FOUND_DATETIME>2026-08-01T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-09-30T08:00:00Z</LAST_FOUND_DATETIME>
            <QDS severity="CRITICAL">95</QDS>
            <TIMES_FOUND>12</TIMES_FOUND>
            <IS_IGNORED>0</IS_IGNORED>
            <IS_DISABLED>0</IS_DISABLED>
          </DETECTION>
          <DETECTION>
            <QID>38170</QID>
            <TYPE>Potential</TYPE>
            <SEVERITY>3</SEVERITY>
            <PORT>443</PORT>
            <PROTOCOL>tcp</PROTOCOL>
            <SSL>1</SSL>
            <STATUS>New</STATUS>
            <FIRST_FOUND_DATETIME>2026-09-25T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-09-30T08:00:00Z</LAST_FOUND_DATETIME>
            <QDS severity="MEDIUM">40</QDS>
            <TIMES_FOUND>1</TIMES_FOUND>
            <IS_IGNORED>0</IS_IGNORED>
            <IS_DISABLED>0</IS_DISABLED>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
    <WARNING>
      <CODE>1980</CODE>
      <TEXT>1 record limit exceeded. Use URL to get next batch of results.</TEXT>
      <URL><![CDATA[https://qualysapi.qualys.eu/api/2.0/fo/asset/host/vm/detection/?action=list&truncation_limit=1&id_min=1002]]></URL>
    </WARNING>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>`;

export const DETECTIONS_PAGE_2 = `<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_VM_DETECTION_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-01T10:00:01Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>1002</ID>
        <IP>10.0.0.20</IP>
        <TRACKING_METHOD>IP</TRACKING_METHOD>
        <OS><![CDATA[Ubuntu 22.04]]></OS>
        <TAGS>
          <TAG><TAG_ID>1</TAG_ID><NAME><![CDATA[Server]]></NAME></TAG>
        </TAGS>
        <DETECTION_LIST>
          <DETECTION>
            <QID>91234</QID>
            <TYPE>Confirmed</TYPE>
            <SEVERITY>5</SEVERITY>
            <STATUS>Fixed</STATUS>
            <FIRST_FOUND_DATETIME>2026-07-01T00:00:00Z</FIRST_FOUND_DATETIME>
            <LAST_FOUND_DATETIME>2026-08-01T00:00:00Z</LAST_FOUND_DATETIME>
            <LAST_FIXED_DATETIME>2026-08-11T00:00:00Z</LAST_FIXED_DATETIME>
            <TIMES_FOUND>4</TIMES_FOUND>
          </DETECTION>
        </DETECTION_LIST>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_VM_DETECTION_OUTPUT>`;

export const KB = `<?xml version="1.0" encoding="UTF-8" ?>
<KNOWLEDGE_BASE_VULN_LIST_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-01T10:00:02Z</DATETIME>
    <VULN_LIST>
      <VULN>
        <QID>91234</QID>
        <VULN_TYPE>Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>5</SEVERITY_LEVEL>
        <TITLE><![CDATA[Microsoft Windows Security Update - September 2026]]></TITLE>
        <CATEGORY>Windows</CATEGORY>
        <PATCHABLE>1</PATCHABLE>
        <CVE_LIST>
          <CVE><ID><![CDATA[CVE-2026-1111]]></ID><URL><![CDATA[https://nvd]]></URL></CVE>
          <CVE><ID><![CDATA[CVE-2026-2222]]></ID><URL><![CDATA[https://nvd]]></URL></CVE>
        </CVE_LIST>
        <CVSS_V3><BASE>9.8</BASE><TEMPORAL>8.8</TEMPORAL></CVSS_V3>
        <THREAT_INTELLIGENCE>
          <THREAT_INTEL id="1"><![CDATA[Zero_Day]]></THREAT_INTEL>
          <THREAT_INTEL id="5"><![CDATA[Exploit_Public]]></THREAT_INTEL>
        </THREAT_INTELLIGENCE>
      </VULN>
      <VULN>
        <QID>38170</QID>
        <VULN_TYPE>Potential Vulnerability</VULN_TYPE>
        <SEVERITY_LEVEL>3</SEVERITY_LEVEL>
        <TITLE><![CDATA[SSL Certificate - Subject Common Name Does Not Match Server FQDN]]></TITLE>
        <CATEGORY>General remote services</CATEGORY>
        <PATCHABLE>0</PATCHABLE>
      </VULN>
    </VULN_LIST>
  </RESPONSE>
</KNOWLEDGE_BASE_VULN_LIST_OUTPUT>`;

export const HOSTS = `<?xml version="1.0" encoding="UTF-8" ?>
<HOST_LIST_OUTPUT>
  <RESPONSE>
    <DATETIME>2026-10-01T10:00:00Z</DATETIME>
    <HOST_LIST>
      <HOST>
        <ID>1001</ID>
        <IP>10.0.0.10</IP>
        <TRACKING_METHOD>QAGENT</TRACKING_METHOD>
        <DNS><![CDATA[srv-app01.corp.local]]></DNS>
        <OS><![CDATA[Windows Server 2019]]></OS>
        <LAST_VULN_SCAN_DATETIME>2026-09-30T08:00:00Z</LAST_VULN_SCAN_DATETIME>
        <TAGS><TAG><TAG_ID>1</TAG_ID><NAME><![CDATA[Server]]></NAME></TAG></TAGS>
      </HOST>
    </HOST_LIST>
  </RESPONSE>
</HOST_LIST_OUTPUT>`;

export const SIMPLE_RETURN_ERROR = `<?xml version="1.0" encoding="UTF-8" ?>
<SIMPLE_RETURN>
  <RESPONSE>
    <DATETIME>2026-10-01T10:00:00Z</DATETIME>
    <CODE>1965</CODE>
    <TEXT>This API cannot be run again until 1 currently running instance has finished.</TEXT>
  </RESPONSE>
</SIMPLE_RETURN>`;

export const TAS_FINDINGS_PAGE_1 = JSON.stringify({
  ServiceResponse: {
    responseCode: 'SUCCESS',
    count: 2,
    hasMoreRecords: 'true',
    lastId: 502,
    data: [
      {
        Finding: {
          id: 501,
          uniqueId: 'a-1',
          qid: 150001,
          name: 'Reflected Cross-Site Scripting (XSS) Vulnerabilities',
          type: 'VULNERABILITY',
          findingType: 'QUALYS',
          group: 'XSS',
          severity: '5',
          status: 'ACTIVE',
          potential: 'false',
          url: 'https://shop.example.com/search?q=',
          owasp: { count: 1, list: [{ OWASP: { name: 'Injection', code: 3, url: 'https://owasp.org' } }] },
          wasc: { count: 1, list: [{ WASC: { name: 'CROSS-SITE SCRIPTING', code: 8 } }] },
          cwe: { count: 1, list: [79] },
          cvssV3: { base: 6.1, temporal: 5.8 },
          firstDetectedDate: '2026-09-01T10:00:00Z',
          lastDetectedDate: '2026-09-29T10:00:00Z',
          lastTestedDate: '2026-09-29T10:00:00Z',
          timesDetected: 5,
          isIgnored: 'false',
          webApp: {
            id: 11,
            name: 'Webshop',
            url: 'https://shop.example.com',
            tags: { count: 1, list: [{ Tag: { id: 9, name: 'Prod' } }] },
          },
        },
      },
      {
        Finding: {
          id: 502,
          qid: 150002,
          name: 'SQL Injection',
          type: 'VULNERABILITY',
          group: 'SQL',
          severity: '4',
          status: 'NEW',
          firstDetectedDate: '2026-09-20T10:00:00Z',
          lastDetectedDate: '2026-09-29T10:00:00Z',
          webApp: { id: 11, name: 'Webshop', url: 'https://shop.example.com' },
        },
      },
    ],
  },
});

export const TAS_FINDINGS_PAGE_2 = JSON.stringify({
  ServiceResponse: {
    responseCode: 'SUCCESS',
    count: 1,
    hasMoreRecords: 'false',
    data: [
      {
        Finding: {
          id: 777,
          qid: 150003,
          name: 'Credit card number disclosed',
          type: 'SENSITIVE_CONTENT',
          group: 'CC',
          severity: '3',
          status: 'FIXED',
          firstDetectedDate: '2026-08-01T00:00:00Z',
          lastDetectedDate: '2026-08-15T00:00:00Z',
          fixedDate: '2026-08-21T00:00:00Z',
          webApp: { id: 12, name: 'Portal', url: 'https://portal.example.com' },
        },
      },
    ],
  },
});

export const TAS_ERROR = JSON.stringify({
  ServiceResponse: {
    responseCode: 'UNAUTHORIZED',
    responseErrorDetails: { errorMessage: 'User does not have WAS module enabled' },
  },
});
