# Qualys Grafana Plugin (`qwe1qwe-qualys-datasource`)

Grafana-Datasource-Plugin, das über die Qualys-API **VMDR**-Detections/Hosts und **TotalAppSec (TAS)**-Findings/Web-Apps abholt, plus zwei mitgelieferte Dashboards:

- **Qualys VMDR - Overview**: KPIs (offene Detections, betroffene Hosts, Exploit-verfügbar, patchbar, neu/behoben, MTTR), Trends (neu vs. behoben, offener Backlog je Severity), Top-Hosts, Top-Schwachstellen, OS/Kategorien/Tags, Top-CVEs, RTI, QDS, Detailtabelle, Asset-Hygiene (Hosts ohne Scan).
- **Qualys TotalAppSec - Overview**: KPIs, Trends, Top-Web-Apps, OWASP Top 10, Status/Typ/Gruppe/Alter, Top-CWE, Top-Schwachstellen, Quelle (Scanner), Detailtabelle, Web-App-Inventar.

Beide Dashboards haben Variablen für Data source, Severity, Status, Typ, Asset-/Web-App-Tag bzw. Web-App und einen freien Filter.

## Architektur

```
Browser (Panels) ──► Grafana-Data-Proxy  ──►  Qualys API
  src/datasource.ts      Route "qualys" aus plugin.json:
  src/qualys/*           URL = jsonData.apiUrl
                         Authorization: Basic {{ secureJsonData.basicAuth }}
                         X-Requested-With
```

- Reines Frontend-Plugin (kein Go-Backend). Zugangsdaten liegen verschlüsselt in Grafana (`secureJsonData`) und werden nur serverseitig vom Data-Proxy eingesetzt.
- `src/qualys/client.ts` – Paginierung (VMDR über `id_min`, TAS über `id GREATER lastId`), Concurrency-Limit, Retry bei HTTP 409, Cache (alle Panels mit gleichem API-Filter teilen sich einen Download), KnowledgeBase-Anreicherung (12 h Cache).
- `src/qualys/parse.ts` – XML-Parser für VMDR/KB, JSON-Mapping für TAS (QPS REST).
- `src/qualys/transform.ts` – Filterausdrücke, Aggregationen, Grafana-Frames.
- `src/dashboards/*.json` – mitgelieferte Dashboards (in `plugin.json` unter `includes`).

Folge: Grafana-Alerting funktioniert mit dieser Data source nicht (dafür bräuchte es ein Go-Backend).

## Query-Editor

| Option              | Bedeutung                                                                                                                                                         |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Data set            | `VMDR detections`, `VMDR hosts`, `TAS findings`, `TAS web apps`                                                                                                   |
| API-Filter          | Severity, Status, Typ, QIDs, IPs, Asset-Tags (VMDR) bzw. Severity, Status, Typ, Web-App-Name/-Tag (TAS). Werden an Qualys geschickt. Dashboard-Variablen erlaubt. |
| Format              | `Table`, `Count`, `Group by`, `Time series`                                                                                                                       |
| Metric              | `count`, `distinct` (z. B. Hosts), `avg`/`max`/`min`/`sum` eines Zahlenfeldes (z. B. `age_days`)                                                                  |
| Group by / Split by | Gruppierung bzw. eine Spalte/Serie pro Wert (z. B. `severity`). Mehrwertige Felder (`tags`, `cves`, `owasp`, `cwe`, `rti`) werden aufgefächert.                   |
| Time field          | Zeitreihe nach `first_found`, `last_found`, `last_fixed` … oder `open_backlog` (offene Findings je Zeitpunkt; Status-Filter muss `Fixed` enthalten)               |
| Filter              | Client-seitig, Bedingungen mit `;` getrennt: `=`, `!=`, `>`, `>=`, `<`, `<=`, `~` (enthält), `!~`. Beispiel: `severity>=4; os~windows; cves!=(none)`              |
| Only in time range  | Nur Datensätze, deren Zeitfeld im Dashboard-Zeitraum liegt                                                                                                        |

Felder VMDR detections: `host, ip, dns, netbios, os, host_id, tracking_method, tags, qid, title, severity, type, status, category, port, protocol, ssl, qds, qds_severity, cvss3, cves, rti, patchable, first_found, last_found, last_fixed, times_found, age_days, age_bucket, is_ignored, is_disabled`

Felder TAS findings: `webapp, webapp_id, webapp_url, webapp_tags, finding_id, qid, name, severity, type, finding_type, group, status, potential, url, owasp, cwe, wasc, cvss3, first_found, last_found, last_tested, last_fixed, times_detected, age_days, age_bucket, is_ignored`

Template-Variablen (Query-Variable): `vmdr:tags`, `vmdr:os`, `tas:webapp`, `tas:tags` – allgemein `<dataset>:<feld>`.

## Qualys-Benutzer

Ein API-fähiger Benutzer mit Lesezugriff auf VMDR (Host Detection, KnowledgeBase, Host List) und – für TAS – das WAS/TotalAppSec-Modul. Fehlt eines davon, meldet _Save & test_ das pro Bereich, der andere funktioniert trotzdem.

## Bauen & lokal testen

Voraussetzung: Node.js ≥ 22, Docker (für die Test-Grafana).

```bash
npm install
npm run build          # Produktions-Build nach dist/
npm run test:ci        # Unit-Tests (Parser, Client, Transformationen, Dashboards)
npm run typecheck
npm run lint
```

Lokale Grafana mit vorkonfigurierter Data source und Dashboards:

```bash
cp .env.example .env   # QUALYS_API_URL, QUALYS_USERNAME, QUALYS_BASIC_AUTH eintragen
npm run dev            # baut im Watch-Modus
docker compose up      # http://localhost:3000
```

`QUALYS_BASIC_AUTH` ist `base64("<user>:<passwort>")`, in PowerShell:

```powershell
[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("myapiuser:secret"))
```

## Installation in einer bestehenden Grafana

1. `npm run build`, dann den Inhalt von `dist/` nach `<grafana>/plugins/qwe1qwe-qualys-datasource/` kopieren (Docker: `/var/lib/grafana/plugins/…`).
2. Da das Plugin nicht signiert ist, in `grafana.ini`:
   ```ini
   [plugins]
   allow_loading_unsigned_plugins = qwe1qwe-qualys-datasource

   [dataproxy]
   timeout = 300
   ```
   bzw. per Umgebungsvariablen `GF_PLUGINS_ALLOW_LOADING_UNSIGNED_PLUGINS` und `GF_DATAPROXY_TIMEOUT`.
3. Grafana neu starten (nötig nach jeder Änderung an `plugin.json`).
4. Data source **Qualys** anlegen, Plattform, Benutzer, Passwort eintragen, _Save & test_.
5. Im Tab **Dashboards** der Data source die beiden Dashboards importieren – oder per Provisioning (`provisioning/dashboards/qualys.yml`).

Mindestversion laut `plugin.json`: Grafana 11.0.

## Grenzen / Hinweise

- Große Subscriptions: alle Detections werden in den Browser geladen. Seitengröße (Standard 500 Hosts) und `Max pages` in der Data source regeln das; der Cache verhindert Mehrfach-Downloads pro Dashboard.
- Qualys-Limits: standardmäßig 2 parallele API-Calls pro Subscription; bei Überschreitung (HTTP 409) wird bis zu 4× mit Backoff wiederholt. Rate-Limits pro Stunde werden als Fehler angezeigt.
- Der offene Backlog ist aus `first_found`/`last_fixed` rekonstruiert; zwischenzeitliches Fixen und Wiederöffnen wird nicht abgebildet.
- Die Felder der TAS-API wurden defensiv gemappt (z. B. `fixedDate`); sollte eure Subscription abweichende Feldnamen liefern, `mapTasFinding` in `src/qualys/parse.ts` anpassen.
