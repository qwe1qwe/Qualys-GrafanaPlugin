# Qualys Data Source

Bringt Daten aus **Qualys VMDR** und **Qualys TotalAppSec (TAS / WAS)** nach Grafana und liefert zwei fertige Dashboards mit.

## Daten

| Data set        | Qualys API                                             | Inhalt                                                                                   |
| --------------- | ------------------------------------------------------ | ---------------------------------------------------------------------------------------- |
| VMDR detections | `/api/2.0/fo/asset/host/vm/detection/` + KnowledgeBase | Schwachstellen je Host inkl. Titel, CVEs, CVSS v3, QDS, Threat-Indikatoren, Patchbarkeit |
| VMDR hosts      | `/api/2.0/fo/asset/host/`                              | Host-Inventar mit Tags und letztem Scan                                                  |
| TAS findings    | `/qps/rest/3.0/search/was/finding`                     | Web-/API-Findings inkl. OWASP, CWE, WASC, CVSS v3                                        |
| TAS web apps    | `/qps/rest/3.0/search/was/webapp`                      | Web-Applikationen                                                                        |

Jede Abfrage kann als **Tabelle**, **Zähler**, **Group by** (z. B. Top-Hosts, OWASP-Kategorien) oder **Zeitreihe** (neu / behoben / offener Backlog) ausgegeben werden.

## Einrichtung

1. Data source hinzufügen → **Qualys**.
2. Plattform (API-Server-URL), Benutzer und Passwort eines Qualys-API-Benutzers eintragen.
3. **Save & test** prüft VMDR- und TAS-API getrennt.
4. Im Tab **Dashboards** der Data source die beiden Dashboards importieren.

Die Zugangsdaten werden verschlüsselt in Grafana gespeichert und nur vom Grafana-Data-Proxy verwendet; der Browser sieht sie nie.

## Hinweise

- Alle Panels mit gleichem API-Filter teilen sich einen Download (Cache-Dauer einstellbar, Standard 15 min).
- Qualys begrenzt parallele API-Aufrufe; das Plugin hält sich an das konfigurierte Limit (Standard 2) und wiederholt Anfragen bei HTTP 409.
- Bei großen Umgebungen `[dataproxy] timeout` in der Grafana-Konfiguration erhöhen (z. B. 300 s) oder die Seitengröße senken.
- Das Plugin hat kein Backend; Grafana-Alerting auf diese Data source ist daher nicht möglich.
