# Greenbone scan reconciliation: historical evidence

This reference preserves the two-run comparison. The main report uses the November 13 scan as the latest available result. The November 15 date refers to receipt of its overview screenshot.

#### 2.2.6 Greenbone report reconciliation

The original interface capture reports 154 of 532 results for 172.16.1.10: 12 Critical, 7 High, 40 Medium, 6 Low, and 89 Log/informational. The original XML contains 65 filtered records because it uses levels=chml and min_qod=70. Therefore, 154 is the GUI result total for that capture, while 532 is a full result count rather than a test count or unique CVE count. [Greenbone interface](../../images/06_lab2_openvas_gvm.png) | [Original XML](../../images/06_lab2_openvas_report.xml)

The later overview supplied on November 15 shows **157 of 576** results. Its severity chart contains 12 Critical, 7 High, 40 Medium, 6 Low and 92 Log entries. The 65 severity-bearing records therefore agree with the later filtered XML total, while the extra 92 are informational Log records. This is a different scan from the original **154 of 532** overview, whose 89 Log entries remain attached to that original run. [Later overview](../../images/Screenshot%202026-11-15%20125300.png)

Two anonymous XML exports must remain separate:

| Attribute | Original report | Later report |
| :--- | :--- | :--- |
| Report ID | f1991541-1d10-4950-b695-b706e3abd88d | 3bae37b8-c055-4d30-bf76-64ebbfd7e219 |
| Scan window UTC | 2026-11-03 20:42:43–21:27:55 | 2026-11-13 16:14:42–18:37:24 |
| Full results | 532 | 576 |
| Results displayed in the corresponding GUI overview | 154 | 157 |
| Log records displayed in that overview | 89 | 92 |
| Filtered exported results | 65 | 65 |
| Host fields | 127.0.0.1 | 127.0.0.1 |
| Shellshock severity/QoD | 9.8 / 99% | 9.8 / 99% |

Both exports classify to 12 Critical, 7 High, 40 Medium and 6 Low numeric records. The host fields are anonymized, so neither XML proves the real target IP alone. The later detailed finding screenshot supplies direct host and endpoint context: 172.16.1.10:80, /cgi-bin/test.cgi, injected User-Agent and uid=33(www-data) gid=33. Its NVT OID, severity, QoD and displayed time support association with the later report, but the report ID is not visible in the screenshot.

![Greenbone overview showing 157 of 576 results](../../images/Screenshot%202026-11-15%20125300.png)

*Screenshot 2. Kali GVM overview of the later scan: 157 displayed results out of 576 full results, comprising 12 Critical, 7 High, 40 Medium, 6 Low and 92 Log entries. The Shellshock row identifies 172.16.1.10:80, severity 9.8 and QoD 99%. Version 28.3.0 is the interface version, not an identification of every scanner component.*

#### 2.2.7 Greenbone result interpretation

The scanner's Shellshock result is an active check, not a banner-only identification. Both exports contain the NVT “GNU Bash Environment Variable Handling RCE Vulnerability (Shellshock, HTTP, CVE-2014-6271/CVE-2014-6278) - Active Check”, OID `1.3.6.1.4.1.25623.1.0.804489`, port `80/tcp`, severity 9.8 and QoD 99%.

| Severity group | Original XML | Later XML | Meaning |
| :--- | ---: | ---: | :--- |
| Critical | 12 | 12 | High severity result records |
| High | 7 | 7 | High severity result records |
| Medium | 40 | 40 | Medium severity result records |
| Low | 6 | 6 | Low severity result records |
| Filtered total | 65 | 65 | XML result nodes after filter |
| Full total | 532 | 576 | All results in each report |
| GUI displayed total | 154 | 157 | Severity-bearing plus Log records in each overview |
| GUI Log records | 89 | 92 | Informational records excluded from these XML exports |

The original GUI's 89 Log records are informational and not proof of additional confirmed vulnerabilities. QoD 99% is Greenbone's confidence in its detection method; it is not a 99% attack success probability. The report therefore uses Greenbone as corroboration and relies on the manual HTTP response and Metasploit session for execution proof.

