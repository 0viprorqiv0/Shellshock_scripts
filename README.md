# Shellshock laboratory scripts and configurations

Supporting files for the Shellshock assessment on Kali, an Ubuntu gateway and Metasploitable 2. This folder can be uploaded as a standalone GitHub repository or as a directory in a larger repository.

| File | Machine | Purpose |
| :--- | :--- | :--- |
| `recon_evidence.sh` | Kali | Collect routing, host discovery, selected TCP service/OS results and optional Shellshock NSE evidence |
| `block_callback_lab.sh` | Ubuntu gateway | Prepare the scoped TCP/4444 LOG/DROP experiment; save preceding firewall state |
| `firewall_rules.reference.sh` | Ubuntu gateway | Historical default-DROP firewall reference used in the report |
| `snort.local.rules` | Gateway / Snort | Local detection rule reference |
| `suricata.local.rules` | Gateway / Suricata | Local detection rule reference |
| `suricata.reference.yaml` | Gateway / Suricata | Configuration excerpt; merge into the installed configuration |
| `gateway.netplan.reference.yaml` | Ubuntu gateway | Laboratory interface/address reference |
| `report-3bae37b8-c055-4d30-bf76-64ebbfd7e219.xml` | Greenbone | Anonymous November 13 scan export with 65 filtered results |
| `recon_evidence_README.md` | Documentation | Reconnaissance usage and evidence interpretation |

## Reconnaissance

On Kali, from this directory:

```bash
bash recon_evidence.sh --shellshock
```

Add `--extended` for the additional scan variants. The fixed target is `172.16.1.10`; the tested Kali address is `10.10.1.10`. Read [the usage notes](recon_evidence_README.md) for output files and limits.

## Gateway experiments

The callback script changes forwarding rules and resets its test counters when rerun. The historical firewall script flushes the filter table and installs DROP policies; it differs from the final scoped ACCEPT-policy ruleset in the report. Inspect these files before applying them to the lab gateway.

IDS rules and YAML files are references for the recorded lab versions. Interface names, engine syntax and effective settings must match the VM being tested. Configuration files alone do not establish that a control was active.

The anonymous Greenbone XML export is included alongside the scripts. Evidence transcripts, screenshots, report backups and report-generation tools are kept outside this repository. For a Word report, cite each file and retain the tested commit identifier.
