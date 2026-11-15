# Bash remediation procedure: detailed reference

This is a proposed procedure, not evidence of a completed update. The local test (C1) still prints the injected marker, and the HTTP test (C2) still executes `id`. Successful remediation requires new verification evidence.

## 1. Select a release-specific correction

Metasploitable 2 runs an obsolete Ubuntu release. Canonical's [USN-2362-1](https://ubuntu.com/security/notices/USN-2362-1) addresses CVE-2014-6271, [USN-2363-1](https://ubuntu.com/security/notices/USN-2363-1) addresses CVE-2014-7169, and [USN-2364-1](https://ubuntu.com/security/notices/USN-2364-1) records later parser fixes. USN-2364-1 lists fixed packages for Ubuntu 10.04, 12.04 and 14.04, while this lab identifies an Ubuntu 8.04 image. I would therefore recommend migration to a supported release, vendor updates, and a retest of the actual CGI path. An arbitrary Bash binary from another release should not be copied into the VM.

The historical notice also shows why the complete distribution revision must be checked before selecting a package:

| Ubuntu release in USN-2364-1 | Historical fixed Bash package | Applicability |
| :--- | :--- | :--- |
| 14.04 LTS | 4.3-7ubuntu1.4 | Historical fix for that release, not a present-day deployment recommendation |
| 12.04 LTS | 4.2-2ubuntu2.5 | Vendor revision includes fixes despite the lower upstream version |
| 10.04 LTS | 4.1-2ubuntu3.4 | Release-specific package, not an Ubuntu 8.04 package |
| Observed target | 3.2-0ubuntu16 | Positively reproduces the tested vulnerability |
| Fixed Ubuntu 8.04 package | Not established by this notice | No safe revision is invented for the target |

| Condition | Correction route | Evidence to retain |
| :--- | :--- | :--- |
| Supported distribution | Install its vendor Bash security update | Repository provenance, package transaction, full revision and retests |
| Legacy teaching VM | Preserve the controlled baseline; migrate the exposed service to a supported replacement | Snapshot identity, replacement release and separate CGI acceptance results |
| Authorized offline legacy exercise | Use a release-compatible package or reviewed backport with verified origin and dependencies | Advisory applicability, package/build origin, dependency checks and actual-binary tests |
| No verifiable correction | Keep remediation open; remove the test CGI when teaching ends | Deferral reason and confirmation of exposure removal |

A fixed replacement would not change the original VM's earlier result. Removing CGI would close this exposure path, but it would not establish that every Bash installation is patched. Installing Bash 4.3 or only the first Shellshock patch would also be insufficient because follow-on fixes were required.

## 2. Preserve the baseline and identify the actual interpreter

Before changing the Target, record a VMware snapshot name and export the evidence outside the VM. Its existence is not assumed from this instruction. On the **Target**, record the pre-change state:

```bash
date -u
uname -a
cat /etc/issue
readlink -f /bin/bash
/bin/bash --version
command -v bash
dpkg-query -W bash
dpkg-query -S /bin/bash
head -n 1 /usr/lib/cgi-bin/test.cgi
ls -l /usr/lib/cgi-bin/test.cgi
sha256sum /bin/bash /usr/lib/cgi-bin/test.cgi
apt-cache policy bash
cat /etc/apt/sources.list
```

The captured state records Bash 3.2.33(1)-release and package 3.2-0ubuntu16. Before changing anything, I would back up the artifacts without flushing the firewall. Run the following commands on the Target, using a directory owned by the logged-in lab account and reserving sudo for the protected source files:

```bash
mkdir -p "$HOME/evidence-run01"
sudo install -m 600 /usr/lib/cgi-bin/test.cgi "$HOME/evidence-run01/test.cgi.pre-remediation"
dpkg-query -W | tee "$HOME/evidence-run01/dpkg-query.pre-remediation.txt"
```

On the **Gateway**, save its forwarding policy separately:

```bash
mkdir -p "$HOME/evidence-run01"
sudo iptables-save -c | tee "$HOME/evidence-run01/iptables.pre-remediation.v4" >/dev/null
```

Resolve the shebang interpreter and its symbolic links before comparing package ownership. If the replacement uses /usr/bin/env bash, determine the CGI worker's effective PATH instead of assuming the interactive user's PATH. A file hash identifies the binary that was tested, but a changed hash alone does not prove a security fix.

## 3. Apply and verify a supported vendor update

On the Target, proceed only after confirming that the release has a supported vendor security channel. Use vendor repositories and inspect the candidate:

```bash
sudo apt-get update
apt-cache policy bash
apt-cache madison bash
apt changelog bash | sed -n '1,120p'
sudo apt-get install --only-upgrade bash
dpkg-query -W bash
dpkg-query -S /bin/bash
readlink -f /bin/bash
/bin/bash --version
if command -v debsums >/dev/null 2>&1; then
  sudo debsums -s bash
else
  printf 'debsums is not installed; package-file verification remains pending\n' >&2
fi
```

A package version becomes meaningful only when it is compared with the advisory for the installed release. If the legacy VM cannot reach a supported repository, the patch claim should remain open. The documented options are migration or an authorized, release-specific offline package after signature and dependency checks.

Save transaction output, including repository, dependency or signature errors. A failed refresh, unchanged candidate or no-op upgrade does not establish a fix. The optional debsums check tests file consistency against package metadata, not CVE coverage. Confirm that new CGI invocations use the replaced interpreter; long-running processes retaining an old executable need separate attention.

## 4. Repeat the local probe before and after correction

On the Target, run the same local test before and after:

```bash
date -u
env x='() { :;}; echo LOCAL_SHELLSHOCK_MARKER' \
  bash -c 'echo NORMAL_COMMAND'
bash --version
dpkg-query -W bash
```

| Output | Interpretation |
| :--- | :--- |
| Marker appears | Bash still executes injected trailing command |
| NORMAL_COMMAND appears | Intended command ran |
| Marker absent and normal command present | This activation no longer reproduces |
| Error or no normal command | Inconclusive |

This test covers one activation form and the Bash selected by the caller's environment. Apache may invoke a different absolute binary, so the CGI path still requires its own retest.

For the captured shebang, also test its absolute interpreter:

```bash
env x='() { :;}; echo LOCAL_SHELLSHOCK_MARKER' \
  /bin/bash -c 'echo NORMAL_COMMAND'
```

Retain stdout, stderr, time, interpreter path and full package revision on both sides of the comparison. Examine executed output, not marker text printed as part of the command line. Package-specific import warnings may differ, but NORMAL_COMMAND must still execute without the injected marker.

## 5. Test CGI without masking application execution

This test uses the Gateway, Kali and Target. Retest HTTP without masking the application path. Preserve the Gateway state and add only two exact temporary exceptions if the active scoped DROP rules would otherwise hide application behavior: one for Kali to Target TCP/80, and one for the return direction Target to Kali TCP/80. Check for duplicates before inserting them.

```bash
sudo iptables-save -c | tee "$HOME/evidence-run01/iptables.before-http-retest.v4" >/dev/null
sudo iptables -C FORWARD -s 10.10.1.10 -d 172.16.1.10 -p tcp --dport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT 2>/dev/null || \
sudo iptables -I FORWARD 1 -s 10.10.1.10 -d 172.16.1.10 -p tcp --dport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT
sudo iptables -C FORWARD -s 172.16.1.10 -d 10.10.1.10 -p tcp --sport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT 2>/dev/null || \
sudo iptables -I FORWARD 1 -s 172.16.1.10 -d 10.10.1.10 -p tcp --sport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT
```

Review the exception order before proceeding: a matching ACCEPT below an earlier DROP cannot unmask the application. Run the same HTTP comparison before correction and after correction, retaining distinct baseline and post-change files. Remove the temporary rules even when the test fails; no global flush or policy change is needed.

On Kali, run the following requests and save the outputs:

```bash
mkdir -p "$HOME/evidence-run01"
date -u
curl --noproxy '*' --max-time 5 -i \
  http://172.16.1.10/cgi-bin/test.cgi \
  2>&1 | tee "$HOME/evidence-run01/postpatch-http-normal.txt"

curl --noproxy '*' --max-time 5 -i \
  -H 'User-Agent: () { :;}; echo; /usr/bin/id' \
  http://172.16.1.10/cgi-bin/test.cgi \
  2>&1 | tee "$HOME/evidence-run01/postpatch-http-injected.txt"
```

On the Target, in a separate terminal, watch the access log:

```bash
sudo tail -n 0 -F /var/log/apache2/access.log
```

On a text-only Metasploitable console, run tail in the existing Target console and switch to the Kali VM to send requests; a second GUI terminal is unnecessary. The Apache log must be collected on the Target, unless another machine actually receives those Apache records.

The acceptance check requires normal HTTP 200 and no uid=33 or injected marker in the injected response. A timeout by itself is inconclusive. I would correlate the client output with Apache access records and gateway counters before assigning a pass or fail.

| Observation after the proposed update | Classification | Follow-up |
| :--- | :--- | :--- |
| Normal 200; injected id output remains | Fail | Recheck actual interpreter and package; this is C2's present outcome |
| Normal 200; no injected output; same CGI path and verified fixed binary | Candidate pass for this activation | Retain responses, access records and provenance; finish vendor checks |
| Both requests time out | Inconclusive | Investigate routing, listener and firewall |
| CGI fails or returns 500 | Application regression requiring investigation | Inspect interpreter, CGI headers and Apache error log |
| Only an IDS alert is available | Detection observation | Determine application behavior separately |

## 6. Remove temporary exceptions and repeat independent checks

On the Gateway, remove both exact temporary rules with guarded checks. Do not restore the entire pre-test ruleset, because that could undo the scoped security controls already validated in the lab:

```bash
while sudo iptables -C FORWARD -s 10.10.1.10 -d 172.16.1.10 -p tcp --dport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT 2>/dev/null; do
  sudo iptables -D FORWARD -s 10.10.1.10 -d 172.16.1.10 -p tcp --dport 80 \
    -m comment --comment LAB-PATCH-RETEST -j ACCEPT
done
while sudo iptables -C FORWARD -s 172.16.1.10 -d 10.10.1.10 -p tcp --sport 80 \
  -m comment --comment LAB-PATCH-RETEST -j ACCEPT 2>/dev/null; do
  sudo iptables -D FORWARD -s 172.16.1.10 -d 10.10.1.10 -p tcp --sport 80 \
    -m comment --comment LAB-PATCH-RETEST -j ACCEPT
done
sudo iptables -S FORWARD | grep -E 'PATCH-HTTP-RETEST|LAB-PATCH-RETEST' || true
sudo iptables-save -c | tee "$HOME/evidence-run01/iptables.after-http-retest.v4" >/dev/null
```

After the application test passes, repeat the scanner check from Kali through the same controlled, unmasked path. Repeat Nmap before closing the temporary window, or use a separate window with the same scope. An active content DROP can otherwise hide a vulnerable application:

```bash
date -u
nmap -sV -p 80 --script http-shellshock \
  --script-args http-shellshock.uri=/cgi-bin/test.cgi \
  172.16.1.10 -oA ~/evidence-run01/postpatch-nmap-shellshock
```

Use vendor advisories and package changelogs for related Bash checks. A clean single NSE result is supporting evidence, not a complete family audit. If Greenbone is used, record target, task, scan configuration and a non-anonymous export where policy permits.

For Greenbone, keep the new target, task, scan settings and report ID with its results. Do not assign the earlier totals 532 or 576 to a new scan. Preserve permitted host-specific finding details when using anonymous exports. Scanner results corroborate the binary and HTTP checks rather than replacing them.

## 7. Close the laboratory and retain the audit trail

The final step removes the lab CGI and records the final state. Run these commands on the Target only if the course phase is finished:

```bash
sudo rm -f /usr/lib/cgi-bin/test.cgi
date -u
```

On the Gateway, remove only the exact LAB-PATCH-RETEST exceptions as shown above, then save the final ruleset with iptables-save -c. Do not restore the entire pre-remediation file unless a separately approved rollback is required; a blanket restore could undo the scoped HTTP and callback controls already validated. If CGI must remain for teaching, state it as pending cleanup. Current evidence demonstrates removal of known temporary labels, not complete cleanup.

