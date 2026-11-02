# SAMONBOARDING – Data protection (GDPR)

[Deutsche Fassung](DATENSCHUTZ.md)

This document describes the personal data SAMONBOARDING processes: where it is kept, how long it is retained and which technical measures are built in. Use it as the basis for your entry in the **record of processing activities** (Art. 30 GDPR).

> **Important:** Software on its own is never "GDPR compliant". What has to comply is the *processing* by the controller, which is you. SAMONBOARDING provides the technical side: data minimisation, storage limitation, no transfer to third parties, access control and subject access. The organisational points in [section 6](#6-what-you-still-have-to-do-as-the-controller) remain your job. This is not legal advice. Agree the use of the tool with your data protection officer.

---

## 1. Summary

| Question | Answer |
|---|---|
| Purpose | Creating, changing, disabling, restoring and deleting user accounts in your own Active Directory |
| Legal basis (typical) | Art. 6(1)(b) GDPR / national employment law (Germany: § 26 BDSG). Reports: Art. 6(1)(f) and Art. 32 GDPR (accountability and security) |
| Where does data go? | Within your own network: the container, domain controller, file servers, Exchange. Plus your SMTP server, possibly at an external mail provider |
| Third parties / third countries | **None.** No cloud, no CDNs, no Google Fonts, no telemetry, no update check |
| Internet access | Not needed. The application does not open any internet connections by itself; it only connects to the DC, file servers and your SMTP and Exchange servers. If you want to shield the container further, restrict its outgoing traffic in the firewall of the host, router or Synology |
| Retention | Reports (changes) 365 days, log 90 days, restore entries 180 days (configurable), then deleted automatically. Delete manually under *Reports* |
| Connection | HTTPS only (TLS 1.2/1.3). Sessions end on sign-out, after 30 minutes of inactivity, after 12 hours at the latest, or on restart |
| Cookies | One strictly necessary session cookie only. No tracking, so no consent banner is needed |

---

## 2. What data is processed

**Data subjects:** employees whose accounts are managed, and the administrators and operators who use the application.

| Data | Where | Purpose |
|---|---|---|
| Account data in AD (name, user name, e-mail, department, company, phone, manager, OU, groups) | **In Active Directory**, not in the application. SAMONBOARDING only reads and writes it there | Account management |
| Reports – changes: time, acting user, action, target account (DN), result, error message if any. **No passwords** | `data/reports.db` (SQLite, table `audit`) | Accountability, security |
| Reports – log: program messages from level *Info* upwards (e.g. connection errors); may contain account names or paths. **No passwords, no per-request IP addresses** | `data/reports.db` (table `applog`) | Operation, troubleshooting |
| Restore entries: user name, name, previous OU, groups, whether enabled, when and by whom offboarded. **No passwords** | `data/offboarding.db` (SQLite) | Undoing an accidental offboarding |
| Sign-in session including the signed-in admin's password (needed to bind to the DC with their own rights) | **Memory only**, never written to disk. Gone after sign-out, 30 minutes of inactivity or restart | Access with the user's own rights |
| Configuration (SMTP account, templates, OUs) | `data/*.json` | Operation |
| Reference list: path (DN) and objectGUID of the OUs and groups chosen in the settings and templates. **No accounts, no personal data** | `data/verweise.json` | Notice when an OU/group was renamed, moved or deleted in AD |
| Account lists of the modules and AD structure (names/DNs for the pickers) (cache, so that switching between pages is fast) | **In memory only**, per session; invalid after 60 seconds and removed on the next access, cleared immediately on every change, on sign-out and on restart. **No copy in a database** | Operation |
| Notification mails (for onboarding and password reset they contain the new password) | Your own mail server, mailbox of the acting employee | Handing over credentials |
| Language setting DE/EN, the last version read in News and the time of the last activity (for sign-out when idle) | Browser `localStorage` | Usability |
| Container log (errors, notices) | Docker log, rotated (3 × 10 MB) | Operation / troubleshooting |

---

## 3. Retention and automatic deletion

| Data | Default | Setting (`.env`) |
|---|---|---|
| Reports – changes | 365 days | `AUDIT_RETENTION_DAYS=365` |
| Reports – log | 90 days | `LOG_RETENTION_DAYS=90` |
| Restore entries | 180 days after offboarding | `OFFBOARD_RETENTION_DAYS=180` |
| Sessions | Sign-out, 30 minutes of inactivity, 12 hours at the latest, or restart | `SESSION_IDLE_MINUTES=30`, `SESSION_MAX_HOURS=12` |
| Container log | max. 30 MB, older output is overwritten | `logging:` in docker-compose.yml |

- Clean-up runs **at start-up and then once a day**. Older entries are removed permanently; the database overwrites deleted entries (`secure_delete`), so they cannot be recovered.
- **Delete manually:** administrators can delete changes or log entries early in the interface under **Reports** (older than 30/90/180 days, or everything), confirmed with their own password. The deletion itself is recorded.
- An `audit.log` from older versions is imported into the database on first start and then deleted.
- `0` means *unlimited*. This is not recommended under the storage limitation principle (Art. 5(1)(e) GDPR).
- A restore entry is also removed immediately when the account is restored or deleted, or when an administrator discards it. The interface shows the retention period above the list.
- To clean up immediately (for example after shortening a period):
  ```bash
  docker compose exec samonboarding python -m samonboarding.privacy bereinigen
  ```
- **Backups:** if you back up `data/`, the retention periods apply to the backups as well. Plan backup retention to match. Before every version change the program itself creates a backup in `data/backups/` (readable only by the program user) and keeps only the last 10. These backups also contain reports and log: the daily clean-up deletes them once they are older than the longest retention period (then everything in them has expired); if a period is `0`, they are kept. Older backups in `backups/` next to the `docker-compose.yml` come from `update.sh` up to version 1.48 and can be deleted after checking.

---

## 4. Technical and organisational measures (Art. 32 GDPR) – what is built in

**Access control**
- The application does not run as root in the container but as its own user without special rights; only this user can read `data/`.
- Sign-in with an AD account only. Every action runs with the signed-in user's own rights on the DC, not with a service account.
- Roles: operator or administrator. Deleting and discarding are reserved for administrators, and the server enforces this.
- Domain admin accounts are protected against offboarding and deletion.
- Lock-out after repeated failed sign-ins (default 5 attempts / 5 minutes).
- The session cookie uses `HttpOnly`, `SameSite=Strict` and `Secure`, and ends when the browser closes. Sessions are held in memory only and end after 30 minutes of inactivity (server and interface).

**Transmission**
- LDAPS to the DC. With `LDAP_CA_FILE` the certificate is verified, and unencrypted LDAP is forbidden by default (`LDAP_ALLOW_PLAIN=false`).
- SMB to the file server is signed. It is encrypted when the file server requires it, which you can enable on the share (`Set-SmbShare -EncryptData $true` or `smb encrypt = required`).
- SMTP with STARTTLS or TLS. In *Auto* mode STARTTLS is used; if the server does not offer it, **nothing** is sent (also when an attacker suppresses STARTTLS). Unencrypted sending is only possible with the explicitly chosen mode *Without encryption* for an internal relay – and then never with an SMTP password.
- **HTTPS only** (TLS 1.2/1.3, modern ciphers). There is no HTTP port. Your own certificate (upload in the interface under *Certificate*, or files in `data/tls/`), otherwise self-signed; with your own certificate HSTS is sent as well.

**Data minimisation**
- No passwords in the reports, the databases or the container log. Individual requests (IP addresses) are not logged.
- No copy of the AD data. The application stores only what it needs for accountability and restore.

**Separation from the internet**
- No external resources. A Content Security Policy header forbids the browser to contact other servers.
- The application does not open any internet connections by itself (no CDNs, no telemetry, no update check). IPv6 is disabled for the container network.
- Security headers: `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin`.

**Storage limitation**
- Automatic deletion after the retention periods ([section 3](#3-retention-and-automatic-deletion)).

**Accountability**
- The reports (changes) record time (local time with time zone), user, action and result; only administrators can view them.

**Safe deletion**
- Deletion only after a simulation and confirmation with your own password.
- Offboarding can be undone.

---

## 5. Data subject rights

**Access (Art. 15):** administrators can download everything SAMONBOARDING itself has stored about an account, meaning changes, matching log entries and restore entries, as a JSON file under *Data protection* in the interface. The download is recorded in the reports. Alternatively, use this command:

```bash
docker compose exec samonboarding python -m samonboarding.privacy auskunft jdoe > access-jdoe.json
```

The search is a text search for the user name. Review the result before handing it out and redact entries about other people. Account data in AD is not included; export it from AD as usual.

**Rectification (Art. 16):** correct the data directly in AD, for example in SAMONBOARDING's user management.

**Erasure (Art. 17):** the deletion function removes the AD account, the profile and home folders, and the restore entry. Report entries are kept until their retention period ends (or until they are deleted manually under *Reports*), because they serve accountability (cf. Art. 17(3)). Decide with your DPO whether this balance suits you; the period can be shortened.

---

## 6. What you still have to do as the controller

- [ ] **Record of processing activities** (Art. 30): add an entry. The template below helps.
- [ ] **Set and document retention periods** (deletion concept). Adjust the defaults if needed, including for backups of `data/`.
- [ ] **Involve the works council**, if you have one. The reports record what administrators do, which in Germany can count as technical monitoring of performance or behaviour (§ 87(1) no. 6 BetrVG).
- [ ] **Upload your own certificate** under *Certificate* (instead of the self-signed one) and leave `LDAP_ALLOW_PLAIN` at `false`.
- [ ] **Restrict access to `data/`** (`chmod 700 data`). Among other things, it holds the SMTP password in plain text.
- [ ] **Weigh up passwords in mails:** onboarding and password-reset mails contain the new password. If they only go internally to the acting employee, this is usually acceptable. Alternatively, leave SMTP disabled and use the PDF or the copy function.
- [ ] **Permissions:** delegate operators only to the OUs they need.
- [ ] **External mail provider** for the notifications? Then conclude or check a data processing agreement (Art. 28) with the provider and list it as a recipient in the record of processing activities.
- [ ] Agree the use of the tool with your **data protection officer**.

### Template: entry in the record of processing activities

| Field | Content |
|---|---|
| Name | Management of user accounts in Active Directory (SAMONBOARDING) |
| Purpose | Joiners and leavers, account maintenance, restore, deletion |
| Legal basis | Art. 6(1)(b) GDPR with national employment law; reports: Art. 6(1)(f), Art. 32 GDPR |
| Data subjects | Employees, external staff with an account, IT administrators |
| Data categories | Master data (name, user name, e-mail, department, company, phone, manager), groups and OU, log data |
| Recipients | Internal IT. Notifications to the acting employee (via your mail server or mail provider). Otherwise no third parties |
| Third countries | None |
| Retention | Changes __ days, log __ days, restore entries __ days, sessions 30 minutes of inactivity (see section 3) |
| Measures | See section 4 |
