# Changelog

*Deutsche Fassung: [CHANGELOG.de.md](CHANGELOG.de.md)*

All notable changes to SAMONBOARDING, newest first. The interface shows them under *Help → News*.
Update on the server: `sudo sh update.sh` or `docker compose pull && docker compose up -d`.

Entries starting with "Security:" or "Fixed:" are marked accordingly in the interface.

## 2.2.1 – 2026-11-08
- Changed: the home page shows its numbers right after signing in. They are now read first and in parallel, before OUs, groups and templates are loaded for the other areas.
- Faster with large directories: the domain controller now counts for the home page itself (search filters such as "enabled and no logon for 90 days" or "locked"). Only the matching accounts are read, with very few attributes, and the browser receives only the numbers instead of three complete account lists – fast even with thousands of accounts. Still live, with your own AD account and only in the released OUs.
- New: while the home page is open, its numbers are read fresh from the domain controller every minute and when you return to the browser tab, so there is no need to click "Refresh". Nothing is stored in the browser. After 10 minutes without activity the automatic refresh stops, so an unattended screen does not keep the session alive.

## 2.2.0-s1 – 2026-11-08
- Security: security update without program changes: same program, updated packages.
- Base images:
  - Python (python): `3.13.18-slim-trixie@ae14d4ce8771` → `3.13.18-slim-trixie@e48f59cdba69`
  - Node (node): `24.22.2-trixie-slim@54f84b4cf843` → `24.22.2-trixie-slim@0820eaa85e07`
- Debian packages:
  - zlib1g `1:1.3.dfsg+really1.3.1-1+b1` → `1:1.3.dfsg+really1.3.1-1+deb13u1`
- Python packages:
  - click `8.5.0` → `8.5.1`
  - fastapi `0.162.0` → `0.162.2`
  - pydantic `2.14.2` → `2.14.3`
  - pydantic_core `2.50.2` → `2.50.4`
  - typing-inspection `0.4.4` → `0.4.5`
- npm packages (only for building the interface, not in the image):
  - is-core-module `2.17.0` → `2.18.0`
  - resolve `1.22.13` → `1.22.14`

## 2.2.0 – 2026-11-08
- New: a home page "What needs doing?" right after signing in. Three cards show how many active accounts have not logged on for 90 days, how many accounts are locked and – for administrators – how many disabled accounts are ready to be deleted. One click opens the matching list; the inactive accounts open sorted oldest first. The numbers come from the account lists the program already reads.
- New: quick search with Ctrl+K (⌘K on a Mac) for people and pages. A person opens in user management, already filtered; only accounts you may see anyway are searched.
- Changed: the menu is grouped into "Tasks" and "Settings". Onboarding is now called "New employee", offboarding "Leaving"; counters next to the menu items show how many accounts are waiting.

## 2.1.0 – 2026-11-08
- New: the offboarding list shows when each account last logged on (date and "… days ago", or "never"; highlighted from 90 days) and can be sorted by it – oldest first, newest first or by name. The value comes from `lastLogonTimestamp`, which Active Directory synchronises between the domain controllers only every 9–14 days, so it is approximate. It is only displayed, never stored or logged.

## 2.0.5 – 2026-11-05
- Security: smaller image – the package manager apt (with its helpers), Perl and the Debian helpers built on it are removed after the build, and no program keeps the setuid/setgid bit any more. The program needs none of them; vulnerabilities in these packages (like CVE-2026-109518 in apt) no longer affect the image. The Debian package list stays, so the daily scan still checks every remaining package.

## 2.0.4 – 2026-11-04
- New: a "Buy me a coffee" button at the end of the menu for administrators – for anyone who wants to support the development. It is a plain link to buymeacoffee.com; nothing is loaded from there and operators do not see it.

## 2.0.3 – 2026-11-04
- English is now the default language of the project files: README, changelog, data protection documentation and release pages appear in English first, the German versions are in `README.de.md`, `CHANGELOG.de.md` and `DATENSCHUTZ.de.md`. Comments in the source code are in English. The interface, the manual and the behaviour are unchanged.

## 2.0.2 – 2026-11-03
- New logo: two people instead of a shield – shows at a glance that this is about managing user accounts. Applies to sign-in, sidebar, mobile view and the icon in the browser tab.

## 2.0.1-s1 – 2026-11-02
- Security: security update without program changes: same program, updated packages.
- Base images:
  - Python (python): `3.13.18-slim-trixie@76baad603769` → `3.13.18-slim-trixie@ae14d4ce8771`
- Python packages:
  - anyio `4.15.1` → `4.16.0`

## 2.0.1 – Code audit – 2026-11-02
- Security: `update.sh --cleanup` could delete `data/`, `docker-compose.yml` and `update.sh` too when a file name contained `*` or spaces (e.g. `neu * .zip`). Unusual names are now only reported; everything is checked again right before deleting.
- Security: `update.sh --cleanup` now reliably detects mounted folders (also bind mounts from the same disk and a mount directly on an old program folder) and leaves them alone.
- Security: `update.sh --restore` only restores backups with plain files and folders (no links or device files). Further hardening: versions only from digits, letters, `.`, `_` and `-`; link loops no longer break `--cleanup`.
- Security: if the DC rejects the certificate on port 636 (with `LDAP_CA_FILE`), there is no longer a fallback to unencrypted LDAP, not even with `LDAP_ALLOW_PLAIN=true`.
- Security: Delete accounts: a folder is also not deleted when another account's home folder lies inside it, when another account has `%username%` literally in its AD attribute, when the path from AD contains a short name with `~`, or when the same folder is also configured as folder redirection and belongs to another account.
- Fixed: Delete accounts: if two locations point to the same folder (e.g. folder redirection into the home folder), it is deleted and counted only once; the AD account is then deleted as expected.
- Security: notification mails (with the initial password) now only go to the address in the signed-in person's AD attribute `mail`. Without this attribute no mail is sent, instead of assuming `<user>@<AD domain>`.
- Security: the container health check no longer runs as root but gives up all rights first. An empty `HTTPS_PORT=` in `.env` now means 9500 there as well (before, the container became "unhealthy").
- Data protection: the program's own backups in `data/backups` are deleted once they are older than the longest retention period; `offboarding.db` overwrites deleted entries (`secure_delete`), as documented.
- Fixed: if a data migration fails at start-up, a restart loop no longer creates new backups; the clean backup from before the change is kept.
- Fixed: the menu item *E-mail notification* is hidden for operators (the server does not give them the settings). Credentials PDF: a message instead of a silent failure when a pop-up blocker prevents the window. Two missing English translations added.
- Docs corrected: `TZ` (empty means UTC), operator rights, example values, template `env.example`, browser storage.

## 2.0.0-s1 – 2026-10-31
- Security: security update without program changes: same program, updated packages.
- Base images:
  - Python (python): `3.13.17-slim-trixie@d98cc29d3266` → `3.13.18-slim-trixie@76baad603769`
  - Node (node): `24.22.1-trixie-slim@43b9ba1142b8` → `24.22.2-trixie-slim@54f84b4cf843`
- Debian packages:
  - tzdata `2026e-0+deb13u1` → `2026f-0+deb13u1`
- Python packages:
  - opentelemetry-api `1.45.1` → `1.45.2`
  - pyasn1 `0.6.4` → `0.6.5`
  - pydantic `2.14.1` → `2.14.2`
  - pydantic_core `2.50.1` → `2.50.2`
- npm packages (only for building the interface, not in the image):
  - postcss `8.5.31` → `8.5.32`

## 2.0.0 – 2026-10-29
- **Moved to the Docker standard:** the program is completely in the image. Only `docker-compose.yml`, `.env` and the folder `data/` remain on the server. Installation: get the files from the release, fill in `.env`, `docker compose up -d`. Updates with a container manager (Dockhand, Watchtower, Tugtainer …) or with `docker compose pull && docker compose up -d`.
- Security: before every version change the program itself backs up the data folder when it starts (`data/backups/vor-<version>-<date>.tar.gz`, the last 10 are kept) and then brings the data to the new state. If an older version starts on data of a newer one, it stops with a clear message naming the backup instead of running on with follow-up errors.
- Security: the container starts only briefly as root (with the rights DAC_READ_SEARCH, CHOWN, SETUID, SETGID), hands `data/` over to the program user 10001 and then runs permanently without special rights. A fresh data folder therefore works without manual steps.
- The `docker-compose.yml` stays stable: no build settings any more, defaults are in the program. It has a version (`SAMONBOARDING_COMPOSE`); if it is out of date, the interface shows administrators a note. The image carries the current file. `docker-compose.image.yml` is gone.
- Fix a version with `SAMONBOARDING_VERSION` in `.env`: empty = newest, `2.0` = newest 2.0.x including security updates, `2.0.0` = exactly this one.
- New `update.sh` for the manual way (runs with `/bin/sh`, also on a NAS): remembers the running version, fetches the new one, starts it and goes back if the start fails. Plus `--version`, `--offline` (image file from the release, without internet), `--restore` (put a backup back) and `--cleanup` (remove old program files, never data). ZIP, building on the server and `--lock` are gone.
- Every release now has `docker-compose.yml`, `env.example` and the image files for amd64 and arm64 attached.
- New versions only come via a pull request; a merge only checks, publishing is done by hand. In addition there is the tag `<major>.<minor>` (e.g. `2.0`).
- Example values in the docs and templates are neutral (`firma.local`, `10.0.10.x`).

## 1.48.1 – 2026-10-28
- For every published version GitHub now also creates a release page (`v<version>`, e.g. `v1.48.1` or `v1.48.1-s1`) with the changelog entry in German and English, for security updates including the list of changed packages. A release page is created once and never changed afterwards.

## 1.48.0 – 2026-10-25
- Security: reproducible build. Base images are pinned with a fixed version and checksum (digest), the Debian packages via a fixed state of snapshot.debian.org (`os-packages.lock`), all Python and npm packages including indirect ones with an exact version. The script `scripts/pins.py` renews the versions.
- Security: weekly security update on GitHub (Mondays, can also be started by hand). It brings the base image, all Debian packages and all dependencies up to date, but only within the base:
  - same Debian version ("trixie"), same Python (3.13) and Node series (24)
  - every package within its major version, below 1.0 within its minor version; calendar versions such as root certificates without a limit
  - build without cache, tests in the image (amd64 and arm64), HTTPS start check and Trivy
  - published only if everything passed, as `<version>-s<counter>` (e.g. `1.48.0-s1`), with an entry here including the list of changed packages. If nothing changed, nothing happens.
- Security: Trivy no longer runs as a GitHub Action but as a fixed version whose checksum (SHA-256) is checked before use. Accepted findings are listed in `.trivyignore` with a reason and an expiry date.
- Security: the published image is scanned with Trivy every day, so vulnerabilities that only become known after the release are noticed.
- Weekly check of how long Debian, Python and Node still get security updates (endoflife.date): a note from 12 months before, a red run from 6 months before. The base is never raised automatically.
- Published versions are never overwritten, `latest` always points to the highest version. Every job only gets the rights it needs.
- News in the interface show security updates (`-s1`, `-s2` …) as separate entries.

## 1.47.1 – 2026-10-25
- The interface is now built with Node 24 (updates until April 2028) instead of Node 22, which ends in April 2027. Node is only used while building, not in the finished image; the generated interface is unchanged.

## 1.47.0 – 2026-10-24
- Security: the image is now based on Debian 13 "Trixie" with Python 3.13 (previously Debian 12 with Python 3.11). It therefore receives security updates for much longer, Python 3.13 until 2029. The weekly rebuild installs them automatically. Usage and settings stay the same.
- Security: everything in the image stays current. The weekly rebuild now also fetches the newest Python 3.13 version and the newest versions of all Python packages. Previously fixed versions (uvicorn, ldap3, smbprotocol, pypsrp) are released; only jumps to a new major version remain excluded. Everything is tested and scanned before it is published.
- Half a year before Debian 13, Python 3.13 or Node 22 stop getting updates, GitHub reports it by e-mail. Only then is the base raised.
- README: notes before use (no warranty, test first, tested with Samba AD, fixed version for production). New: `SECURITY.md` for reporting security vulnerabilities confidentially.
- Security: the package tool `pip` is only needed while building and has been removed from the finished image. It brought its own outdated copies of urllib3, certifi and msgpack, which Trivy had reported as vulnerabilities.

## 1.46.1 – 2026-10-24
- Security: every image is checked for known vulnerabilities with Trivy on GitHub before it is published. If Trivy finds a serious vulnerability (CRITICAL/HIGH) for which a fix exists, the image is not published. In addition, GitHub rebuilds the image every Monday with the newest packages and Debian security updates. It goes through the same tests and the same scan and is published under `latest` only if everything passes. It reaches a server only with `sh update.sh --pull`.
- Security: the current Debian security updates are now installed at build time (among others OpenSSL, GnuTLS, Kerberos, PAM, Perl). The packages `setuptools` and `wheel`, which are not needed, are removed from the image. The first Trivy scan had found several serious vulnerabilities here.

## 1.46.0 – 2026-10-24
- Security: members of Key Admins, Enterprise Key Admins, Group Policy Creator Owners and Cert Publishers are now protected as well. Until now operators could reset their passwords.
- Security: computer and service accounts (gMSA) can no longer be changed via password reset, offboarding, moving or deletion, not even with a specifically crafted DN.
- Security: when deleting folders:
  - User names containing "~" (possible Windows short names) are skipped.
  - Folders inside another account's folder are not deleted.
  - If a subfolder is replaced by a link while deleting, the link is not followed.
- Security: the lockout after failed sign-ins can no longer be bypassed with many simultaneous attempts.
- Security: on GitHub the build step with the newly installed packages can no longer see the access token. The GitHub Actions used are pinned to fixed versions. Images are only published from the `main` branch.
- Fixed: a double click on "Create", "Reset password", offboarding or deletion no longer runs the action twice.
- Fixed: after switching quickly between two people, the group window no longer shows the wrong person's groups.
- Fixed: onboarding also detects a sign-in name (UPN) that is already taken.
- Fixed: if an object with the same name already exists in the target OU, offboarding stops before changing anything.
- Fixed: an interrupted restore can be repeated.
- Fixed: `update.sh`:
  - The backup of `data/` is taken only once the container is stopped.
  - A local build no longer replaces a newer version from GitHub.
  - The right version is shown after `--pull`.
- Fixed: if one page fails to load, the others still load.

## 1.45.0 – 2026-10-24
- News in the interface: *Help → News* shows what changed in the installed versions. A small dot appears if there is a new version since you last read it; for security updates it is orange.

## 1.44.0 – 2026-10-24
- Automatically generated passwords (onboarding, password reset) no longer contain easily confused characters: 0 O o 1 l I.

## 1.43.1 – 2026-10-24
- Only one workflow on GitHub ("Image"). It checks formatting (ruff) and the tests and then builds the image. The duplicate "Tests" run is gone.

## 1.43.0 – 2026-10-24
- **`sudo sh update.sh --pull` now fetches the ready-made image from GitHub** (`ghcr.io/soleil0815/samonboarding`) and starts it. Nothing is built on the server, and git is not needed.
  - The script backs up `data/` first. If the new version does not start, it puts the previous image back into service.
  - `update.sh` and `docker-compose.yml` are taken from the image to match its version.
- `docker-compose.yml` names the image (`SAMONBOARDING_IMAGE`). Building locally with `sudo sh update.sh` still works.
- The `git pull` route from 1.40 to 1.42 has been removed.

## 1.42.0 / 1.42.1 – 2026-10-24
- Interim versions for updating via git, replaced by 1.43.0.

## 1.41.0 – 2026-10-24
- On every push, GitHub builds the ready-made image and publishes it as `ghcr.io/soleil0815/samonboarding` (`:latest` and `:<version>`), for amd64 and arm64.
  - Before that, the Python packages are pinned and checked with all tests.
- New: `docker-compose.image.yml` for Dockhand, Portainer & co.

## 1.40.0 – 1.40.2 – 2026-10-23
- Project prepared for GitHub: `.gitattributes`, `update.sh` marked as executable, a ZIP never contains a `.git` folder.
- License: GNU AGPL v3 or later (`LICENSE`). The sign-in page links to the source code.
- All commands in the docs and messages as `sh update.sh …` (also works without the executable bit).
- Everything related to Dockhand removed (label `dockhand.update=false`).

## 1.39.0 – 2026-10-23
- Installation files in English: `update.sh` (all output), `.env.example`, `Dockerfile`, `docker-compose.yml`. The setting names in `.env` are unchanged.
- Confirm with `y` (`j` still works), `--yes` in addition to `--ja`.

## 1.38.0 – 2026-10-23
- Internet block (iptables and systemd on the host) removed completely. `update.sh` removes an existing block automatically once the new version is running.
- The settings `INTERNET_SPERRE`, `ZUSATZ_ZIELE`, `DATEISERVER_NETZE` and `DNS_SERVER` are gone.

## 1.37.0 – 2026-10-22
- Faster: only the open page is loaded. The account lists are kept in memory per session for up to 60 seconds, not in a database.
  - Every change clears this cache immediately.
  - "Refresh accounts" always reads fresh from the DC.
- The protection check of the lists needs only a few combined queries instead of one query per account.
- Renamed, moved or deleted OUs and groups are detected (via the objectGUID).
  - Administrators see a notice.
  - "Apply new names" updates all affected settings and templates.
- Fixed: members of built-in groups had no padlock in the list. The action itself was always blocked.
- Fixed: after a DC outage the fallback list was cached.

## 1.36.0 – 2026-10-22
- Fixed: issues from the code review:
  - LDAP searches detect aborts and errors.
  - Time limits for the DC.
  - DN comparison by components.
- Security: before deleting, the admin password and role are checked again right beforehand. Folders also used by other accounts are not deleted.
- Restoring only by GUID. An onboarding that is aborted is rolled back cleanly.
- Security: in SMTP mode "Auto" nothing is sent without STARTTLS any more. For internal relays without TLS there is the mode "Without encryption".
- Name generation: Ø, Æ, Œ, Ł, Đ and Þ are transliterated.

## 1.35.1 – 2026-10-22
- Fixed: `update.sh` stopped on the Synology with "syntax error near unexpected token `('" (bash in POSIX mode).

## 1.35.0 – 2026-10-22
- Docker Compose is no longer required. Without Compose, `update.sh` starts the container directly with `docker` and the same settings, e.g. on a Synology.
- Fallbacks for tools missing on the NAS (cmp, sha256sum, timeout, sort -V).

## Older versions (summary)
- Install a new version from a ZIP: `sudo sh update.sh samonboarding-x.y.z.zip`, with confirmation, backup, rollback and cleanup.
- The container runs without root (user 10001). Python packages, npm packages and base images with fixed versions; new packages are checked with the tests.
- Manual in German and English in the help. Link to helfi.space.
- HTTPS with your own or a self-signed certificate, reports in SQLite, data protection (GDPR) with retention periods and subject access.
- Modules: onboarding with templates, user management, password reset, offboarding with restore, deleting accounts (administrators only, with simulation and password confirmation).
