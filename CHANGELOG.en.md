# Changelog

All notable changes to SAMONBOARDING, newest first. The interface shows them under *Help → News*.
Update on the server: `sudo sh update.sh --pull`.

Entries starting with "Security:" or "Fixed:" are marked accordingly in the interface.

## 1.46.1 – 2026-10-24
- Security: every image is checked for known vulnerabilities with Trivy on GitHub before it is published. If Trivy finds a serious vulnerability (CRITICAL/HIGH) for which a fix exists, the image is not published. In addition, the published image is checked again every Monday.

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
