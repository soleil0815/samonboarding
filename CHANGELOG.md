# Changelog

*Deutsche Fassung: [CHANGELOG.de.md](CHANGELOG.de.md)*

All notable changes to SAMONBOARDING, newest first. The interface shows them under *Help → News*.
Update on the server: `sudo sh update.sh` or `docker compose pull && docker compose up -d`.

Entries starting with "Security:" or "Fixed:" are marked accordingly in the interface.

## 2.11.0 – 2026-11-23
- Changed: deleting a single account now also runs as a job on the server, like the batch deletion. Closing the page, reloading it or a proxy timeout no longer matters: the deletion continues, and the result mail is sent in any case.
  - Running deletions are found again: when an administrator opens **Delete accounts** again (also after reloading or signing in again), the page shows the running or just-finished deletion with its progress and result – for single and batch deletions. **Hide result** removes it from the page and from memory (it stays in the reports).
  - Instead of the warning "do not close the page" the page now says: "Deletion running on the server. You may leave the page; the result appears here and by email (if set up)."
  - A deletion belongs to the administrator who started it; other administrators do not see it. Finished deletions are kept in memory for one hour (account name and result), never on disk.
- Fixed: in the English interface the result of a single deletion (message, number of files and folders, ownership taken) was partly shown in German.

## 2.10.0 – 2026-11-23
- New: Kerberos for the encrypted connection without a certificate. If the DC has no LDAPS, the application now first signs in with Kerberos on port 389 and encrypts with it (AES); the DC proves its identity, and it also works in domains in which NTLM is switched off. NTLM remains the fallback.
  - Needs: `AD_DC_IP` as the DNS name of the DC (e.g. `dc01.firma.local`, not an IP address – the ticket is issued for exactly this name), port 88 (TCP) from the server to the DC, and a clock that differs by less than 5 minutes. Nothing else to set up: the program writes its Kerberos configuration itself from `AD_DOMAIN` and `AD_DC_IP` (AES only, no DNS lookups). The ticket of a sign-in is held in memory only while the connection is set up and then destroyed.
  - A wrong password is never tried with NTLM as well (it would count twice towards the account lockout). Once Kerberos has worked for a DC, the application never falls back to NTLM for it (until the next restart).
  - File servers (SMB) and Exchange keep NTLM as before (Exchange "Automatic" = NTLM; Kerberos only when chosen explicitly), so a wrong password never counts twice there either.
  - `LDAP_KERBEROS=false` switches it off (NTLM only). The diagnostic package shows `ldap-sealed-kerberos` or `ldap-sealed-ntlm`.
  - The image now contains the MIT Kerberos libraries and the Python packages gssapi and krb5 (compiled in their own build stage). Debian packages from the snapshot of 23.11.2026 (Kerberos libraries with the current security fixes).

## 2.9.0 – 2026-11-23
- New: works with domain controllers without LDAPS. Many Windows domains have no certificate on their DCs. If LDAPS (port 636) is not available, the application now connects on port 389 and encrypts the connection with NTLM ("sign and seal", as Windows tools such as RSAT do). Sign-in, all changes and setting passwords (onboarding, password reset) work this way – also when the DC requires LDAP signing. Before, only the clear-text fallback `LDAP_ALLOW_PLAIN` was left, which can never set passwords.
  - Nothing to set up: `LDAP_SASL_ENCRYPTION=true` is the default; `false` = LDAPS only. With `LDAP_CA_FILE` there is still never a fallback.
  - The diagnostic package shows the kind of connection (LDAPS, encrypted 389, unencrypted) and recommends a certificate on the DC: TLS remains stronger than NTLM encryption.
  - Once LDAPS has worked for a DC, the application never falls back to port 389 for it (until the next restart). Referrals to other servers are no longer followed.
  - `LDAP_ALLOW_PLAIN` is no longer needed and only a last resort after the encrypted connection.
  - Kerberos instead of NTLM (for domains where NTLM is switched off) follows in a later version.

## 2.8.0 – 2026-11-23
- Changed: the structure of the domain is for administrators only. Operators (Account Operators and the own operator group) no longer see the menu item **AD structure**, the quick search no longer offers it, and the server refuses the page to them like the other administrator pages. The selection lists of their pages no longer come from the whole domain either: they get only the target OUs released for moving and the groups named in the templates (for the preview during onboarding) – never the list of all OUs, groups or users.

## 2.7.1 – 2026-11-23
Code audit 2026-11 (full audit, as on the 3rd of every month).
- Security: an administrator who loses the Domain Admins role in the AD now loses the admin pages within 5 minutes and is signed out – before, an open session kept them for up to 12 hours on pages that never ask the AD (SMTP server, certificate, settings).
- Security: with `LDAP_CA_FILE` set, the connection never falls back to unencrypted LDAP (389) – not even after a connection reset.
- Security: an Account Operator can no longer create an account through a template that contains a privileged group (e.g. Domain Admins); user management already refused the same group.
- Security: members of the own operator group (`CUSTOM_OPERATOR_GROUP`) are protected like Account Operators, and only administrators may add anyone to that group.
- Security: Exchange with sign-in method "basic" is only allowed with a verified certificate – otherwise another server could read the administrator's password. An older settings file with this combination is refused before connecting.
- Security: restoring an offboarded account as an operator only works for accounts from a current source OU, and groups outside the approved group OUs are left for administrators (as in user management).
- Security: wrong passwords in the confirmation before deleting now each count, even when many are sent at the same time.
- Security: new header `Cross-Origin-Resource-Policy: same-origin` – other websites cannot embed the program's responses.
- Fixed: deleting folders never follows a link at the top of a folder (e.g. a home folder that is itself a junction), and never picks a folder that is another account's home or profile folder or lies inside one – now for folder redirection too.
- Fixed: offboarding the same account again (e.g. re-enabled by hand in the OU of offboarded accounts) no longer overwrites the restore entry with its real previous OU and groups. The settings refuse an OU for offboarded accounts inside a source OU.
- Fixed: after a deletion that removed folders but not the account, the restore preview says that these folders are gone.
- Fixed: if the connection breaks while a new account is being set up (password, "change at next logon", groups), the half-finished account is removed – before, it could stay enabled with only some of its groups.
- Fixed: the start page no longer counts accounts created in the last 90 days as inactive; the success message after deleting counts only folders that were really deleted.
- Fixed: a template whose naming macro has no %FIRSTNAME% or %LASTNAME% is refused (every account would have had the same name).
- Fixed: account lists that cannot be loaded show the reason instead of "Loading" forever; without source OUs they say who sets them. Without a template, onboarding says so instead of failing with "[object Object]".
- Fixed: closing the result of a password reset no longer empties a half-filled onboarding form; the password-reset and move dialogs name the account; the delete confirmation fits on a phone.
- Fixed: English words in the German interface and German words in the English one (OU picker, template page, error messages).
- Fixed: `update.sh --restore` deletes nothing if the safety copy of the current data cannot be written (e.g. disk full). `update.sh` understands a version written in quotes in `.env` and no longer glues a new line to a last line without a line break.
- Fixed: the patch-day security update never publishes a version that has been merged but not released yet.
- Diagnostic package: logon names that only appear in the details of the reports and user names after a domain name (`DOMAIN\user`) are now anonymised too.
- Docs: data protection names the IP address stored for failed sign-ins and the browser storage for the appearance; the list of protected groups is complete; a fixed version line only gets security updates while it is the newest; the README pictures exist in light only (the note in 2.5.0 was wrong).

## 2.7.0 – 2026-11-20
- Important: from this version on the server connects to the internet about once a day (`api.github.com`, port 443) to look for new versions – nothing is sent along. Anyone who wants no connection to the outside at all sets `UPDATE_CHECK=false` in `.env`.
- New: version check for everyone who does not update the container automatically. Once a day the server asks GitHub whether there is a newer version; administrators then see a note at the top of every page with the version, a "What's new?" link and the update commands (`sudo sh update.sh` or `docker compose pull && docker compose up -d`). Security updates (`-s1`, `-s2` …) are marked as such.
  - Nothing is sent along: no version, no identifier, no data from the AD – the comparison happens on the server, the browser never connects to GitHub.
  - A fixed version in `.env` (`SAMONBOARDING_VERSION`) is respected: with `2.6` the note names the newest 2.6.x and a newer line separately; with an exact version it names `sudo sh update.sh --version <new version>`.
  - Without internet nothing happens (no error, no delay); the diagnostic package shows why. Switch it off with `UPDATE_CHECK=false`, a proxy only for this check with `UPDATE_CHECK_PROXY` in `.env`.
- Data protection: the documentation and the "Data protection" window now name this daily request to GitHub.

## 2.6.2 – 2026-11-18
- Faster: the protection check of the lists (which accounts are Domain Admins & co.) now reads the members of the privileged groups directly and follows nested groups itself, instead of the "in chain" search across the domain. On Samba that search took about a second per group – the start page and the Leaving list needed 10–27 seconds, now they should be there in about a second. The protection itself is unchanged: before every action the account is still checked live.
- Diagnostic package: the connection test measures the protection check; the notes on slow pages name the step that takes the time; browser versions are no longer mistaken for IP addresses; Docker's health check (every 30 s) no longer appears in the request statistics.

## 2.6.1 – 2026-11-15
- Changed: the appearance now follows the computer by default (◐ like the system – light or dark as set in Windows/macOS). Light ☀ and dark ☾ can still be chosen; a choice made before stays.

## 2.6.0 – 2026-11-15
- New: diagnostic package. Under **Settings → Diagnostics** (administrators only) you get an anonymous ZIP for troubleshooting: version and environment, settings, a short connection test to the DC (with your account – there is still no service account), configured OUs/groups that no longer exist, HTTPS certificate, data folder, response times per page since the start, the latest warnings and errors from the log and how often actions failed. Notable points come first.
  - Anonymous: users, OUs, groups, servers, IP and e-mail addresses and shares become placeholders (`benutzer-1`, `ou-2`, `host-3` …), the same name always the same placeholder; the mapping is not stored. Passwords, tokens and sessions are never included. A preview shows exactly what is inside; the package is only downloaded, never sent. Its creation is recorded in the reports.
  - Without signing in: `sudo docker compose exec samonboarding python -m samonboarding.diagnose` writes it to `data/diagnose/`.
  - Stays up to date with the program: every module, setting, template field and environment variable must have a rule for the package – otherwise the tests fail.
- Fixed: switching the language removed the highlight from the light/dark buttons.

## 2.5.0 – 2026-11-14
- New: light or dark. The switch ☀ / ☾ / ◐ (light, dark, like the system) is at the bottom of the sidebar and in the top right corner of the sign-in page. Light is the default; the browser remembers the choice (only this display setting – no data from AD is kept in the browser). The page takes on the chosen appearance before it is drawn, so nothing flashes white.
  - All colours are now variables with a light and a dark value; the dark look follows the light one (dark grey instead of night blue, hairlines, one blue accent, no glow).
- Changed: font as in WhatsOnMyNet – San Francisco on the Mac, otherwise the bundled Inter; code, paths and DNs in IBM Plex Mono. Both replace Manrope and JetBrains Mono and are, as before, packed into the image (nothing is loaded from the internet).
- README: the pictures exist in light and dark; GitHub shows the one that matches your appearance.

## 2.4.0 – 2026-11-14
- Changed: new, light design. The interface now looks calm and businesslike instead of dark: light grey background, white cards with fine lines, one blue accent colour, no gradients or glow effects.
  - Font: the system font of the computer (San Francisco on the Mac, Segoe UI on Windows); the bundled Manrope remains the fallback. Still nothing is loaded from the internet.
  - Login: centred, a single narrow form.
  - Menu: quiet like in macOS – grey highlight for the open page, small coloured dots for the account stages, the counters as plain numbers.
  - Tables: the actions in a row (Offboarding, Move, Groups, Reset password …) are quiet white buttons with coloured text; only the main action of a page stays filled.
  - Every page uses the same column width, so the title stays in the same place when switching pages. On narrow screens the button next to the page title moves below it, and table headers wrap instead of being cut off.
  - New favicon: the two-person symbol in white on a graphite tile.

## 2.3.1 – 2026-11-13
- Changed: the support link is now a small card at the bottom of the home page ("Like SAMONBOARDING? A coffee would make my day." with the button "Buy me a coffee") instead of the button in the menu. Still visible to administrators only, still a plain link – nothing is loaded from the internet.

## 2.3.0-s1 – 2026-11-10
- Security: security update without program changes: same program, updated packages.
- npm packages (only for building the interface, not in the image):
  - lilconfig `3.1.4` → `3.1.5`
  - postcss-selector-parser `6.1.5` → `6.1.6`
  - cssesc `3.0.0` (removed)

## 2.3.0 – 2026-11-09
- Security: the content security policy no longer allows inline scripts (`script-src 'self'`, before `'self' 'unsafe-inline'`). Should someone ever manage to inject HTML into the page, the browser will not run any script from it. Findings "CSP: script-src unsafe-inline" from the OWASP ZAP scan.
  - The interface logic is now its own file (`/app.js`, cached for a day, a new version changes its address).
  - Buttons and fields no longer carry inline JavaScript (`onclick="…"`). They are marked with `data-on-click="…"`; one listener on the page reads these marks and calls the named functions. The text is never run as code: only calls of the interface's own functions with simple values are accepted.
  - The print window for access data starts printing from the main window (it inherits the policy, an inline script there would be blocked).
- Styles still allow `'unsafe-inline'` (style attributes in the interface). CSS cannot run code; this remaining finding is accepted.

## 2.2.5 – 2026-11-09
- Security updates of the image now come once a month on patch day – the second Tuesday, like Microsoft's Patch Tuesday (before: every Monday), the same day in all programs. By hand they can still be started at any time.
- Security scan (OWASP ZAP) findings, quick part:
  - The page itself is now delivered with `Cache-Control: no-cache`: the browser asks on every load whether it is still current, so a new version shows up right after an update (no Ctrl+F5 needed any more).
  - The example address in the certificate form is now from the range reserved for documentation (`192.0.2.20`) instead of a private address – the scanner reported it as "Private IP Disclosure".
- Still open from the scan: the content security policy allows inline scripts and styles (`unsafe-inline`). Removing it for scripts follows in 2.3.0.

## 2.2.4 – 2026-11-08
- Home page: you can see that something is happening. While the domain controller is being asked, the cards show the seconds passing ("Reading from the DC … 3 s", later "refreshing … 3 s"); when the result arrives, the numbers count up to their value (from the previous value after a refresh). With "reduce motion" switched on in the system, the numbers appear at once.
- The progress bar at the top is more visible.

## 2.2.3 – 2026-11-08
- Faster sign-in: the role (administrator or operator) is now taken from the account's own group SIDs (`tokenGroups`, one cheap read). The expensive nested group search across the whole domain only runs if that does not already decide. Your own operator group (e.g. CO-ADMIN) is looked up once by its name.
- Faster lists in every module: the check for protected accounts (Domain Admins etc.) needs one nested search per privileged group across the domain. It now runs once per minute and session instead of on every list (offboarding, deletion, home page twice), and is discarded on every change; every action is still checked live.
- Faster pages: each page's own account list starts at once, in parallel with the settings. All groups of the domain are only loaded for new employee, templates and AD structure, all users only for templates – the other pages need only the OUs.
- New: you can see that something is happening – the sign-in button shows "Signing in …", a thin progress bar at the top runs while the domain controller is being asked, the home page shows placeholders while reading for the first time and "refreshing …" afterwards, and the tables show a spinner while loading.
- New: requests that take longer than one second are logged with their duration per step (connection, search, role check, protection check) – durations only, never names. The browser developer tools show the same numbers (Server-Timing).

## 2.2.2 – 2026-11-08
- Faster with large directories: the quick search (Ctrl+K) now asks the domain controller directly – from two characters, shortly after the last key, at most 10 hits – instead of loading complete account lists into the browser. Every typed word must appear in the name, logon name or e-mail. Only the OUs released for user management, leaving and password reset are searched, with your own AD account; the search text is never stored or logged.
- Faster after signing in: the AD structure (all OUs, groups and users) is only loaded on the pages that show or edit it – new employee, templates, AD structure and the OU settings of the lists – and no longer for the home page, reports, certificate, e-mail notification or the manual.

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
