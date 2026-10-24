# SAMONBOARDING

*Deutsche Version: [README.md](README.md)* · **Manual: [MANUAL.en.md](samonboarding/web/manual/MANUAL.en.md)** · **Data protection (GDPR): [DATA-PROTECTION.en.md](DATA-PROTECTION.en.md)** · Website: [helfi.space](https://helfi.space) · License: [AGPL-3.0-or-later](LICENSE) · Changes (German): [CHANGELOG.md](CHANGELOG.md)

Web application for day-to-day user management in Active Directory (**Samba AD** or **Windows Server AD**):

| Module | What it does |
|---|---|
| **Onboarding** | Creates new users from a template (naming scheme, OU, password, groups, further attributes) |
| **Offboarding** | Disables an account, removes it from all groups and moves it to a target OU |
| **Password reset** | Resets passwords (random or manual), can unlock accounts and force a change at next logon |
| **User management** | Moves accounts between permitted OUs and maintains group memberships |
| **Restore** | Undoes an accidental offboarding (OU, groups, enabled state) |
| **Delete accounts** | Administrators only: deletes disabled accounts including roaming profile, folder redirection and home folder, always simulated first |
| **E-mail notification** | Optional: mail to the employee who performed the action (SMTP) |

The application runs as a Docker container (FastAPI + ldap3). The web interface is fully built in and needs no internet access. It is available in **English and German** (switch with *DE / EN*); German labels are given in *italics* in this document where they help.

---

## Contents

1. [How it works](#1-how-it-works)
2. [Requirements](#2-requirements)
3. [Installation](#3-installation)
4. [Configuration](#4-configuration)
5. [Preparing Active Directory](#5-preparing-active-directory)
6. [First-time setup in the interface](#6-first-time-setup-in-the-interface)
7. [The modules in detail](#7-the-modules-in-detail)
8. [Operation](#8-operation)
9. [Security notes](#9-security-notes)
10. [Troubleshooting](#10-troubleshooting)
11. [Development](#11-development)

---

## 1. How it works

```
 Browser  ──HTTPS──▶  SAMONBOARDING (Docker, port 9500)  ──LDAPS 636──▶  Domain controller
                                   │
                                   └──SMTP (optional)──▶  Mail server
```

These five points explain the whole concept:

1. **There is no service account.** Everyone signs in with their *own* AD account, and every action runs as that user. Whatever AD does not allow them, they cannot do here either. Permissions are granted in AD (delegation), not in the application.
2. **The connection to the DC is encrypted (LDAPS, port 636).** This is required because AD only allows setting passwords over an encrypted connection.
3. **Two roles**, based on the groups of the signed-in user (nested memberships count):

   | Role | Requirement | Allowed to |
   |---|---|---|
   | **Administrator** | Member of `Administrators`, `Domain Admins` or `Enterprise Admins` (detected by SID, also with localized names) | everything, including settings, templates, SMTP and choosing the permitted OUs |
   | **Account Operator** | Member of `Account Operators` **or** of your own group (`CUSTOM_OPERATOR_GROUP`) | onboarding, offboarding, password reset and user management, but only in the OUs the administrator has permitted |

   Everyone else is rejected at sign-in.
4. **Permitted OUs.** In the interface, the administrator chooses in which OUs work may be done. The server checks this again on every action, not just the interface.
5. **HTTPS only, sessions in memory only.** The application is only available over HTTPS. Sessions (including the password, which is needed for the actions in AD) end on sign-out, after **30 minutes of inactivity** or when the container restarts. Every action is recorded in the **reports** (SQLite, without passwords).

### Interface

The navigation follows the life cycle of an account: **joining** (*Onboarding*), **maintenance** (*Benutzerverwaltung* = user management, *Passwort zurücksetzen* = password reset), **leaving** (*Offboarding*) and **deletion** (*Konten löschen*). Below that are setup (*Templates*, *E-Mail-Benachrichtigung*, *AD-Struktur*) and help. Feedback appears as a message in the bottom right corner. Errors and long messages stay until you close them. On tablets and phones the navigation opens from the menu icon in the top left.

**Language:** the interface is available in **German and English**. Switch with *DE / EN* at the bottom of the sidebar or in the top right corner of the sign-in page. The browser remembers the choice; on the first visit the browser language is used. Server messages and notification mails use the chosen language. Names, OUs, groups and paths from AD are never translated. The English texts are in `samonboarding/web/i18n.json` (German text → English text, with placeholders `{0}` for values).

Colours and fonts are defined in `samonboarding/web/theme.json`. After changing them, rebuild the image (`docker compose up -d --build`).

---

## 2. Requirements

- A Linux server (or VM) with **Docker Engine**. **Docker Compose is not required:** if it is available (`docker compose` or `docker-compose`, any version, e.g. on a **Synology**), `update.sh` uses it. Otherwise `update.sh` starts the container directly with `docker` and the same settings (network, port, `data/`, permissions, restart, health check); only a `docker-compose.override.yml` is then not applied.
- The server reaches the domain controller on **TCP 636** (LDAPS) and can resolve its name
- A **domain controller** with LDAPS enabled (see [section 5](#5-preparing-active-directory))
- Optional: an SMTP server for notifications

---

## 3. Installation

### Step 1: Provide the files

**From GitHub:**

```bash
sudo apt install git          # if not installed yet
sudo git clone https://github.com/soleil0815/samonboarding.git /opt/samonboarding
cd /opt/samonboarding
```

Nothing has to be built on the server: GitHub builds the ready-made image (`ghcr.io/soleil0815/samonboarding`) for every new version, and `sudo sh update.sh --pull` fetches and starts it (step 3).

**Alternatively as a ZIP:** unpack the ZIP of a version into a folder such as `/opt/samonboarding`. These files and folders must sit directly next to each other:

```
/opt/samonboarding/
├── app.py
├── Dockerfile
├── docker-compose.yml      ← replaced with every version, do not edit
├── .env.example            ← template for your settings
├── .env                    ← your settings (created in step 2, kept on updates)
├── requirements.txt
├── tailwind.config.js
├── tailwind.input.css
├── .dockerignore
└── samonboarding/          ← complete folder with all modules and web/index.html
```

Check: `ls samonboarding/web` must show `index.html`. If the `samonboarding/` folder is missing, the build stops with `"/samonboarding/web": not found`.

### Step 2: Enter your settings in `.env`

Your settings live in the file **`.env`**, not in `docker-compose.yml`. The `.env` belongs to you: new versions only ship an updated `.env.example`, your `.env` is never overwritten.

```bash
cp .env.example .env
nano .env
```

Adjust at least these values:

```ini
AD_DOMAIN=company.local
AD_DC_IP=192.168.1.10
CUSTOM_OPERATOR_GROUP=CO-ADMIN
```

All other settings (port, time zone, certificate, retention …) are listed with comments in `.env.example`; their meaning is in [section 4](#4-configuration). Put comments on their own lines only (starting with `#`), never after a value.

If you need something that cannot be set in `.env` (e.g. a custom DNS server for the container), create a **`docker-compose.override.yml`**. Docker reads it automatically in addition, and it is not replaced on updates either.

### Step 3: Start

```bash
sudo sh update.sh --pull     # fetch and start the ready-made image from GitHub (recommended)
# or: sudo sh update.sh      # build the image here on the server
```

With `--pull` nothing is built; the start only takes as long as the download. Without `--pull`, `update.sh` checks the requirements, creates the npm lock file the first time, builds the image with the pinned versions, starts the container and waits until it is "healthy". At the end it shows the address. The first build takes a few minutes. Without the script, `sudo chown -R 10001:10001 data` and `docker compose up -d --build` work too (the container runs as user 10001, not as root, and needs write access to `data/`).

### Step 4: Check

```bash
docker compose ps          # status should be "running" or "healthy"
docker compose logs -f     # follow the logs (Ctrl+C stops the output)
```

**No internet at runtime:** the application does not open any internet connections by itself, only to the DC, file servers, SMTP and Exchange if used (see [section 9](#9-security-notes)). If you want to shield the container further, restrict the outgoing traffic of the Docker network `samonboarding` (subnet `DOCKER_SUBNET`) in the firewall of the host, router or Synology.

### Step 5: Sign in

Open `https://<server>:9500` in a browser and sign in with an AD account that is an administrator. On first start the application creates a **self-signed certificate**, so the browser shows a warning once. Afterwards you can upload your own certificate in the interface under **Certificate** (see [HTTPS](#https)). These formats are accepted:

- `username`
- `username@company.local`
- `COMPANY\username`

Continue with the [first-time setup](#6-first-time-setup-in-the-interface).

---

### Alternative: ready-made image from GitHub (Dockhand, Portainer & co.)

On every push to `main`, GitHub builds the image itself (`.github/workflows/image.yml`) and publishes it as `ghcr.io/soleil0815/samonboarding:latest` and `ghcr.io/soleil0815/samonboarding:<version>`. Before that, GitHub pins the Python packages and runs all tests with exactly these packages; if anything fails, no image is published. Nothing is built on the server, and `update.sh` is not needed.

1. **Create a stack** with the content of `docker-compose.image.yml` (in Dockhand: new stack, paste the file or take it from the repository).
2. **Settings** as stack variables, with the same names as in `.env.example`. `AD_DOMAIN` and `AD_DC_IP` are required, usually also `CUSTOM_OPERATOR_GROUP` and `TLS_HOSTNAMES`.
3. **Registry access:** if the repository is private, the image is private too. Then add the registry `ghcr.io` in Dockhand with user `soleil0815` and a token with the *read:packages* permission (GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)). Alternatively make the package public on GitHub under *Packages → samonboarding → Package settings*.
4. **Start.** The data lives in the Docker volume `samonboarding-data`; it gets the right owner automatically on the first start.
5. **Updates:** new version on GitHub → image is built → pull the image again in Dockhand or enable automatic updates. To stay on a specific version: variable `SAMONBOARDING_VERSION=1.41.0`.

What does **not** happen automatically (only `update.sh` does that): backing up `data/` before the update and going back to the previous version if the start fails. Going back works by hand via `SAMONBOARDING_VERSION`. Backing up the volume:

```bash
docker run --rm --user 0 -v samonboarding-data:/app/data:ro -v "$PWD":/backup --entrypoint tar \
  ghcr.io/soleil0815/samonboarding:latest czf /backup/samonboarding-data-$(date +%F).tar.gz -C /app data
```

Moving an existing installation (`/opt/samonboarding/data`) into the volume, once, with the old container stopped:

```bash
docker run --rm --user 0 -v /opt/samonboarding/data:/von:ro -v samonboarding-data:/app/data --entrypoint sh \
  ghcr.io/soleil0815/samonboarding:latest -c 'cp -a /von/. /app/data/ && chown -R 10001:10001 /app/data'
```

## 4. Configuration

Whether the directory is a **Samba AD** or a **Windows Server AD** is detected automatically at sign-in (RootDSE) and shown next to the role. No setting is needed for this.

All settings are in the file **`.env`** (template: `.env.example`). After a change run `docker compose up -d` (the container is recreated). An empty value means: default.

| Variable | Default | Meaning |
|---|---|---|
| `AD_DOMAIN` | `yourdomain.local` | DNS name of the domain (not the NetBIOS name). The search base is derived from it: `company.local` → `DC=company,DC=local` |
| `AD_DC_IP` | `192.168.1.10` | IP address or name of the domain controller |
| `CUSTOM_OPERATOR_GROUP` | empty | sAMAccountName of an additional group whose members are operators. The built-in *Account Operators* group always applies, recognised by its SID |
| `LDAP_CA_FILE` | empty | Path (inside the container) to a CA file in PEM format. If set, the DC certificate is verified |
| `LDAP_ALLOW_PLAIN` | `false` | `true` = fall back to unencrypted LDAP (port 389) if 636 is unreachable. Passwords then travel in plain text – emergencies only |
| `SESSION_IDLE_MINUTES` | `30` | Sign-out after this many minutes of inactivity |
| `SESSION_MAX_HOURS` | `12` | Maximum session length, even with continuous activity. Then sign in again (the role is determined again) |
| `HTTPS_PORT` | `9500` | HTTPS port in the container. There is no HTTP port |
| `TLS_HOSTNAMES` | empty | Names and IPs for the self-signed certificate, comma-separated (e.g. `samonboarding.company.local,192.168.1.20`) |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | `data/tls/cert.pem`, `data/tls/key.pem` | Your own certificate and key (PEM) |
| `LOGIN_MAX_ATTEMPTS` | `5` | Failed attempts per user and IP before a temporary lock |
| `LOGIN_LOCK_MINUTES` | `5` | Duration of the lock in minutes |
| `DATA_DIR` | `<project>/data` | Data directory (inside the container `/app/data`) |
| `TZ` | `Europe/Berlin` | Time zone for reports and mails (e.g. `Europe/London`, `UTC`) |
| `DOCKER_SUBNET` | `172.30.80.0/24` | Subnet of the container's Docker network. Only change it if it overlaps with your network |
| `AUDIT_RETENTION_DAYS` | `365` | Data protection: older report entries (changes) are deleted daily. `0` = unlimited |
| `LOG_RETENTION_DAYS` | `90` | Data protection: older log entries are deleted daily. `0` = unlimited |
| `OFFBOARD_RETENTION_DAYS` | `180` | Data protection: restore entries are deleted this many days after offboarding. `0` = unlimited |

Notes:

- **Certificate validation:** By default the application trusts the DC's LDAPS certificate automatically, including a self-signed one (Samba) or one from your own company CA. Nothing has to be imported. The connection is still encrypted, but without the check someone on the network could pose as the DC and read the passwords of people signing in (man-in-the-middle). Setting `LDAP_CA_FILE` is therefore **recommended** (see [section 5](#5-preparing-active-directory)). `AD_DC_IP` must then be the name contained in the certificate.
- **Name resolution:** If you use a name instead of an IP for `AD_DC_IP`, the Docker host must be able to resolve it. If it cannot, add the AD DNS server to a `docker-compose.override.yml` (kept on updates):

  ```yaml
  services:
    samonboarding:
      dns:
        - 192.168.1.10
  ```
- If a file `data/config.json` exists, **it takes precedence** over the environment variables `AD_DOMAIN` and `AD_DC_IP`. The application does not create this file itself.

---

## 5. Preparing Active Directory

Preparation always consists of the same three things:

1. **LDAPS** on the domain controller (port 636)
2. Optional: an **operator group** (`CUSTOM_OPERATOR_GROUP`)
3. **Permissions** for the operators on the affected OUs

Test whether LDAPS is reachable (from the Docker host):

```bash
openssl s_client -connect 192.168.1.10:636 -showcerts </dev/null
```

If a certificate is shown, LDAPS is active. `connection refused` or a timeout means port 636 is closed or blocked.

### 5.1 Samba AD

**LDAPS:** Samba enables TLS by default and creates a self-signed certificate during provisioning. It usually lives in `/var/lib/samba/private/tls/` (`ca.pem`, `cert.pem`, `key.pem`; the path may differ depending on the installation). That is enough to get started. A test with `openssl s_client` should show a certificate.

**Create an operator group (optional):**

```bash
samba-tool group add CO-ADMIN
samba-tool group addmembers CO-ADMIN user1,user2
samba-tool group listmembers CO-ADMIN
```

The group name is the `sAMAccountName` and goes into `CUSTOM_OPERATOR_GROUP` in `.env`. Alternatively, operators can be members of the built-in group `Account Operators`:

```bash
samba-tool group addmembers "Account Operators" user1
```

**Permissions:** The built-in group `Account Operators` normally has permissions to manage users and groups. If you use your own group (`CO-ADMIN`), it needs these permissions on the OUs you work with. This can be done with `samba-tool dsacl set` or from a Windows client with RSAT (see the Samba documentation). The easiest way is to keep operators in `Account Operators`.

**Password policy:** Reset and new passwords must meet the policy. Show it with:

```bash
samba-tool domain passwordsettings show
```

**Enable certificate validation (optional):**

1. Copy `ca.pem` from the DC to `./data/ca.pem`
2. In `.env`: `LDAP_CA_FILE=/app/data/ca.pem` and set `AD_DC_IP` to the DNS name of the DC (for example `dc1.company.local`)
3. `openssl x509 -in cert.pem -noout -subject -ext subjectAltName` shows which name the certificate contains

### 5.2 Windows Server AD

**LDAPS:** The domain controller needs a certificate with the purpose *Server Authentication* that contains the DC's DNS name. The easiest way is an **Active Directory Certificate Services (AD CS)** enterprise CA: domain controllers then receive a suitable certificate automatically, and LDAPS is available on port 636. Without a CA you can issue a certificate manually and install it in the DC's computer certificate store (Personal).

Test on the DC or a domain member server:

```powershell
Test-NetConnection dc1.company.local -Port 636
```

Or with `ldp.exe`: *Connection → Connect…*, port `636`, tick *SSL*.

**Create an operator group (optional):**

```powershell
New-ADGroup -Name "CO-ADMIN" -GroupScope Global -GroupCategory Security -Path "OU=Groups,DC=company,DC=local"
Add-ADGroupMember -Identity "CO-ADMIN" -Members user1,user2
```

**Delegate permissions** (for `CO-ADMIN` or any other own group): in *Active Directory Users and Computers*, right-click the OU → *Delegate Control…* and select these tasks:

| Task | Used for |
|---|---|
| Create, delete, and manage user accounts | Onboarding, offboarding (disable, move) |
| Reset user passwords and force password change at next logon | Password reset, unlock |
| Read all user information | Showing the user lists |
| Modify the membership of a group | Groups during onboarding, offboarding and in user management |

Important:

- Permissions apply **per OU**. Delegate them for all source OUs, target OUs and group OUs you permit later in the interface. To move an account the operator needs the right to create objects in the target OU.
- The built-in group `Account Operators` has such rights by default, but **not** for protected accounts (for example members of `Domain Admins`).

**Enable certificate validation (optional):**

1. Export the CA root certificate (format *Base-64 encoded X.509*) and save it as `./data/ca.pem`
2. In `.env`: `LDAP_CA_FILE=/app/data/ca.pem` and set `AD_DC_IP` to the **fully qualified DNS name** of the DC (for example `dc1.company.local`) as contained in the certificate
3. The Docker host must be able to resolve this name (see the note on `dns:` in [section 4](#4-configuration))

---

## 6. First-time setup in the interface

Sign in as an **administrator**. The settings are found in each menu item in a box marked *„(Nur Admin)"* (administrators only).

1. Open *AD-Struktur* (AD structure): OUs and groups must be listed here. If the list is empty, the connection is not working (see [troubleshooting](#10-troubleshooting)).
2. **Offboarding:** choose the source OUs (accounts there may be offboarded) and the target OU for disabled accounts. Save.
3. *Passwort zurücksetzen* (password reset): choose the source OUs in which passwords may be reset. Save.
4. *Benutzerverwaltung* (user management): choose source OUs (scan area), permitted target OUs (moving) and group OUs (group selection). Save.
5. **Templates:** create at least one template for onboarding (see below).
6. *E-Mail-Benachrichtigung* (optional): enter the SMTP server, save and send a test mail with the test button.
7. **Test as an operator:** sign in with an operator account and run one onboarding, one password reset and one offboarding with a test user.

Using the selection: OUs and groups appear as a **tree with checkboxes**. The arrows expand and collapse branches, the search box filters. For **source OUs and group OUs** a selected OU applies **including all sub-OUs**. For **permitted target OUs** exactly the selected OU applies.

As long as no source OUs are chosen for a module, its list stays empty and a note says that no OUs are configured.

### Templates

A template describes how a new user is created:

| Field | Meaning |
|---|---|
| *Template Name* | Name of the template (required) |
| *Username Makro* | Structure of the user name (`sAMAccountName`), see table below |
| *Ziel OU (DN)* | OU in which the account is created (enter a DN or pick from the AD list) |
| *E-Mail-Adresse / Postfach* | Whether the e-mail address is required, optional or not asked, and whether an Exchange mailbox is created (see [below](#e-mail-address-and-mailbox-per-template)) |
| *Passwort-Modus* | *Automatic random password* (12 characters, without easily confused characters such as 0/O or 1/l/I) or *fixed default password* (then the field *Standardpasswort* must be filled) |
| *Benutzer muss Passwort beim nächsten Login ändern* | Forces a change at first logon |
| *Kennwort läuft nie ab* | Sets the "password never expires" flag |
| *AD Gruppen zuweisen* | Groups the user is added to (tree with checkboxes) |
| Further fields | Optional: display name, department, company, job title, manager (manager DN), office, phone, address, country and more |
| Profile (like the RSAT tab "Profile") | **Profile path**, **logon script** and **home folder** (see below) |

**Home folder** as in RSAT: *Local path* (path only, e.g. `C:\Users\%username%`) or *Connect* with a drive letter (`D:` to `Z:`, default `Z:`) and network path (`\\server\home$\%username%`). A drive letter requires a network path; the application checks this when saving. By default only the AD attributes are set (`homeDirectory`, `homeDrive`). With the option to **create the folder automatically when the user is created**, the application also creates the folder itself (see [Creating the home folder automatically](#creating-the-home-folder-automatically)). Profile path, logon script and home folder are limited to 260 characters (AD limit).

Text fields may contain the placeholder `%username%`. It is replaced by the new user name, for example for the path `\\server\home\%username%`.

**Naming macros** (examples):

| Macro | Name | Result |
|---|---|---|
| `%LASTNAME%%FIRSTNAME%[3]` (default) | Max Mustermann | `MUSTERMANNMAX` |
| `%FIRSTNAME[1]%.%LASTNAME%` | Anna Schmidt | `A.SCHMIDT` |
| `%LASTNAME[5]%%FIRSTNAME[2]%` | Eva Öztürk | `OEZTUEV` |

- `%FIRSTNAME%` and `%LASTNAME%` stand for first and last name; `[n]` uses only the first *n* characters
- The name is built in upper case, umlauts are transliterated (Ä → AE, ß → SS), accents are dropped, spaces and hyphens are removed
- Only `A–Z`, `0–9`, `.`, `_`, `-` are allowed, **at most 20 characters**
- If the name is already taken, a number is appended (`…2`, `…3`)

---

## 7. The modules in detail

### Onboarding

1. Choose a template, enter first and last name and (depending on the template) the e-mail address
2. The account is created in the template's target OU (name: *First Last*, UPN: `username@company.local`)
3. The account is first created **disabled**, then the password is set, then it is enabled. If setting the password fails, the half-finished account is deleted again
4. The template's groups are assigned. If this fails for individual groups, a warning is shown
5. The credentials appear in the result window (copy or print as PDF). If SMTP is active, a mail goes to the employee who performed the action

#### E-mail address and mailbox per template

In a template's dialog (menu item **Templates**) the administrator chooses under *E-Mail-Adresse / Postfach* what happens during onboarding with this template. Templates for different environments can therefore coexist:

| Setting | When it makes sense | Behaviour |
|---|---|---|
| **Own mail server without Exchange** (default) | The address must be stored in AD | Required field, no account without an address |
| **E-mail address optional** | Mixed environment | Field present, may stay empty |
| **On-premises Exchange** | The mailbox should be created automatically | Field hidden, the mailbox is created via Exchange (see next section) |
| **Microsoft 365 / Exchange Online** | The mailbox is created through the licence | Field hidden, the `mail` attribute is not set |

During onboarding the form follows the selected template: switching the template shows or hides the e-mail field accordingly. The server enforces the setting as well (with *Exchange* and *Microsoft 365* a submitted address is ignored). If no address was set, the e-mail line is omitted in the mail and the result window.

The dialog also shows a **hint** read from AD: an entry *Microsoft Exchange* in the configuration partition indicates Exchange, an account `MSOL_*` or `AAD_*` indicates Microsoft Entra Connect (Azure synchronisation). This is only a recommendation; a pure cloud environment does not have to leave traces in AD.

**Older templates** without this setting remain *required*. If the global setting *do not ask* was chosen in version 1.15, templates without their own value inherit it as *Microsoft 365* until they are saved once.

**Microsoft 365:** the application does not create a mailbox there. It is created when a licence is assigned to the user. This can be automated: add the group that assigns the licence via *group-based licensing* to the template. After the next synchronisation (usually about 30 minutes) the mailbox exists.

#### Creating a mailbox on an on-premises Exchange server

For templates set to *On-premises Exchange*, the application runs `Enable-Mailbox` on your Exchange server after creating the account. The connection is set up once in the menu item **Templates**, box *Exchange im eigenen Haus* (on-premises Exchange):

| Field | Meaning |
|---|---|
| Enable Exchange integration | Switch, **off** by default. While it is off, a template with *On-premises Exchange* only gets a warning and no mailbox is created |
| Exchange server | Server name without `https://` (e.g. `exchange01.company.local`), reachable from the container |
| Port, HTTPS, verify certificate | Default `443`, HTTPS on, verification on. Only turn verification off if the certificate cannot be trusted otherwise |
| Authentication | *Automatic (negotiate)*; if there are problems try *NTLM* or *Kerberos* |
| Mailbox database | empty = Exchange chooses |
| Domain controller | empty = the same DC the application used to create the account, so Exchange does not have to wait for replication |

Process and rules:

- The application connects to `https://<server>/PowerShell` (Exchange Management Shell) using the **credentials of the signed-in user**. That user needs the Exchange role *Mail Recipients* (e.g. through the role group *Recipient Management*). No Exchange credentials are stored
- **Test connection** checks reachability, authentication and whether `Enable-Mailbox` is available to the account, using the values in the form (even unsaved)
- If no mailbox is created (error, server unreachable), the **account remains**. A warning is shown and the mailbox can be created in Exchange later. Nothing is rolled back
- Exchange assigns the e-mail address according to its address policy. The application then reads it from AD and shows it in the result. The form does not ask for it with this template
- Creating the mailbox can take a few seconds; do not close the page meanwhile
- This uses the Python package `pypsrp` (in `requirements.txt`). If it is missing, the test reports it
- Every change of the setting and every connection test is recorded in the reports, without passwords

This feature can only be fully verified against a real Exchange server. Try it with a test account first.

#### Creating the home folder automatically

If a network path is entered as home folder in the template and the option to create the folder automatically is set, the following happens after the account has been created:

1. The application creates **only the last folder** of the path. The parent folder (e.g. `\\server\home$`) must exist
2. The new account gets **Full Control** (inherited by subfolders and files). All other permissions, including those inherited from the parent folder, stay unchanged. Afterwards the application reads back whether the entry really is set
3. If the folder already exists, it is **not touched** (it might belong to someone else). A note is shown
4. The folder is created with the credentials of the signed-in person, who needs the right to create folders and change permissions on the server
5. An error (server unreachable, missing right) **never** prevents creating the account. It appears as a note in the result window and in the reports (`homeFolder`)

As with deletion, the container must reach the file server on TCP 445. If the folder has no permission list at all (rare, "Everyone has access"), it is not changed.

### Offboarding

Choose an account from the source OUs. It is **disabled**, **removed from all groups** and moved to the **target OU**. Your own account cannot be offboarded.

**Multi-selection:** with the checkboxes up to 25 accounts can be offboarded at once (header checkbox = all visible). Before starting, a confirmation shows the number and the names. The accounts are processed one after another; an error with one account (e.g. protected, outside the source OU) does not stop the others. At the end you see what worked and what did not. Every account has its own audit entry; the notification mail is a single summary.

**Protected accounts:** privileged accounts are always rejected by the server (*403*), for all roles. Privileged means members (also through nested groups or as primary group) of *Domain Admins*, *Schema Admins*, *Enterprise Admins* and the built-in groups *Administrators*, *Account/Server/Print/Backup Operators*, as well as the built-in Administrator account (RID 500) and `krbtgt`. In the list such accounts are shown with a lock and cannot be selected. The check reads each account's real groups (`tokenGroups`) and not only the `adminCount` flag, which not every directory maintains. It is checked again when the action runs. If such an account really has to be processed, remove the membership in AD first.

**Restore (undo offboarding):** before every offboarding the application records the OU the account was in, its groups and whether it was enabled. Under *Offgeboardete Konten wiederherstellen* (bottom of the offboarding page) every account offboarded this way is listed with a **Restore** button (*Wiederherstellen*):

1. A **preview** shows what will happen: back to the OU, back into these groups, enabled again. Nothing is changed by the preview
2. If the old OU no longer exists or is no longer within the offboarding source OUs, you choose another OU from the list
3. After **Restore** the account is moved, added back to its groups and enabled. Offboarding did not change the password, so it still works

Account and groups are looked up by their fixed AD identifier (`objectGUID`), even if they have been renamed or moved in the meantime. A deleted group is skipped (note), a group without write permission is reported individually, and everything else is still restored. An account that was already disabled before offboarding stays disabled.

Anyone allowed to offboard may restore. Administrators can additionally **discard** an entry (e.g. if the account was restored by hand). An entry disappears once the account has been restored, deleted or discarded. The data is stored in `data/offboarding.db` (SQLite, no additional software needed), without passwords. Accounts offboarded before version 1.19 have no entry. Every restore is recorded in the reports (`offboarding-restore`); if offboarding mails are enabled, a notification is sent.

### Password reset

Choose an account from the permitted OUs, then *random password* (12 characters) or *manual* (at least 6 characters; the AD password policy applies). Optional: force a change at next logon and unlock the account. The new password is shown once in the result window.

### User management

- **Move:** move the account to one of the permitted target OUs
- **Groups:** add or remove group memberships from the permitted group OUs

All user lists are sorted alphabetically by display name.

### Delete accounts (administrators only)

The menu item *Konten löschen* is only visible to administrators. Account Operators do not see it, and the server additionally rejects their requests with *403*. Protected (privileged) accounts, see offboarding, can neither be simulated nor deleted here.

**Setup (configuration on the page, administrators only):**

1. Choose the **OU of the disabled accounts** (pre-filled with the offboarding target OU). Only accounts in this OU that are also disabled appear in the list.
2. For every storage location you use, tick it and enter the **base paths** as UNC paths (one per line). **Storage locations are optional:** if your domain has no profiles, home folders or folder redirection on servers, leave all of them unticked. The application then only deletes the AD account and does not access any files (and `smbprotocol` is not needed for that). Simulation, password confirmation and all protections still apply. An enabled storage location needs at least one base path:

   | Storage location | Looked for | Notes |
   |---|---|---|
   | Roaming profile | `<base path>\<user name>.V2` | Only folders with one of the configured **suffixes** (`V2`, `V6`, …). Without a matching suffix nothing is suggested |
   | Folder redirection | `<base path>\<user name>` | Not stored in an account attribute but in the GPO, hence the fixed base path |
   | Home folder | `<base path>\<user name>` | Additionally the path from the account's `homeDirectory` |

   For profile and home folder the path from the AD account (`profilePath`, `homeDirectory`) can be used too. It only counts if it is **below a base path**. `%username%` is replaced, other variables are rejected.
3. Optional per storage location: **take ownership if access is denied** (see below)
4. Save, then **test the connection to the base paths**. The test reports for each base path whether the server is reachable and the content readable.

**Simulation:** click *Simulation* in the list. It shows the AD account (name, DN, number of groups) and for each path the status, source, number of files and folders and the size. The simulation changes nothing.

**Delete:** if the simulation looks right, the field *Endgültig löschen* (delete permanently) appears below it. To confirm, type the user name, enter your **own password** and confirm the dialog. The password is compared with that of the current session. A wrong password does not use up the plan. After 5 failed attempts deletion is locked for this session for about 5 minutes; every failed attempt is recorded in the reports (`deletion-password-fail`, without the password). Process:

1. The plan from the simulation is valid for **10 minutes**, only for this session and this account, and only **once**
2. Everything is **checked again** before deleting. If anything changed since the simulation (new folder, access revoked, account enabled again), nothing happens and the simulation must be repeated
3. First the **folders** are deleted (files first, then folders from the inside out), then the **AD account**
4. If something fails for a folder (e.g. a locked file, see troubleshooting), the **AD account remains**. The result list shows per folder what was deleted and what was not. After fixing the cause, repeat the simulation; only the rest will be found
5. Every deletion is recorded with all folders and numbers in the reports (`deletion-execute`)

**Several accounts at once:** tick accounts in the list (or *all visible* at the top, at most **25 per run**) and click *Auswahl simulieren* (simulate selection).

- The **batch simulation** is read-only. Every account appears as *ready* or *blocked* (with reason, e.g. still enabled, no access, shared folder); the paths can be expanded. Blocked accounts are never deleted
- To confirm, type the **number** of ready accounts and enter your own **password**. The number catches accidental triggering, the password makes sure it really is you
- Deletion runs as a **background job** with a progress display. The page may stay open, but the job also continues on the server without it
- Every account goes through the same process as a single deletion (re-check, folders first, then the AD account). If one fails, it remains and the others continue. A table shows the result per account at the end
- The reports contain one entry per account (`deletion-execute`) and a summary entry (`deletion-batch`). The deletion mail is **one summary** per run
- The simulation runs sequentially in one request. With 25 very large profiles this can take a while. If requests go through a reverse proxy, choose a generous timeout
- If the container is restarted during a job, the job ends there. Accounts already deleted are in the reports; the rest remains and can be simulated again

**Taking ownership (optional, per storage location):** Windows often creates profile folders so that only the user has access. Instead of changing permissions on the server by hand, the application can do it. If the option is enabled for a storage location:

- The **simulation** only checks whether ownership could be taken (handle with the right *change owner*) and changes nothing. Affected folders show the status *ownership required*. Their content cannot be counted beforehand, so the numbers are minimums
- During **deletion**, only for an entry that fails with *access denied*, the owner is set to `Administrators` and this group gets Full Control. Then it is retried **once**. Only folders and files that are deleted anyway are touched
- Every takeover is counted: in the result ("ownership taken: n×") and in the reports (`takeovers`, `takeoverPaths`)
- The signed-in administrator needs the Windows right *Take ownership of files or other objects* on the file server (Domain Admins and local administrators have it by default). Without it the folder remains an obstacle and the simulation reports *no access*
- Without the option everything works as described: missing access prevents deletion

Deletion is **permanent, without a recycle bin**. The AD account can only be recovered via the AD Recycle Bin (if enabled), the files only from a backup or the file server's shadow copies. With very large profiles deletion can take a few minutes; do not close the page meanwhile.

**Protections:**

- Only paths **below** the configured base paths are considered. The base path itself and the share are never a target
- Rejected: `..`, wildcards (`* ?`), `:` (streams), `%`, a trailing dot or space, and paths not starting with `\\`
- If the same path is also set in AD for **other accounts** (e.g. a shared department folder as home folder), it is excluded
- Links (junctions, symlinks) are **never followed**: only the link itself is removed, the content of the target is untouched. The simulation shows how many links are contained. If the target folder itself is a link, it is skipped
- The SMB library deletes read-only files by removing the attribute first
- Your own account and accounts that are still enabled are rejected
- Every simulation, every deletion and every settings change is recorded in the reports

**Network requirements:**

- The container reaches the file servers on **TCP 445** (SMB)
- The signed-in administrator needs **read and delete permissions** on the folders. The file server decides; the application does not bypass anything. Windows often creates profile folders so that only the user has access. The GPO *"Add the Administrators security group to roaming user profiles"* or a suitable permission on the share helps here. Without access the simulation reports *no access*
- **Mail after deletion** (SMTP setting *Löschen eines Kontos*) can be switched off and stays off until you enable it. The mail goes to the signed-in person and lists account, result, folders, number of files and ownership takeovers. It is also sent if deletion was incomplete. It contains no passwords
- **No Samba server is needed in the container.** The application only uses an SMB client (Python package `smbprotocol`, included in `requirements.txt`)
- Authentication to the file server uses NTLM with the administrator's credentials. The file server should be reachable by name or IP and support SMB signing

---

## 8. Operation

### Account lists and cache

The interface only loads the page that is open. The server keeps the account lists per session for up to **60 seconds in memory** (`samonboarding/listcache.py`); every change clears them immediately; **Refresh accounts** / **Reload** always reads fresh (`?frisch=1`). There is deliberately **no copy of the AD accounts in a database**: everyone only sees what their own AD permissions allow, nothing is written to disk, and decisions such as *protected?* or *in the released OU?* are checked live on the DC before every action. The protection check for the list needs a few combined queries instead of one query per account.

### Renamed or moved OUs and groups

Settings and templates store OUs and groups as DNs. For every reference the application remembers the objectGUID (`data/verweise.json`). If an OU/group is renamed, moved or deleted in AD, administrators see a notice at the top; **Apply new names** updates all affected settings (recorded in the reports as `config-references`). Deleted objects must be replaced by hand. Roles depend on SIDs, restoring after offboarding on GUIDs – neither is affected by renames. Details: manual, section *Initial setup*.

### Reports and log

Everything is written to **`data/reports.db`** (SQLite), without passwords. Administrators see it in the interface under **Reports**:

| Section | Content | Deleted automatically after |
|---|---|---|
| **Changes** | Who did what and when: sign-in, onboarding, offboarding, password reset, groups, deletion, settings, with result and details | 365 days (`AUDIT_RETENTION_DAYS`) |
| **Log** | Program messages from level *Info* upwards (e.g. connection errors, warnings) | 90 days (`LOG_RETENTION_DAYS`) |

- Search, filters (successful/failed, or warnings/errors) and *Load more* for older entries
- **Delete manually:** at the bottom of the page choose "older than 30/90/180 days" or "all entries" and confirm with your own password. The deletion itself is recorded in the changes
- Deleted entries are overwritten in the database file (`secure_delete`) and cannot be recovered
- An existing `audit.log` from older versions is imported on first start and then removed

The container output (`docker compose logs -f`) is still available, limited to 3 × 10 MB. Individual browser requests (IP addresses) are not logged.

Subject access request (Art. 15 GDPR), i.e. everything the application has stored about an account: in the interface under *Data protection*, or with

```bash
docker compose exec samonboarding python -m samonboarding.privacy auskunft jdoe
```

### Update

From version 1.39.0 the installation files (`update.sh` with all its output, `.env.example`, `Dockerfile`, `docker-compose.yml`) are in English. The setting names in `.env` are unchanged, so an existing `.env` keeps working.

**Ready-made image from GitHub (recommended):**

```bash
cd /opt/samonboarding
sudo sh update.sh --pull
```

The script fetches the newest image from `ghcr.io/soleil0815/samonboarding` (`docker pull`) – GitHub built and tested it, nothing is built on the server. Before that it backs up `data/`, afterwards it restarts the container and checks that it becomes "healthy". `update.sh` and `docker-compose.yml` are brought to the state of the image as well. **If the new version does not start, the script automatically puts the previous image back into service.** `.env`, `data/` and `backups/` stay unchanged. `git` is not needed for this, so a `git clone` never has to be updated. A specific image instead of the newest one: `SAMONBOARDING_IMAGE=ghcr.io/soleil0815/samonboarding:1.43.0` in `.env`.

If the repository is private, the image is private too. Then log in once as root (user `soleil0815`, password = a token with the *read:packages* permission):

```bash
sudo docker login ghcr.io -u soleil0815
```

**As a ZIP:** upload the ZIP of the new version to the project folder (e.g. `/opt/samonboarding`) and run there:

```bash
sudo sh update.sh samonboarding-*.zip
```

The script checks the ZIP (a single top folder, no invalid paths or links, really SAMONBOARDING), shows the installed and the new version and how many files change, are added and are dropped, and asks **once** (type `y`). It then backs up the current program files to `backups/programm-<version>-<date>.tar.gz`, swaps the files, removes files that no longer exist in the new version and continues with the new version's script (backup of `data/`, build, start, check). Finally it cleans up: the ZIP, temporary files and old SAMONBOARDING images are removed. If the build fails or the new version does not start, the previous program files come back and the ZIP stays.

`.env`, `data/`, `backups/` and a `docker-compose.override.yml` are never touched. Package versions pinned on the server (`requirements.txt`, `images.lock`, `package-lock.json`) are kept as long as they match the new version. Without the question (e.g. for scripts): `sudo sh update.sh samonboarding-*.zip --yes`. Unpacking uses `unzip`, otherwise `python3` or the Docker image – nothing needs to be installed.

Manually still works: unpack the new version (replace all files except `data/`, `.env`, `backups/` and any `docker-compose.override.yml`), then:

```bash
sh update.sh
```

The script first backs up `data/` to `backups/` (the last 3 backups are kept; `KEEP_BACKUPS=5 sh update.sh` keeps more), builds the image, restarts the container and checks that it becomes "healthy". If the build fails, the previous container keeps running unchanged. **If the new version does not start cleanly, the script automatically starts the previous image again.**

**New package requirements:** if a new version changes `requirements.in` (e.g. a minimum version because of a security issue), `update.sh` re-pins the Python packages automatically. It installs the new packages in a check container and runs the test suite, once with the previous and once with the new packages. Only if no additional test fails with the new packages, the same number of tests runs and a smoke test of the real application (`tests/smoke_app.py`) passes are the exact versions written to `requirements.txt`. Otherwise everything stays on the previous versions, with a notice; the rejected requirements are recorded in `.paketpruefung-abgelehnt` and only retried with `sudo sh update.sh --lock`. If a version running as root (before 1.31) is still in place, or on a first install, the script first sets up the new version with the previous packages and then updates the packages automatically in a second pass – only then is a rollback possible.

| Option | Effect |
|---|---|
| `--lock` | Re-pin all versions (Python packages, npm packages, base images with digest) and build afterwards, e.g. for security updates |
| `--no-cache` | Build without the Docker build cache |
| `--no-backup` | No backup of `data/` |
| `--prune` | Remove unused images afterwards |
| `--pull` | Fetch and start the ready-made image of the newest version from GitHub (nothing is built) |
| `--yes` | No question (when installing a ZIP) |

Only settings in `.env` changed: `docker compose up -d` is enough.

### Reproducible versions

Every build uses exactly the same versions:

| File | Content |
|---|---|
| `images.lock` | Base images with fixed versions (Python `3.11.13`, Node `22.17.0`); after `sh update.sh --lock` also with digest (`@sha256:…`) |
| `requirements.txt` | Lock list of all Python packages including dependencies, each `==version`. Installed with `--no-deps`; `pip check` then verifies that everything fits together |
| `requirements.in` | The direct Python packages (intent). `sh update.sh --lock` creates the lock list from it |
| `package.json`, `package-lock.json` | npm packages for CSS, fonts and icons, exact including all sub-packages (`npm ci`) |
| `requirements-dev.txt` | Test tools (pytest, ruff) with exact versions |

Versions only change deliberately with `sh update.sh --lock`. The script shows which Python packages change. Ideally commit the changed files to Git.

`data/`, `.env` and any `docker-compose.override.yml` are kept during an update; simply replace all other files with the new version. New options are listed in `.env.example`. All users are signed out afterwards.

**Internet block removed (from 1.38.0):** if an older version installed the internet block, `update.sh` removes it automatically once the new version is running and "healthy" (iptables chains `SAMONB-EGRESS*`/`SAMONB-HOST*`, the systemd units `samonboarding-internetsperre.service`/`.path`/`.timer` and `data/netziele.txt`). The lines `INTERNET_SPERRE`, `ZUSATZ_ZIELE`, `DATEISERVER_NETZE` and `DNS_SERVER` in an existing `.env` are ignored and can be deleted. `update.sh` still needs root rights (as root or with `sudo`) for the permissions on `data/` and this cleanup.

### Backup

Back up the `data/` folder. It contains:

- `smtp_config.json`, `templates.json` and the module configurations
- `offboarding.db` (stored states for restoring after offboarding)
- `reports.db` (reports: changes and log)
- `tls/` (HTTPS certificate and key)

### HTTPS

The application speaks **HTTPS only** (port 9500). There is no unencrypted port; requests without HTTPS are rejected. TLS 1.2 and 1.3 with modern ciphers are allowed. The session cookie is `Secure`, `HttpOnly` and `SameSite=Strict` and ends when the browser closes.

**Certificate:**

1. **Without your own certificate**, the application creates a self-signed one (valid for 10 years) in `data/tls/` on first start. The browser warns once. To get the right name into the certificate, set `TLS_HOSTNAMES` in `.env`, or create a new self-signed certificate with the right names in the interface under **Certificate**.
2. **Your own certificate** (e.g. from your internal CA, recommended): upload it in the interface under **Setup → Certificate** (administrators only). It takes effect **immediately, without a restart**. New connections get the new certificate; reload the page once.
   - **PFX/P12** with password, e.g. from the Windows certificate manager (*Export → Yes, export the private key*). Intermediate certificates are included.
   - **Certificate + key** as PEM or DER (`.pem`, `.crt`, `.cer`, `.key`); the key may be password-protected. Intermediate certificates optionally as a separate file or inside the certificate file.
   - Before applying, the application checks: do certificate and key belong together? Is it valid (not expired)? Is the key strong enough (RSA from 2048 bits, or ECDSA)? Does the server accept it? It warns if the certificate expires soon, has no subject alternative names (SAN) or intermediate certificates are missing.
   - The previous certificate is kept as `cert.pem.prev` / `key.pem.prev` in `data/tls/`. Every change is recorded in the reports.
   - The page shows the current certificate with names, issuer, expiry date and fingerprint. From 30 days before expiry a warning appears daily in the log.

With your own certificate the application also sends HSTS (for one day), so the browser only opens the site over HTTPS from then on. It does not do this with a self-signed certificate, otherwise the warning could no longer be clicked away.

Without the interface, files still work (restart afterwards):

```bash
cp onboarding.crt data/tls/cert.pem    # PEM, including intermediate certificates
cp onboarding.key data/tls/key.pem     # PEM, without password
docker compose restart
```

A reverse proxy is no longer needed. If you use one anyway, forward to `https://<container>:9500`.

---

## 9. Security notes

- Run it in the internal network only, **not** on the internet
- **Roles by SID:** administrators are members of *Domain Admins*, *Enterprise Admins* or *Administrators*; operators are members of *Account Operators* or your own group (`CUSTOM_OPERATOR_GROUP`). This is detected by the groups' fixed SIDs, not by name, so it also works on German DCs, and a self-made group called "Domain Admins" grants no rights
- **What operators may not do:** only administrators can reset, move, change or restore protected accounts (Domain Admins etc.), and only administrators can add accounts to privileged groups (e.g. Backup Operators, Schema Admins). Offboarding and deleting protected accounts is blocked for everyone
- **Checks on the real DN:** allowed OUs are checked against the DN returned by the DC. Special DN forms like `<GUID=…>` or `<SID=…>` are rejected
- **Delete only matching folders:** a path from an AD attribute (home folder, profile path) is only deleted if the folder name matches the user name (`mueller` or `mueller.V6`). If it points to someone else's folder, it is skipped
- **Requests only from the own site:** write requests with a foreign `Origin` are rejected, in addition to the `SameSite=Strict` cookie. If you use a reverse proxy anyway, it must pass the `Host` header through unchanged. Requests over 6 MB are rejected, and the automatic API documentation (`/docs`) is switched off
- **File permissions:** configuration (including the SMTP password), databases and the certificate key are stored readable by the owner only (0600)
- **SMTP password:** if server or user name change, the password must be entered again, so the stored password cannot be sent to a foreign server
- **Data protection in the interface:** the *Data protection* link (bottom of the sign-in page, sidebar under *Help*) briefly shows what is stored and the current retention periods. Administrators can download the subject access report (Art. 15 GDPR) for an account as JSON there (recorded in the reports)
- **Data protection:** which data is kept where, retention periods, built-in measures and a template for the record of processing activities are in [DATA-PROTECTION.en.md](DATA-PROTECTION.en.md)
- **No internet connections at runtime:** Tailwind CSS, fonts (Manrope, JetBrains Mono) and icons (Font Awesome) are packed into the image during the Docker build and served by the application itself. There are no CDNs, no Google Fonts, no telemetry and no update check. In addition, a Content Security Policy header forbids the browser to load anything from other servers. Only the **build** needs internet (npm, pip, Docker base images). At runtime, connections go only to your own services: domain controller, file server, SMTP and, if configured, Exchange
- **Vulnerability scan (Trivy):** every image is checked with [Trivy](https://trivy.dev) on GitHub before it is published. If there is a serious vulnerability (CRITICAL/HIGH) with an available fix, the image is not published, and the run page under *Actions* lists the findings. On Mondays GitHub rebuilds the image automatically with the newest Python packages and Debian security updates and publishes it only if tests and scan pass. It reaches a server only with `sh update.sh --pull`. If the run fails, GitHub sends an e-mail and the last clean image stays. This can usually be fixed with newer base images in `images.lock` or a minimum version in `requirements.in`. If a finding cannot be fixed and demonstrably does not affect the program, add it to `.trivyignore` with a reason and date.
- The application runs over HTTPS only (see above). Ideally install your own certificate and leave `LDAP_ALLOW_PLAIN` at `false` (default)
- Give operators only the rights they need (delegation on individual OUs)
- The `data/` folder contains the **SMTP password in plain text** and possibly fixed template passwords. Restrict permissions (`chmod 700 data`) and protect backups
- For onboarding and password reset, notification mails contain the new password in plain text and go to the acting employee. Mails for offboarding, password reset, user management and deletion can be switched off individually in the SMTP settings. The onboarding mail is sent as soon as SMTP is enabled; if you do not want that, do not enable SMTP
- The application protects against password guessing with a temporary lock per user and IP (default: 5 attempts, 5 minutes). An AD account lockout is independent of this; plan your AD policy accordingly
- Deletion is reserved for administrators (menu hidden, the server checks the role). File server access runs with the signed-in administrator's permissions. Deleted files cannot be restored; plan backups or shadow copies on the file server
- **No root in the container:** the application runs as user 10001 without Linux capabilities and cannot gain privileges (`no-new-privileges`). `data/` belongs to this user and only it can read it (`update.sh` sets this)
- The image contains no data from `data/` (`.dockerignore`). Still, do not push it to public registries

---

## 10. Troubleshooting

| Message / symptom | Cause and fix |
|---|---|
| *Domain Controller … nicht erreichbar* (not reachable) | Port 636 not reachable from the Docker host, firewall or wrong `AD_DC_IP`. Test: `openssl s_client -connect DC:636` (see [section 5](#5-preparing-active-directory)). With a name: check DNS |
| *LDAP-Anmeldung fehlgeschlagen* (LDAP sign-in failed) | Wrong user name or password, account locked or disabled. One attempt per sign-in counts against the AD lockout |
| *Zugriff verweigert: Sie müssen Mitglied der Gruppe …* (access denied) | The user is neither administrator nor operator. Check group membership. For `CUSTOM_OPERATOR_GROUP` the **sAMAccountName** counts. New memberships apply after signing in again |
| *SMTP-Server … nicht erreichbar* (not reachable) / mails are not sent | Check the server name and port in the SMTP settings and that the network or firewall allows the connection from the Docker host to the mail server. Then check with *Send test email* |
| *Zu viele fehlgeschlagene Anmeldungen* (too many failed sign-ins) | Temporary lock of the application (HTTP 429). Wait about 5 minutes |
| *Passwort setzen fehlgeschlagen* (setting the password failed) | The password does not meet the policy, the connection is not encrypted via LDAPS (check port 636, `LDAP_ALLOW_PLAIN=false`) or the user lacks rights on the OU |
| Lists are empty | No source OUs chosen for the module yet ([section 6](#6-first-time-setup-in-the-interface)) or the account is not in these OUs |
| *Das Konto liegt nicht in einer … freigegebenen Quell-OU* | The target is outside the configured OUs. As administrator, extend the OUs |
| Action fails with *insufficientAccessRights* | The signed-in user lacks AD rights on the OU (delegation, [section 5](#5-preparing-active-directory)) |
| Certificate error (with `LDAP_CA_FILE`) | Wrong CA file, or `AD_DC_IP` is not the name from the certificate |
| Interface without styling or icons | The image was built without local files. The logs say *"Lokale Assets … fehlen"* (local assets missing). Rebuild with `docker compose build --no-cache` |
| Changing `AD_DOMAIN` or `AD_DC_IP` has no effect | Check whether `data/config.json` exists. It takes precedence and must be adjusted or deleted |
| *Sitzung ungueltig - bitte neu anmelden.* (session invalid) | The user's password was changed in AD or the session expired |
| *Dieses Konto ist geschützt ...* (403) on offboarding or deletion | The account is a member of a privileged group (e.g. Domain Admins). Intended protection. If it really has to be processed, remove the membership in AD first |
| Onboarding warning *Postfach konnte nicht angelegt werden* (mailbox could not be created) | Read the message: *authentication rejected* → change the authentication (NTLM) or check the *Mail Recipients* role. *Not reachable* → server name, port 443 and firewall from the container to Exchange. *Certificate* → trust the certificate or deliberately turn verification off. The account exists; create the mailbox in Exchange |
| Restore: *Die OU … gibt es nicht mehr* (OU no longer exists) | Choose another OU in the restore dialog |
| Times in the reports are in UTC | `TZ` is missing in `.env` or the image is old. Set `TZ=Europe/Berlin` and rebuild (`docker compose up -d --build`) |
| Deletion: *Seit der Simulation hat sich etwas geändert* (something changed since the simulation) | The state changed between simulation and deletion (e.g. a user signed in and created a profile). Nothing was deleted. Repeat the simulation |
| Deletion: *Nicht alle Ordner konnten gelöscht werden* (not all folders could be deleted) | Usually locked files (user still signed in, virus scanner) or missing delete rights. The AD account remains. Error details in the result list, then repeat the simulation |
| Deletion simulation: *Dateiserver nicht erreichbar* (file server not reachable) | Port 445 from the container to the file server is blocked or the server name in the path is wrong. Check with the connection test on the page |
| Deletion simulation: *Anmeldung am Dateiserver fehlgeschlagen* (file server sign-in failed) | The server rejects NTLM with the administrator's credentials (account without access to the share, SMB signing / NTLM policy) |
| Deletion simulation: *Kein Zugriff* (no access) to a profile folder | The administrator has no rights on the folder, typical for roaming profiles. Check the GPO that adds the Administrators group, or share/NTFS permissions |
| Deletion: file or folder *ist in Benutzung (gesperrt)* (in use) | A file is still open (user signed in, virus scanner, indexing). End the session on the server (`Get-SmbOpenFile | Close-SmbOpenFile`) or wait, then repeat the simulation. Taking ownership does not help here |
| Deletion: *Besitzübernahme fehlgeschlagen* (taking ownership failed) | The administrator lacks the right *Take ownership of files or other objects* on the server, or the folder is on a drive without NTFS permissions |
| Deletion simulation: profile folder not found | The suffix does not match (e.g. `.V6` instead of `.V2`) or the folder is not below a configured base path |
| Build stops with `"/samonboarding/web": not found` | The `samonboarding/` folder is not next to the `Dockerfile` |

---

## 11. Development

### Structure

```
app.py                      entry point for uvicorn (app:app), only imports samonboarding.main
samonboarding/
  main.py                   builds the FastAPI app: routers, error handling, security headers
  config.py                 environment variables, paths, defaults, VERSION
  storage.py                read/write JSON files (atomic, with lock)
  audit.py                  audit(...) and audited(...): write changes to the reports
  reports.py                reports in SQLite (data/reports.db): changes, log, search, deletion, audit.log import
  tls.py                    HTTPS certificate: check (PFX/PEM/DER), save, swap at runtime, create self-signed
  routers/certificate.py    "Certificate" page: show, upload, create self-signed (admins only)
  serve.py                  start over HTTPS only (python -m samonboarding.serve)
  errors.py                 AdError, DcUnreachable
  dn.py                     DN/filter helpers (escaping, splitting, comparing)
  ldap_client.py            connection, search, error checks, Row objects, sorting
  sessions.py               sessions, sign-in lock
  permissions.py            role check, check of permitted OUs
  naming.py                 passwords, naming macros, country codes
  models.py                 Pydantic request models
  mailer.py                 e-mail template and SMTP sending
  fileshare.py              UNC path checks, target folders, folder scan, deletion, SMB access (smbprotocol)
  offboard_store.py         stored state before offboarding (SQLite, data/offboarding.db)
  adguid.py                 read and search objectGUID (find accounts/groups again after renaming)
  listcache.py              account lists kept briefly in memory per session (60 s, cleared on every change)
  references.py             check references to OUs/groups in the settings and update them after renames
  routers/references.py     /api/references (check) and /api/references/repair (admins only)
  acl.py                    read/modify Windows security descriptors (owner, access entries)
  routers/                  one module per area (auth, settings, usermgmt, offboarding, restore,
                            pwdreset, deletion, infrastructure, templates, onboarding, ui)
  web/index.html            complete interface (HTML + JavaScript)
  web/theme.json            colours and fonts of the interface (for the Docker build)
  web/i18n.json             English texts (interface, messages, mails)
  web/manual/               manual (HANDBUCH.md, MANUAL.en.md) - shown in the interface under Help → Manual
  i18n.py                   server-side translator (mails) and per-request language (header X-UI-Lang)
  routers/privacy_info.py   data protection window: retention (/api/privacy-info) and subject access for admins (/api/privacy/report)
  privacy.py                data protection: retention periods (daily), subject access (python -m samonboarding.privacy)
DATA-PROTECTION.en.md       data protection documentation (GDPR), German: DATENSCHUTZ.md
Dockerfile                  stage 1 builds Tailwind CSS, fonts (Manrope, JetBrains Mono) and Font Awesome, stage 2 is the app
tailwind.config.js          Tailwind scans samonboarding/web/*.html, colours and fonts from web/theme.json
tests/                      unit tests and scenarios (see Tests)
pyproject.toml              ruff and pytest configuration
requirements-dev.txt        packages for testing (exact versions)
requirements.in             direct Python packages; requirements.txt is the exact lock list
package.json                npm packages for the CSS build (exact); package-lock.json is created by sh update.sh
images.lock                 base images (Python, Node) with fixed version or digest
update.sh                   back up, build, restart, check status; --lock re-pins the versions
```

### Adding a feature

1. Create `samonboarding/routers/<name>.py` with `router = APIRouter()` and the endpoints
2. Import it in `samonboarding/main.py` and add it to the list of routers
3. Import shared helpers (LDAP, DN, permissions) from the existing modules
4. Record new actions in the reports with `audited(...)` and check permissions on the server (`require_admin`, `require_user_in_ous`)
5. Write new texts in German and add the English version to `web/i18n.json` (`exact` for fixed texts, `patterns` with `{0}` for texts with values). Output AD data in the interface with `nt(...)` or `translate="no"` so it is never translated

### Notes

- New **Tailwind classes** in `web/index.html` need a new image build (`docker compose up -d --build`), because the CSS is generated from the HTML file during the build
- Changes to **Python code** need a new image build (`sudo sh update.sh`). The code is part of the image and is not mounted from the host, so an image restored by a rollback also brings its own code
- The Python packages are deliberately minimal: `fastapi`, `uvicorn`, `ldap3`, `pydantic`, plus `smbprotocol` for the file server features and `pypsrp` for the Exchange mailbox

### Tests

```bash
pip install -r requirements-dev.txt
pytest -q          # all tests
ruff check . && ruff format --check .
```

| File | Checks |
|---|---|
| `tests/test_acl.py` | Windows security descriptors (SID, ACE, inserting before inherited entries, broken data) |
| `tests/test_protection.py` | Protection of privileged accounts (SIDs from raw data, nested groups, RID 500/502), Samba/Windows detection and Exchange/Entra hint |
| `tests/test_exchange.py` | Exchange settings validation, calls to the Exchange Management Shell (with stand-in modules for `pypsrp`), error messages |
| `tests/test_fileshare.py` | UNC path checks, target folders, scan, deletion with links and ownership takeover, error mapping, home folder creation |
| `tests/test_smb_requests.py` | Builds permission requests with the real `smbprotocol` classes (no server). Skipped without `smbprotocol` |
| `tests/test_ui.py` | Interface logic (JavaScript in `index.html`) under Node.js with a fake DOM: selection, batch simulation, password/count confirmation, progress, navigation, mobile menu, messages, restore dialog, language switch, loading only the open page. Skipped without Node.js |
| `tests/test_adguid.py` | Reading `objectGUID` (raw bytes) and writing it as an LDAP filter |
| `tests/test_i18n.py` | English: dictionary, every fixed API error message translated, mails in the chosen language |
| `tests/test_hardening.py` | Security review: folder name matches the account, mail values (password) are never translated, sender name, file permissions 0600, Exchange basic only with HTTPS, input, special DN forms, role SIDs |
| `tests/test_certificate.py` | Own certificate: PFX with chain, PEM/DER, encrypted key, mismatched pairs, expired, short keys, saving with `.prev`, swap at runtime, expiry warning, API admins only |
| `tests/test_https_reports.py` | Certificate creation/reuse, start with TLS only, HTTP rejected, HSTS only with own certificate, 30 minutes inactivity, reports API (admins only, deletion with password and record) |
| `tests/test_privacy.py` | Reports in SQLite (retention 365/90 days, search, paging, `secure_delete`, import of the old audit.log), restore entries, subject access |
| `tests/test_manual.py`, `tests/ui/manual.test.js` | Manual: sign-in required, both languages, safe rendering (no HTML, only internal or https links), every contents entry leads to a heading |
| `tests/test_assets.py` | Colours/fonts (`theme.json`), local-only asset loading, no internet addresses, CSP, fonts in the Dockerfile |
| `tests/test_scenarios.py` | Runs the scenarios in `tests/scenarios/`: sign-in and roles, onboarding, offboarding, groups, settings, deletion (simulation, execution, ownership takeover, mail), restore after offboarding, templates, sorting, renamed/moved OUs and groups |

The scenarios run against a **simulated AD and a simulated file server** and need no installed packages (small stand-in modules in `tests/scenarios/stubs`). Run one on its own with `python tests/scenarios/scenario_deletion.py`. They do **not** test real SMB connections or real file permissions; that is only possible on a test server (see Delete accounts — try with an unimportant account first). The same checks run on every push in GitHub Actions (`.github/workflows/image.yml`); the image is only built if everything passes.

## License

SAMONBOARDING is free software under the **GNU Affero General Public License, version 3 or later** (AGPL-3.0-or-later), see [LICENSE](LICENSE). You may use, share and modify the program. Anyone who offers a **modified** version to others – even only over the network as a web application – must make the source code of the modified version available to those users (section 13 of the license). That is why the sign-in page links to the source code; if you run your own version, point the link in `samonboarding/web/index.html` to your own repository. There is no warranty (sections 15 and 16).

The included packages (FastAPI, ldap3, Tailwind CSS, Font Awesome, fonts etc.) have their own licenses.
