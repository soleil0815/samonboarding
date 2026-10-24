# SAMONBOARDING – Manual

This manual explains how to use the interface: for **operators**, who create and maintain accounts every day, and for **administrators**, who set the application up. Installation and technical details are in the README.

The names of buttons and menus below are those of the English interface (switch with **EN** at the bottom of the sidebar).

## Contents

1. [Overview](#1-overview)
2. [Signing in and sessions](#2-signing-in-and-sessions)
3. [Roles: who may do what?](#3-roles-who-may-do-what)
4. [Onboarding: creating a new user](#4-onboarding-creating-a-new-user)
5. [User management](#5-user-management)
6. [Resetting a password](#6-resetting-a-password)
7. [Offboarding](#7-offboarding)
8. [Undoing an offboarding](#8-undoing-an-offboarding)
9. [Deleting accounts (administrators only)](#9-deleting-accounts-administrators-only)
10. [Initial setup (administrators)](#10-initial-setup-administrators)
11. [Templates](#11-templates)
12. [E-mail notification](#12-e-mail-notification)
13. [Reports](#13-reports)
14. [Certificate](#14-certificate)
15. [Data protection](#15-data-protection)
16. [Running the server](#16-running-the-server)
17. [Common questions and errors](#17-common-questions-and-errors)

---

## 1. Overview

SAMONBOARDING is a web interface for the life cycle of user accounts in Active Directory (Samba AD or Windows Server AD):

| Menu | Purpose |
|---|---|
| **Onboarding** | Create a new account from a template |
| **User management** | Move an account to another OU, maintain groups |
| **Reset password** | Set a new password, unlock an account |
| **Offboarding** | Disable an account, remove it from all groups, move it to the target OU; undo |
| **Delete accounts** | Permanently delete disabled accounts together with their profile and home folders (administrators only) |
| **Templates** | Templates for onboarding |
| **E-mail notification** | SMTP server and which mails are sent |
| **AD structure** | Overview of OUs and groups |
| **Reports** | Who did what and when, program messages (administrators only) |
| **Certificate** | Upload the HTTPS certificate (administrators only) |
| **News** | What changed in the installed versions. A small dot marks a new version, an orange dot a security update |

Good to know:

- **Every action runs with your own AD account.** The application has no service account of its own. Whatever you may not do in AD, you may not do here either.
- **Released OUs only.** Each module only shows accounts from the OUs an administrator has released for that module.
- **Everything is recorded**, without passwords (see [Reports](#13-reports)).
- **Language:** switch between German (DE) and English (EN) at the bottom of the sidebar. The browser remembers your choice.
- **Lists and "Refresh":** only the page you open is loaded. The application keeps the account lists for up to 60 seconds so that switching between pages is fast. After every change made through SAMONBOARDING the lists are up to date immediately. Changes made directly in AD (e.g. with RSAT) appear the next time the page is opened, after 60 seconds at the latest – or immediately with **Refresh accounts** or **Reload**. Before every action the application checks live on the DC anyway.

---

## 2. Signing in and sessions

1. Open the address in the browser, e.g. `https://server:9500`. With a self-signed certificate the browser warns the first time; an administrator can install a proper certificate (see [Certificate](#14-certificate)).
2. Sign in with your **AD user name** (e.g. `jdoe`, without the domain) and your AD password.

The session ends

- when you click **Sign out**,
- after **30 minutes without activity** (the interface tells you),
- when the application restarts, e.g. after an update,
- after **12 hours** at the latest, even if you keep working.

After several wrong passwords the application blocks further attempts for a few minutes (default: 5 attempts, 5 minutes). The AD account lockout policy applies independently.

---

## 3. Roles: who may do what?

The role comes from your group membership in AD. It is recognised by the fixed identifier (SID) of the group, not by its name.

| | Operator | Administrator |
|---|---|---|
| Who | Member of *Account Operators* or the custom operator group | Member of *Domain Admins*, *Enterprise Admins* or *Administrators* |
| Onboarding, user management, password, offboarding, restore | yes, in the released OUs | yes |
| Module settings, templates, SMTP | view only | yes |
| Delete accounts, reports, certificate | no | yes |
| Change protected accounts (e.g. Domain Admins) | no | yes (offboarding and deleting: nobody) |
| Add to privileged groups | no | yes |

New group memberships apply after the next sign-in.

**Protected accounts** are members (also nested) of Domain, Schema and Enterprise Admins, Administrators and the operator groups, plus the built-in Administrator account and `krbtgt`. They appear in the lists with a **lock**.

---

## 4. Onboarding: creating a new user

1. Open **Onboarding**.
2. Choose a **template**. On the right you see what the template does: target OU, how the user name is built, groups.
3. Enter **first name** and **last name**. Depending on the template also the **e-mail address** (required, optional or not asked).
4. Click **Create employee in Active Directory**.

What happens:

- The user name is built from the template's macro, e.g. `DOEJOH`. Umlauts are converted (Ö → OE). If the name is taken, a number is appended.
- The account is first created disabled, the password is set, then the account is enabled. If setting the password fails, the half-finished account is removed again.
- The template's groups are assigned. If that fails for a group, a warning appears; the account stays.
- Depending on the template an **Exchange mailbox** is created or a **home folder** is created on the file server. Errors there never prevent the account; they appear as a notice.

At the end a **result window** shows user name, logon name and password. **Copy** takes the data, **PDF credentials** creates a sheet to hand over. The password is not shown again afterwards. If e-mail notification is enabled, you also receive the credentials by mail.

---

## 5. User management

The table shows all accounts from the released OUs with their groups, sorted alphabetically. Use the search field to filter.

- **Move:** click **Move** next to the account, choose the target OU, **Move**. Only the released target OUs can be chosen.
- **Groups:** click **Groups**, tick or untick, **Save changes**. The groups from the released group OUs can be chosen.

---

## 6. Resetting a password

1. Open **Reset password**, find the account in the list, click **Reset password**.
2. Choose the mode:
   - **Automatic strong random password** (12 characters, without easily confused characters such as 0/O or 1/l/I) or
   - **Enter a new password manually** (twice; the AD password policy applies).
3. Options:
   - **User must change password at next logon** (recommended, on by default)
   - **Unlock the user account** if it is locked after failed attempts
4. Click **Reset**. The new password appears **once** in the result window.

---

## 7. Offboarding

Offboarding **disables** an account, **removes it from all groups** and moves it to the **target OU** for former employees. The password is not changed.

1. Open **Offboarding**, find the account, click **Offboarding** next to it and confirm.
2. **Several at once:** tick up to 25 accounts (the box at the top selects all visible ones) and click **Offboard selection**. A confirmation with number and names appears first. An error with one account does not stop the others; at the end you see what worked.

Not possible: your own account and protected accounts (with a lock).

---

## 8. Undoing an offboarding

Before every offboarding the application remembers the OU, the groups and whether the account was enabled. At the bottom of the offboarding page under **Restore offboarded accounts**:

1. Click **Restore** next to the account. A **preview** shows what will happen. Nothing is changed yet.
2. If the old OU no longer exists, choose another one.
3. Confirm **Restore**: the account returns to its OU and its groups and is enabled again (if it was disabled before, it stays disabled). The old password still applies.

A group deleted in the meantime is skipped and reported. Administrators can also **discard** an entry. Entries are deleted automatically after a period (default 180 days; the page shows the period).

---

## 9. Deleting accounts (administrators only)

Here **disabled** accounts are deleted **permanently**: the AD account and, if set up, roaming profile, folder redirection and home folder on the file servers. **There is no recycle bin.** The AD account can only be recovered from the AD Recycle Bin (if enabled), files only from a backup.

### Deleting one account

1. In the list (accounts in the OU of disabled accounts) click **Simulation**. The simulation **changes nothing**. It shows the AD account and, per folder, status, number of files and size.
2. If everything looks right: type the **user name** below it, enter **your own password** and click **Delete permanently**.
3. Before deleting, everything is checked again. If anything has changed since the simulation, nothing happens and you simulate again. The plan is valid for 10 minutes and only once.
4. Folders are deleted first, then the AD account. If a folder fails (e.g. a file still open), **the AD account stays**. Fix the cause and simulate again.

### Deleting several accounts

1. Tick accounts (at most 25) and click **Simulate selection**.
2. Each account appears as **Ready** or **Blocked** (with the reason). Blocked accounts are never deleted.
3. To confirm, enter the **number** of ready accounts and your **password**, then **Delete permanently**.
4. Deletion runs in the background with a progress display. At the end a table shows the result per account.

### Safeguards

- Only disabled accounts, never your own, never protected ones.
- Only folders **below** the configured base paths, and only if the folder name matches the user name.
- Folders that are also entered for other accounts are excluded.
- Links (junctions, symlinks) are never followed.
- After 5 wrong passwords, deleting is blocked for about 5 minutes.

---

## 10. Initial setup (administrators)

The settings are in a box **(admin only)** on the respective pages. You choose OUs and groups in a **tree with check boxes**; expand and collapse with the arrows, filter with the search field.

1. Open **AD structure** and check that OUs and groups appear. If the list is empty, the connection to the DC is not working.
2. **Offboarding:** set the source OUs (accounts may be offboarded from these) and the target OU for disabled accounts.
3. **Reset password:** set the source OUs.
4. **User management:** source OUs (which accounts appear), allowed target OUs (where accounts may be moved) and group OUs (which groups can be chosen).
5. **Templates:** create at least one template (see [Templates](#11-templates)).
6. Set up and test **E-mail notification** (optional).
7. **Delete accounts** (optional): enter the OU of disabled accounts and the storage locations with their base paths, save and check with **Test connection to the base paths**.
8. Sign in with an **operator account** and run through everything once with a test user.

Rule: for **source OUs** and **group OUs** a selected OU counts **with all sub-OUs**; for **target OUs** exactly the selected OU counts. As long as no source OU is chosen for a module, its list stays empty.

### When OUs or groups are renamed or moved in AD

The settings (source and target OUs of the modules, OU of disabled accounts, target OU and groups of the templates) store the **path (DN)** of the OU or group. If it is renamed or moved in AD, the stored path points nowhere. That is not dangerous – a missing OU returns no accounts, a missing group is not assigned – but the module no longer works as intended.

That is why the application remembers the fixed identifier of each referenced object (**objectGUID**), which stays the same when it is renamed or moved. Administrators see a yellow notice at the top of the page as soon as something no longer matches:

| Notice | Meaning | What to do |
|---|---|---|
| *renamed or moved* | The object still exists under a new name or in another place. The new path is shown | Click **Apply new names** – all affected settings and templates are updated |
| *deleted and created again* | A **different** object now has the old name (e.g. a group deleted and created again with the same name) | Check that this is intended; then **Apply new names** (confirms the new object) |
| *no longer exists* | The object was deleted | Choose another OU/group in the setting or template |

Good to know:

- The application remembers the identifiers as soon as an administrator opens the page. If an OU is renamed **before** that ever happened (e.g. after the update to this version, before any administrator has signed in), the notice says *no longer exists* – then simply select the OU again.
- **Roles** do not depend on group names but on fixed SIDs (Domain Admins, Account Operators …). Renaming these groups changes nothing.
- **Undoing an offboarding** finds the account and its groups by objectGUID, even after a rename.
- A **renamed account** (different user name) is the same account for the application. Home and profile paths stored in the account do not change automatically – deletion uses the path in the AD account.
- Selecting the group again in **Templates** after a rename achieves the same as *Apply new names*.

---

## 11. Templates

A template defines what a new account looks like. Open **Templates**: **+ New template**, or **Edit** or **Duplicate** an existing one.

| Field | Meaning |
|---|---|
| Template name | Name shown in the onboarding selection |
| Username macro | How the user name is built, e.g. `%LASTNAME%%FIRSTNAME%[3]` |
| Target OU | OU in which the account is created |
| E-mail address / mailbox | Required, optional, on-premises Exchange or Microsoft 365 |
| Password mode | Random password or fixed default password |
| Change password / never expires | Account options |
| AD groups | Groups for the new account |
| Further fields | Department, company, job title, manager, office, phone, address … |
| Profile | Profile path, logon script, home folder (as on the RSAT "Profile" tab) |

**Name macros:**

| Macro | Example John Doe |
|---|---|
| `%LASTNAME%%FIRSTNAME%[3]` | `DOEJOH` |
| `%FIRSTNAME[1]%.%LASTNAME%` | `J.DOE` |
| `%LASTNAME[5]%%FIRSTNAME[2]%` | `DOEJO` |

`[n]` takes the first *n* characters. Allowed are `A–Z`, `0–9`, `.`, `_`, `-`, at most 20 characters. In text fields `%username%` is replaced by the new user name, e.g. `\\server\home$\%username%`.

**E-mail and mailbox:**

| Setting | Behaviour |
|---|---|
| Own mail server without Exchange | Address is required and written to AD |
| E-mail address optional | The field may stay empty |
| On-premises Exchange | Field hidden, the mailbox is created on the Exchange server (set up and test the connection in the *On-premises Exchange* box) |
| Microsoft 365 | Field hidden, the mailbox is created through the licence |

**Create home folder automatically:** with a network path and the option to create the folder automatically, the application creates the folder and gives the new account full control. An existing folder is not touched.

---

## 12. E-mail notification

Open **E-mail notification** (operators can only view the settings).

1. **Enable e-mail sending globally**, enter server, port, TLS mode, user and password and the sender. For Strato for example `smtp.strato.de`, port `587`, *STARTTLS*.
2. **Save**, then send yourself a mail with **Send test email**.
3. Choose which actions send mails: offboarding, password reset, user management, deletion. The onboarding mail is always sent as soon as SMTP is enabled.

Mails go to the **signed-in person**, optionally also to CC recipients. Onboarding and password mails contain the new password.

Notes:

- *Auto* uses STARTTLS. If the server offers no encryption, nothing is sent. Choose *Without encryption* only for an internal relay; an SMTP password is then never sent.
- If the server or user name changes, the password must be entered again.
- If the test fails, check the server name and port and that the network or firewall allows the connection to the mail server.

---

## 13. Reports

Open **Reports** (administrators only). Two areas:

| Area | Content | Deleted after |
|---|---|---|
| **Changes** | Who did what and when, with result and details | 365 days |
| **Log** | Program messages (warnings, errors, connection problems) | 90 days |

- **Search** and **filter** (successful/failed or warnings/errors); **Load more** shows older entries.
- **Delete manually:** at the bottom choose "older than 30/90/180 days" or "all" and confirm with your own password. The deletion itself is recorded.
- Passwords never appear in the reports.

---

## 14. Certificate

Open **Certificate** (administrators only). The page shows the current certificate with names, issuer and expiry date.

- Upload a **PFX / P12** (with password, e.g. exported from the Windows certificate manager with the private key) or
- **Certificate + key** as PEM/DER files, optionally with intermediate certificates, or
- **Create** a new **self-signed** certificate with the right server names.

**Check and apply** verifies that certificate and key match and are valid. The new certificate applies **immediately**; reload the page afterwards. The old one is kept as a backup. A warning appears in the log 30 days before expiry.

---

## 15. Data protection

The **Data protection** link (bottom of the sign-in page and in the sidebar under *Help*) briefly shows what is stored and the current retention periods.

- No connections to the internet: interface, fonts and icons come from your own server.
- Only one strictly necessary cookie for signing in, no tracking.
- Your password is only held in memory during the session.
- **Subject access (Art. 15 GDPR):** administrators enter a user name there and **Download** everything the application has stored about that account (JSON). Review it before handing it out and redact information about other people.

Details for the record of processing activities are in `DATA-PROTECTION.en.md`.

---

## 16. Running the server

For administrators with access to the Docker host.

**Update from GitHub:** run `sudo sh update.sh --pull` in the project folder. The script fetches the ready-made image from GitHub, backs up `data/` first, restarts and puts the previous image back into service automatically if the start fails. If the image is private, log in once first: `sudo docker login ghcr.io -u soleil0815` (password: token with *read:packages*).

**With Dockhand or Portainer:** instead of building on the server, it can use the ready-made image `ghcr.io/soleil0815/samonboarding` that GitHub builds and tests for every new version (file `docker-compose.image.yml`, instructions in the README under *Alternative: ready-made image from GitHub*). Dockhand then fetches the updates; the automatic backup and return to the previous version of `update.sh` are not available that way.

**Update as a ZIP:** upload the ZIP of the new version to the project folder (e.g. `/opt/samonboarding`) and run there:

```bash
sudo sh update.sh samonboarding-*.zip
```

The script shows the installed and the new version and what changes, asks once (type `y`) and then does everything: backup of the program and `data/`, swapping files, removing old files, build, start, check. An internet block installed by an older version is removed automatically afterwards. Finally the ZIP, temporary files and old images are removed. If the new version does not start, the previous one comes back. `.env`, `data/` and `backups/` are never touched. All users are signed out afterwards.

Without a new version, just rebuild and start: `sudo sh update.sh`.

**Settings** such as domain, DC, port and retention periods are in the `.env` file. After a change run `sudo sh update.sh`.

**Backup:** the `data/` folder and the `.env` file. Everything the application stores permanently is there.

**View the container output:**

```bash
docker compose logs -f
```

---

## 17. Common questions and errors

The application's messages come from the server; in the English interface they are translated where a translation exists.

| Message / question | What to do |
|---|---|
| List is empty | No source OUs have been released for the module yet, or the account is outside them. Ask an administrator |
| An account just created in AD is missing from the list | The lists are kept for up to 60 seconds. Click **Refresh accounts** |
| Yellow notice *Settings refer to changed OUs or groups* | An OU or group was renamed, moved or deleted in AD. See [Initial setup](#10-initial-setup-administrators) |
| *Access denied: you must be a member …* | You are neither operator nor administrator. Have the group membership checked, then sign in again |
| *LDAP sign-in failed* | Wrong user name or password, account locked or disabled |
| *Too many failed sign-ins* | Wait a few minutes |
| *Domain controller … not reachable* | DC down, network or firewall. Inform an administrator |
| *Setting the password failed* | The password does not meet the policy, or you lack rights on the OU |
| *insufficientAccessRights* | You lack rights on this OU in AD (delegation) |
| *This account is protected* | Member of a privileged group. Intended protection |
| *You were signed out because nothing happened for 30 minutes* | Intended. Sign in again. After a restart of the application (e.g. an update) you also need to sign in again |
| Mail does not arrive | Is SMTP enabled? Use **Send test email** in E-mail notification and read the message |
| *Mailbox could not be created* | The account has been created. Read the message (sign-in, reachability, certificate) and create the mailbox in Exchange |
| Delete: *something has changed since the simulation* | Nothing was deleted. Run the simulation again |
| Delete: *file is in use* | User still signed in or virus scanner. Simulate again later |
| Delete: *no access* | You lack rights on the folder on the file server. Check the rights or enable *take ownership* |
| Times in the reports are wrong | Set `TZ` in `.env` (e.g. `Europe/Berlin`) and run `sudo sh update.sh` |
