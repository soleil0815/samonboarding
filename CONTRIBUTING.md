# Contributing

*Deutsche Kurzfassung unten.*

Thanks for your interest in SAMONBOARDING. Please read this first – it saves time on both sides.

## Before you open anything

- **This is a spare-time project without support.** Questions and bug reports are read, but answered only as time allows. There are no fixed response times.
- **Security vulnerabilities: never in public.** Report them confidentially as described in [SECURITY.md](SECURITY.md) (*Security → Report a vulnerability*), not as an issue, discussion or pull request.
- **No real data.** Do not post passwords, tokens, real domain or server names, IP addresses, user names or log extracts from a production AD. Use neutral examples such as `firma.local`, `dc01.firma.local`, `10.0.10.5` or `PC-0001`.

## Bug reports

Use the issue form *Bug report*. Helpful are: the version (*Help → News* in the interface), Samba AD or Windows Server AD, how you run it (Docker Compose, container manager, NAS), steps to reproduce, what you expected and what happened instead.

## Pull requests

Small, focused pull requests are welcome. For larger changes please open an issue first and describe the idea, so nobody builds something that does not fit.

- **Language:** code, comments, commit messages and pull requests in English. Documentation is bilingual: `README.md` (English) / `README.de.md` (German), `CHANGELOG.md` / `CHANGELOG.de.md`. Interface texts are German with the English translation in `samonboarding/web/i18n.json`.
- **Tests:** every change comes with a test; every bug fix with a test that fails without the fix. Before you push, run:
  ```bash
  pip install -r requirements-dev.txt
  python3 -m unittest discover -s tests -p 'test_*.py'
  ruff check . && ruff format --check .
  pyright
  for f in tests/ui/*.test.js; do node "$f"; done
  ```
- **Principles that do not change:** the program never runs as root in the container; nothing is loaded from the internet by the interface; passwords are never stored or logged; deleting only happens after a simulation and a confirmation; shell scripts are POSIX `sh`.
- **No version bump and no release in your pull request.** Releases are done by the maintainer.
- The GitHub workflow checks every pull request (build, tests in the image, Trivy). It runs with a read-only token and cannot publish anything.

## Licence and sign-off (DCO)

SAMONBOARDING is licensed under **AGPL-3.0-or-later**. By contributing you agree that your contribution is published under this licence. Please confirm this with a `Signed-off-by` line in each commit ([Developer Certificate of Origin](https://developercertificate.org/)):

```bash
git commit -s -m "Fix …"
```

The copyright notice in the files stays `Die SAMONBOARDING-Autoren` (*The SAMONBOARDING authors*); please do not add personal names or e-mail addresses to the files.

---

## Deutsch (Kurzfassung)

- Freizeitprojekt **ohne Support**; Meldungen werden gelesen, beantwortet nach verfügbarer Zeit.
- **Sicherheitslücken nie öffentlich**, sondern vertraulich wie in [SECURITY.md](SECURITY.md) beschrieben.
- **Keine echten Daten** (Kennwörter, Server- und Domänennamen, IP-Adressen, Benutzernamen, Protokolle aus einem echten AD).
- Pull Requests: klein und mit Test; Code, Kommentare und Commits auf Englisch; alle Tests, ruff und pyright grün; keine Versionserhöhung.
- Mit einem Beitrag stimmst du der Veröffentlichung unter **AGPL-3.0-or-later** zu (`git commit -s`, DCO).
