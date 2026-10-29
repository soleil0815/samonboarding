"""Workflows auf GitHub: Zeitplan, Reihenfolge der Schritte, Rechte, Trivy ohne Action, nie ueberschreiben."""

import re
import unittest
from pathlib import Path

import _paths

ROOT = Path(_paths.ROOT)
FLOWS = ROOT / ".github" / "workflows"


def text(name):
    return (FLOWS / name).read_text(encoding="utf-8")


def step_index(flow, name):
    index = flow.find(f"- name: {name}")
    if index < 0:
        raise AssertionError(f"step missing: {name}")
    return index


class WorkflowSecurityTests(unittest.TestCase):
    def test_nur_die_beiden_workflows(self):
        self.assertEqual(sorted(p.name for p in FLOWS.glob("*.y*ml")), ["checks.yml", "image.yml"])

    def test_actions_auf_commit_pruefsummen_und_kein_trivy_action(self):
        for name in ("image.yml", "checks.yml"):
            flow = text(name)
            for line in flow.splitlines():
                if "uses:" in line:
                    self.assertRegex(line, r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40}( |$)", line)
            self.assertNotIn("aquasecurity/", flow)  # trivy-action / setup-trivy (CVE-2026-33634)
            self.assertNotIn("setup-trivy", flow)
            self.assertNotIn("trivy-action", flow)

    def test_minimale_rechte_und_keine_gespeicherten_zugangsdaten(self):
        for name in ("image.yml", "checks.yml"):
            flow = text(name)
            self.assertIn("\npermissions: {}\n", flow)  # oben nichts - jeder Job nur, was er braucht
            self.assertEqual(flow.count("actions/checkout@"), flow.count("persist-credentials: false"))
        checks = text("checks.yml")
        self.assertNotIn("write", checks)
        self.assertEqual(checks.count("packages: read"), 1)
        image = text("image.yml")
        self.assertEqual(image.count("contents: write"), 1)
        self.assertEqual(image.count("packages: write"), 1)

    def test_release_nur_vom_hauptzweig_und_nie_zwei_gleichzeitig(self):
        flow = text("image.yml")
        self.assertTrue(
            "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\n" in flow, "Ausloeser"
        )
        # veroeffentlicht nur von main, nie bei Push oder Pull Request: ein Merge allein veroeffentlicht nichts
        publish = (
            "PUBLISH: ${{ github.ref == 'refs/heads/main' && github.event_name != 'push' "
            "&& github.event_name != 'pull_request' && 'true' || 'false' }}"
        )
        self.assertTrue(publish in flow, "PUBLISH")
        for step in ("Commit the new pins", "Publish the image"):
            block = flow[step_index(flow, step) :][:400]
            self.assertIn("if: env.PUBLISH == 'true'", block, step)
        self.assertTrue(
            "group: ${{ github.event_name == 'pull_request' && format('image-pr-{0}', github.ref) || 'image-release' }}"
            in flow,
            "Releases nie gleichzeitig",
        )
        self.assertIn("cancel-in-progress: false", flow)
        self.assertEqual(flow.count("--push"), 1)
        self.assertEqual(flow.count("docker login"), 1)

    def test_trivy_feste_version_mit_sha256(self):
        script = (ROOT / "scripts" / "install-trivy.sh").read_text(encoding="utf-8")
        version = re.search(r'^TRIVY_VERSION="(\d+\.\d+\.\d+)"$', script, re.M).group(1)
        self.assertNotEqual(version, "0.69.4")  # die boesartige Version vom Maerz 2026
        self.assertRegex(script, r'(?m)^TRIVY_SHA256="[0-9a-f]{64}"')
        self.assertIn('if [ "$actual" != "$TRIVY_SHA256" ]', script)
        self.assertIn('if [ "$official" != "$TRIVY_SHA256" ]', script)  # und so in der offiziellen Liste
        self.assertIn("--proto '=https'", script)
        self.assertNotIn("latest", script)
        for name in ("image.yml", "checks.yml"):
            self.assertIn("sh scripts/install-trivy.sh", text(name))


class ScheduleTests(unittest.TestCase):
    def test_zeitplaene(self):
        image = text("image.yml")
        self.assertIn('    - cron: "17 5 * * 1"', image)  # montags frueh: Sicherheitsupdate
        self.assertIn("workflow_dispatch:", image)  # auch von Hand
        self.assertIn("options: [security-update, release]", image)
        checks = text("checks.yml")
        self.assertIn('    - cron: "43 3 * * *"', checks)  # taeglich: Scan des veroeffentlichten Images
        self.assertIn('    - cron: "29 6 * * 1"', checks)  # woechentlich: Unterbau
        self.assertIn("github.event.schedule == '43 3 * * *'", checks)
        self.assertIn("github.event.schedule == '29 6 * * 1'", checks)
        self.assertIn("python3 scripts/pins.py eol", checks)
        scan = checks[checks.index("scan-published:") : checks.index("base-support:")]
        self.assertIn(":latest", scan)
        self.assertIn("pins.py scan published:amd64", scan)
        self.assertIn("pins.py scan published:arm64", scan)

    def test_modus_je_ausloeser(self):
        flow = text("image.yml")
        mode = (
            "MODE: ${{ (github.event_name == 'push' || github.event_name == 'pull_request') && 'check' || "
            "(github.event_name == 'workflow_dispatch' && inputs.mode) || 'security-update' }}"
        )
        self.assertTrue(mode in flow, "MODE")
        plan = flow[step_index(flow, "Plan") :][:500]
        self.assertTrue('if [ "$mode" = check ]; then mode=release; fi' in plan, "Pruefung plant wie ein Release")

    def test_release_seite_mit_anhaengen_und_tag_x_y(self):
        flow = text("image.yml")
        release = flow[step_index(flow, "GitHub release (only main)") :]
        for needed in ('cp docker-compose.yml "$assets/docker-compose.yml"', 'cp .env.example "$assets/env.example"',
                       'docker save "$IMAGE:$TAG" | gzip -6 > "$assets/samonboarding-$TAG-$arch.tar.gz"',
                       '--latest="$latest" "$assets"/*'):  # fmt: skip
            self.assertTrue(needed in release, needed)
        publish = flow[step_index(flow, "Publish the image") : step_index(flow, "GitHub release (only main)")]
        self.assertTrue('if [ "$MINOR_LATEST" = true ]; then tags="$tags --tag $IMAGE:$MINOR"; fi' in publish, "X.Y")
        smoke = flow[step_index(flow, "Start check of the server") : step_index(flow, "Vulnerability scan (Trivy")]
        for arch in ("amd64", "arm64"):  # auch so gestartet wie mit der docker-compose.yml (als root, dann 10001)
            self.assertTrue(f"smoke samonboarding:test-{arch} --as-root" in smoke, arch)


class OrderTests(unittest.TestCase):
    def test_reihenfolge_der_schritte(self):
        flow = text("image.yml")
        order = [
            "Install Trivy",
            "Check code",
            "Renew pins within the base",
            "Build without cache",
            "Debian packages",
            "Changes and version limits",
            "Plan",
            "Changelog entry",
            "Build the final image",
            "Tests in the image",
            "Start check of the server",
            "Vulnerability scan (Trivy",
            "Dry run",
            "Commit the new pins",
            "Publish the image",
            "GitHub release (only main)",
        ]
        positions = [step_index(flow, name) for name in order]
        self.assertEqual(positions, sorted(positions))

    def test_ohne_zwischenspeicher_gebaut_und_gleiche_schichten_veroeffentlicht(self):
        flow = text("image.yml")
        probe = flow[step_index(flow, "Build without cache") : step_index(flow, "Debian packages")]
        self.assertIn("--no-cache --pull", probe)
        for name in ("Build $arch", "Final build $arch", "Publish"):  # Fehlerursache lesbar am Lauf
            self.assertIn(f'python3 scripts/pins.py run "{name}" -- docker buildx build', flow)
        self.assertIn("--cache-to", probe)
        self.assertNotIn("type=gha", flow)  # kein Zwischenspeicher aus frueheren Laeufen
        final = flow[step_index(flow, "Build the final image") : step_index(flow, "Tests in the image")]
        publish = flow[step_index(flow, "Publish the image") :]
        for block in (final, publish):
            self.assertIn("--cache-from", block)
            self.assertIn('--label "org.opencontainers.image.version=$TAG"', block)

    def test_bedingungen(self):
        flow = text("image.yml")
        self.assertIn("if: env.MODE == 'security-update'\n        run: python3 scripts/pins.py update", flow)
        for step in ("Tests in the image", "Start check of the server", "Vulnerability scan (Trivy"):
            block = flow[step_index(flow, step) :][:200]
            self.assertIn("if: steps.plan.outputs.action != 'nothing'", block, step)  # nichts geaendert: nichts tun
        publish = flow[step_index(flow, "Publish the image") :][:300]
        self.assertIn("steps.plan.outputs.action == 'publish'", publish)
        self.assertIn('if [ "$LATEST" = true ]; then tags="$tags --tag $IMAGE:latest"; fi', flow)
        commit = flow[step_index(flow, "Commit the new pins") :][:300]
        self.assertIn("steps.plan.outputs.commit == 'true'", commit)

    def test_github_release(self):
        """Je veroeffentlichter Version eine Release-Seite v<Version> mit dem Changelog-Eintrag - nie geaendert."""
        flow = text("image.yml")
        block = flow[step_index(flow, "GitHub release (only main)") :]
        self.assertIn("if: env.PUBLISH == 'true'", block[:200])
        self.assertLess(block.index('gh release view "v$TAG"'), block.index('gh release create "v$TAG"'))
        self.assertIn("left unchanged", block)
        self.assertIn('--notes-file "$RUNNER_TEMP/notes.md" --latest="$latest"', block)
        self.assertIn('grep -qx "$TAG"', block)  # kein Release ohne veroeffentlichtes Image
        self.assertEqual(flow.count("gh release create"), 1)

    def test_nach_dem_veroeffentlichen_abmelden(self):
        flow = text("image.yml")
        self.assertLess(flow.index("docker login"), flow.index("--push"))
        self.assertLess(flow.index("--push"), flow.index("docker logout ghcr.io"))
        self.assertLess(step_index(flow, "Vulnerability scan (Trivy"), flow.index("docker login"))


class ImageContentTests(unittest.TestCase):
    def test_nicht_benoetigtes_entfernt(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        final = docker[docker.index("FROM ${PYTHON_IMAGE}") :]
        self.assertIn("python -m pip uninstall -y pip", final)  # Paketmanager pip nicht im fertigen Image
        self.assertIn("pip uninstall -y setuptools wheel", final)
        self.assertIn("ensurepip/_bundled", final)
        self.assertNotIn("npm", final.replace("COPY --from=assets", ""))  # Node/npm nur im Bau-Abschnitt
        self.assertIn("scripts/", (ROOT / ".dockerignore").read_text(encoding="utf-8").split())


if __name__ == "__main__":
    unittest.main()
