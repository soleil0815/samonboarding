"""GitHub workflows: schedule, order of steps, permissions, Trivy without an action, never overwrite."""

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
    def test_only_the_two_workflows(self):
        self.assertEqual(sorted(p.name for p in FLOWS.glob("*.y*ml")), ["build.yml", "checks.yml", "image.yml"])

    def test_actions_pinned_to_commit_hashes_and_no_trivy_action(self):
        for name in ("image.yml", "build.yml", "checks.yml"):
            flow = text(name)
            for line in flow.splitlines():
                if "uses: ./.github/workflows/build.yml" in line:
                    continue  # our own build steps (same repository, same commit)
                if "uses:" in line:
                    self.assertRegex(line, r"uses: [\w.-]+/[\w.-]+@[0-9a-f]{40}( |$)", line)
            self.assertNotIn("aquasecurity/", flow)  # trivy-action / setup-trivy (CVE-2026-33634)
            self.assertNotIn("setup-trivy", flow)
            self.assertNotIn("trivy-action", flow)

    def test_minimal_permissions_and_no_persisted_credentials(self):
        for name in ("image.yml", "checks.yml"):
            flow = text(name)
            self.assertIn("\npermissions: {}\n", flow)  # nothing at the top - each job gets only what it needs
            self.assertEqual(flow.count("actions/checkout@"), flow.count("persist-credentials: false"))
        checks = text("checks.yml")
        self.assertNotIn("write", checks)
        self.assertNotIn("packages:", checks)  # the published image is pulled without login
        image = text("image.yml")
        self.assertEqual(image.count("contents: write"), 1)
        self.assertEqual(image.count("packages: write"), 1)
        build = text("build.yml")
        self.assertEqual(build.count("actions/checkout@"), build.count("persist-credentials: false"))
        self.assertNotIn("permissions:", build)  # gets exactly the rights of the calling job

    def test_pull_requests_only_get_a_read_only_token(self):
        """Code from a pull request runs in the check job: it can neither commit nor publish."""
        image = text("image.yml")
        check = image[image.index("  check:\n") : image.index("  release:\n")]
        release = image[image.index("  release:\n") :]
        self.assertIn("if: github.event_name == 'pull_request' || github.event_name == 'push'", check)
        self.assertNotIn("write", check)
        self.assertIn("contents: read", check)
        self.assertIn("packages: read", check)
        self.assertIn("publish: false", check)
        self.assertIn("mode: check", check)
        self.assertIn("if: github.event_name == 'schedule' || github.event_name == 'workflow_dispatch'", release)
        self.assertIn("publish: ${{ github.ref == 'refs/heads/main' }}", release)
        self.assertEqual(image.count("uses: ./.github/workflows/build.yml"), 2)
        self.assertIn("  workflow_call:\n", text("build.yml"))

    def test_release_only_from_main_and_never_two_at_once(self):
        image = text("image.yml")
        flow = text("build.yml")
        self.assertTrue(
            "on:\n  pull_request:\n    branches: [main]\n  push:\n    branches: [main]\n" in image, "Ausloeser"
        )
        # publishes only if the caller allows it (release job on main): a merge alone publishes nothing
        self.assertTrue("PUBLISH: ${{ inputs.publish && 'true' || 'false' }}" in flow, "PUBLISH")
        for step in ("Commit the new pins", "Publish the image"):
            block = flow[step_index(flow, step) :][:400]
            self.assertIn("if: env.PUBLISH == 'true'", block, step)
        self.assertTrue(
            "group: ${{ github.event_name == 'pull_request' && format('image-pr-{0}', github.ref) || 'image-release' }}"
            in image,
            "Releases nie gleichzeitig",
        )
        self.assertIn("cancel-in-progress: false", image)
        self.assertEqual(flow.count("--push"), 1)
        self.assertEqual(flow.count("docker login"), 1)

    def test_trivy_fixed_version_with_sha256(self):
        script = (ROOT / "scripts" / "install-trivy.sh").read_text(encoding="utf-8")
        version = re.search(r'^TRIVY_VERSION="(\d+\.\d+\.\d+)"$', script, re.M).group(1)
        self.assertNotEqual(version, "0.69.4")  # the malicious version from March 2026
        self.assertRegex(script, r'(?m)^TRIVY_SHA256="[0-9a-f]{64}"')
        self.assertIn('if [ "$actual" != "$TRIVY_SHA256" ]', script)
        self.assertIn('if [ "$official" != "$TRIVY_SHA256" ]', script)  # and listed like this in the official list
        self.assertIn("--proto '=https'", script)
        self.assertNotIn("latest", script)
        for name in ("build.yml", "checks.yml"):
            self.assertIn("sh scripts/install-trivy.sh", text(name))


class ScheduleTests(unittest.TestCase):
    def test_schedules(self):
        image = text("image.yml")
        self.assertIn('    - cron: "17 5 * * 1"', image)  # early Monday: security update
        self.assertIn("workflow_dispatch:", image)  # also manually
        self.assertIn("options: [security-update, release]", image)
        checks = text("checks.yml")
        self.assertIn('    - cron: "43 3 * * *"', checks)  # daily: scan of the published image
        self.assertIn('    - cron: "29 6 * * 1"', checks)  # weekly: base support
        self.assertIn("github.event.schedule == '43 3 * * *'", checks)
        self.assertIn("github.event.schedule == '29 6 * * 1'", checks)
        self.assertIn("python3 scripts/pins.py eol", checks)
        scan = checks[checks.index("scan-published:") : checks.index("base-support:")]
        self.assertIn(":latest", scan)
        self.assertNotIn("docker login", scan)  # pulled like any user: also proves every day that the image is public
        self.assertIn('export DOCKER_CONFIG="$RUNNER_TEMP/no-login"', scan)
        self.assertIn("::error title=Image not public::", scan)
        self.assertIn("pins.py scan published:amd64", scan)
        self.assertIn("pins.py scan published:arm64", scan)

    def test_mode_per_trigger(self):
        image = text("image.yml")
        flow = text("build.yml")
        self.assertIn(
            "mode: ${{ github.event_name == 'workflow_dispatch' && inputs.mode || 'security-update' }}", image
        )
        self.assertTrue("MODE: ${{ inputs.mode }}" in flow, "MODE")
        plan = flow[step_index(flow, "Plan") :][:500]
        self.assertTrue('if [ "$mode" = check ]; then mode=release; fi' in plan, "Pruefung plant wie ein Release")

    def test_release_page_with_assets_and_tag_x_y(self):
        flow = text("build.yml")
        release = flow[step_index(flow, "GitHub release (only main)") :]
        for needed in ('cp docker-compose.yml "$assets/docker-compose.yml"', 'cp .env.example "$assets/env.example"',
                       'docker save "$IMAGE:$TAG" | gzip -6 > "$assets/samonboarding-$TAG-$arch.tar.gz"',
                       '--latest="$latest" "$assets"/*'):  # fmt: skip
            self.assertTrue(needed in release, needed)
        publish = flow[step_index(flow, "Publish the image") : step_index(flow, "GitHub release (only main)")]
        self.assertTrue('if [ "$MINOR_LATEST" = true ]; then tags="$tags --tag $IMAGE:$MINOR"; fi' in publish, "X.Y")
        smoke = flow[step_index(flow, "Start check of the server") : step_index(flow, "Vulnerability scan (Trivy")]
        for arch in ("amd64", "arm64"):  # also started as with docker-compose.yml (as root, then 10001)
            self.assertTrue(f"smoke samonboarding:test-{arch} --as-root" in smoke, arch)


class OrderTests(unittest.TestCase):
    def test_order_of_steps(self):
        flow = text("build.yml")
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

    def test_built_without_cache_and_same_layers_published(self):
        flow = text("build.yml")
        probe = flow[step_index(flow, "Build without cache") : step_index(flow, "Debian packages")]
        self.assertIn("--no-cache --pull", probe)
        for name in ("Build $arch", "Final build $arch", "Publish"):  # failure cause readable in the run
            self.assertIn(f'python3 scripts/pins.py run "{name}" -- docker buildx build', flow)
        self.assertIn("--cache-to", probe)
        self.assertNotIn("type=gha", flow)  # no cache from earlier runs
        final = flow[step_index(flow, "Build the final image") : step_index(flow, "Tests in the image")]
        publish = flow[step_index(flow, "Publish the image") :]
        for block in (final, publish):
            self.assertIn("--cache-from", block)
            self.assertIn('--label "org.opencontainers.image.version=$TAG"', block)

    def test_conditions(self):
        flow = text("build.yml")
        self.assertIn("if: env.MODE == 'security-update'\n        run: python3 scripts/pins.py update", flow)
        for step in ("Tests in the image", "Start check of the server", "Vulnerability scan (Trivy"):
            block = flow[step_index(flow, step) :][:200]
            self.assertIn("if: steps.plan.outputs.action != 'nothing'", block, step)  # nothing changed: do nothing
        publish = flow[step_index(flow, "Publish the image") :][:300]
        self.assertIn("steps.plan.outputs.action == 'publish'", publish)
        self.assertIn('if [ "$LATEST" = true ]; then tags="$tags --tag $IMAGE:latest"; fi', flow)
        commit = flow[step_index(flow, "Commit the new pins") :][:300]
        self.assertIn("steps.plan.outputs.commit == 'true'", commit)

    def test_github_release(self):
        """One release page v<version> per published version with the changelog entry - never changed."""
        flow = text("build.yml")
        block = flow[step_index(flow, "GitHub release (only main)") :]
        self.assertIn("if: env.PUBLISH == 'true'", block[:200])
        self.assertLess(block.index('gh release view "v$TAG"'), block.index('gh release create "v$TAG"'))
        self.assertIn("left unchanged", block)
        self.assertIn('--notes-file "$RUNNER_TEMP/notes.md" --latest="$latest"', block)
        self.assertIn('grep -qx "$TAG"', block)  # no release without a published image
        self.assertEqual(flow.count("gh release create"), 1)

    def test_logout_after_publishing(self):
        flow = text("build.yml")
        self.assertLess(flow.index("docker login"), flow.index("--push"))
        self.assertLess(flow.index("--push"), flow.index("docker logout ghcr.io"))
        self.assertLess(step_index(flow, "Vulnerability scan (Trivy"), flow.index("docker login"))


class ImageContentTests(unittest.TestCase):
    def test_unneeded_parts_removed(self):
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        final = docker[docker.index("FROM ${PYTHON_IMAGE}") :]
        self.assertIn("python -m pip uninstall -y pip", final)  # package manager pip not in the final image
        self.assertIn("pip uninstall -y setuptools wheel", final)
        self.assertIn("ensurepip/_bundled", final)
        self.assertNotIn("npm", final.replace("COPY --from=assets", ""))  # Node/npm only in the build stage
        self.assertIn("scripts/", (ROOT / ".dockerignore").read_text(encoding="utf-8").split())

    def test_package_manager_perl_and_setuid_removed(self):
        """apt, Perl and the setuid bits are removed after the build; dpkg stays so Trivy can check the packages."""
        docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        final = docker[docker.index("FROM ${PYTHON_IMAGE}") :]
        block = final[final.index("purge() {") : final.index("USER ${APP_UID}")]
        self.assertLess(final.index("apt-get $apt_opts full-upgrade"), final.index("purge() {"))  # used first
        self.assertLess(final.index("useradd"), final.index("purge() {"))
        for package in ("apt libapt-pkg7.0 sqv debian-archive-keyring", "adduser", "debconf", "perl-base"):
            self.assertIn(f"purge {package};", block)
        self.assertIn("find / -xdev -type f -perm /6000 -exec chmod ug-s {} +", block)
        self.assertIn('test -z "$(find / -xdev -type f -perm /6000)"', block)
        self.assertIn("command -v dpkg-query", block)  # the package list stays readable for Trivy
        self.assertNotIn("purge dpkg", block)
        lock = (ROOT / "os-packages.lock").read_text(encoding="utf-8")
        for package in ("apt", "libapt-pkg7.0", "sqv", "debian-archive-keyring", "adduser", "debconf", "perl-base"):
            self.assertNotRegex(lock, rf"(?m)^(amd64|arm64) {re.escape(package)}=", package)
        self.assertRegex(lock, r"(?m)^amd64 dpkg=")

    @unittest.skipUnless(Path("/app/static").is_dir(), "only in the image")
    def test_inside_the_image(self):
        import shutil
        import subprocess

        for gone in ("apt", "apt-get", "perl", "adduser", "dpkg-reconfigure"):
            self.assertIsNone(shutil.which(gone), gone)
        self.assertIsNotNone(shutil.which("dpkg-query"))
        self.assertIsNotNone(shutil.which("setpriv"))
        found = subprocess.run(
            ["find", "/usr", "/etc", "/opt", "-xdev", "-type", "f", "-perm", "/6000"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.split()
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
