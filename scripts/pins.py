#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Die SAMONBOARDING-Autoren
"""Exact versions for the build and the monthly security update (patch day) (Python standard library only).

What is pinned (all files in the repository):
  images.lock          base images with fixed version AND digest, plus the Debian snapshot (DEBIAN_SNAPSHOT) from which
                       the Debian packages of the image are installed - same snapshot = exactly the same packages
  os-packages.lock     resulting list of all Debian packages in the image (name=version), checked on every build
  requirements.txt     all Python packages including indirect ones (name==version)
  package.json / package-lock.json   npm packages for building the interface (not part of the finished image)

"update" renews these versions, but only WITHIN the base:
  - same series of the base images: Python 3.13.x stays 3.13, Node 24.x stays 24, Debian "trixie" stays "trixie"
  - every package within its major version, below 1.0 within its minor version (0.54.x stays 0.54)
  - calendar versions (e.g. certifi 2026.10.23, tzdata 2025.2) without a limit
Raising the base (new Debian, Python or Node series) is never done here - that is a deliberate, manual change.

Commands (the GitHub workflows use them, they can also be run by hand):
  update                 renew all pins within the limits (needs docker and internet)
  build-args             print the --build-arg options from images.lock
  os-lock IMAGE --arch A [--check]   write the packages of a built image into os-packages.lock (or compare)
  changes [--base REV] [--out FILE]   what changed compared with REV (git), checks the limits
  next-tag               next tag for a security update: <version>-s<counter>
  current-tag            tag of the current state (program version or last security update)
  changelog TAG FILE     add the changelog entry for a security update (changes from "changes --out")
  is-highest TAG [TAG ...]  exit code 0 if TAG is at least as high as all given tags
  registry-tags IMAGE    published tags of ghcr.io/<owner>/<name> (token: GITHUB_TOKEN)
  test-image IMAGE       run the automatic tests inside the image
  smoke IMAGE            start the server in the image and query it via HTTPS
  scan IMAGE [--auto-out F | --inherited-from REV | --report-only]
                         vulnerability scan with trivy (from PATH), stops on HIGH/CRITICAL with a fix - except
                         for a valid temporary exception (see trivyignore-auto)
  trivyignore-auto FILE...   update the automatic temporary exceptions in .trivyignore from scan --auto-out files
  plan --mode M --changed C --image I   decide: publish / skip / nothing, tag, :latest, commit
  bundle                 dry run: renewed pin files as notices on the run page
  release-notes TAG --image I [--out F]   text of the GitHub release (changelog entry DE/EN)
  run TITLE -- COMMAND   run a step; on failure show the decisive lines (network problems: one retry)
  trivyignore-check      every entry in .trivyignore needs a reason and an expiry date
  eol                    how long Debian, Python and Node still get security updates (endoflife.date)
"""

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
IMAGES_LOCK = "images.lock"
OS_LOCK = "os-packages.lock"
REQ_IN = "requirements.in"
REQ_TXT = "requirements.txt"
PKG_JSON = "package.json"
PKG_LOCK = "package-lock.json"
CHANGELOGS = {"de": "CHANGELOG.de.md", "en": "CHANGELOG.md"}
TRIVYIGNORE = ".trivyignore"

DEBIAN_RELEASES = {"bookworm": "12", "trixie": "13", "forky": "14", "duke": "15"}
PY_TAG_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?-slim-([a-z]+)$")  # 3.13.16-slim-trixie
NODE_TAG_RE = re.compile(r"^(\d+)(?:\.(\d+)\.(\d+))?-([a-z]+)-slim$")  # 24.21.0-trixie-slim
TAG_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-s(\d+))?$")  # 1.48.0 / 1.48.0-s2
VERSION_RE = re.compile(r"^(\d+)((?:\.\d+)*)")
CALENDAR_MAJOR = 1900  # versions like 2026.10.23 (certifi) or 2025.2 (tzdata) are calendar versions
EOL_ERROR_DAYS = 183  # half a year before the end: red run
EOL_WARN_DAYS = 365  # a year before the end: note
# Only if endoflife.date cannot be reached (then a note says so); source: endoflife.date, October 2026
EOL_FALLBACK = {("debian", "13"): "2028-08-09", ("python", "3.13"): "2029-10-31", ("nodejs", "24"): "2028-04-30"}


class PinError(Exception):
    """Readable error for the run page (no stack trace needed)."""


# ---------------------------------------------------------------------------------------------------------------------
# Output for GitHub: annotations on the run page and the summary
# ---------------------------------------------------------------------------------------------------------------------
def _escape(text):
    return str(text).replace("%", "%25").replace("\r", "").replace("\n", "%0A")


def annotate(level, title, message):
    """level: error | warning | notice. Without GitHub only a readable line."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level} title={_escape(title)}::{_escape(message)}")
    else:
        print(f"{level.upper()}: {title}: {message}")


def summary(markdown):
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(markdown.rstrip() + "\n\n")


def set_output(name, value):
    path = os.environ.get("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{name}={value}\n")


# ---------------------------------------------------------------------------------------------------------------------
# Versions and limits
# ---------------------------------------------------------------------------------------------------------------------
def version_parts(text):
    """'0.54.0' -> [0, 54, 0]; '2026.10.23' -> [2026, 10, 23]; not a version -> None."""
    match = VERSION_RE.match(str(text).strip())
    if not match:
        return None
    return [int(match.group(1))] + [int(p) for p in match.group(2).split(".") if p]


def is_calendar(text):
    parts = version_parts(text)
    return bool(parts) and parts[0] >= CALENDAR_MAJOR


def upper_bound(text):
    """Exclusive upper limit within the series: 2.9.1 -> 3; 0.54.0 -> 0.55; calendar version -> None (no limit)."""
    parts = version_parts(text)
    if parts is None:
        raise PinError(f"Unknown version format: {text}")
    if parts[0] >= CALENDAR_MAJOR:
        return None
    if parts[0] == 0:
        minor = parts[1] if len(parts) > 1 else 0
        return f"0.{minor + 1}"
    return str(parts[0] + 1)


def within_limit(old, new):
    """Is the step from old to new allowed (same major version, below 1.0 same minor version; calendar: any)?"""
    old_p, new_p = version_parts(old), version_parts(new)
    if old_p is None or new_p is None:
        return old == new
    if old_p[0] >= CALENDAR_MAJOR and new_p[0] >= CALENDAR_MAJOR:
        return True
    if old_p[0] != new_p[0]:
        return False
    if old_p[0] == 0:
        return (old_p + [0])[1] == (new_p + [0])[1]
    return True


def tag_key(tag):
    """'1.48.0-s2' -> (1, 48, 0, 2); '1.48.0' -> (1, 48, 0, 0); other tags (latest, sha) -> None."""
    match = TAG_RE.match(str(tag))
    if not match:
        return None
    return tuple(int(g or 0) for g in match.groups())


def is_highest(tag, others):
    key = tag_key(tag)
    if key is None:
        return False
    return all(key >= k for k in (tag_key(o) for o in others) if k is not None)


def python_series(tag):
    match = PY_TAG_RE.match(tag)
    if not match:
        raise PinError(f"Python image tag not understood: {tag} (expected e.g. 3.13.16-slim-trixie)")
    return (match.group(1), match.group(2), match.group(4))


def node_series(tag):
    match = NODE_TAG_RE.match(tag)
    if not match:
        raise PinError(f"Node image tag not understood: {tag} (expected e.g. 24.21.0-trixie-slim)")
    return (match.group(1), match.group(4))


# ---------------------------------------------------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------------------------------------------------
def read_text(name, root=None):
    path = Path(ROOT if root is None else root) / name
    return path.read_text(encoding="utf-8") if path.exists() else ""


def git_show(rev, name):
    """File content at a git revision ('' if it did not exist there)."""
    done = subprocess.run(["git", "show", f"{rev}:{name}"], cwd=ROOT, capture_output=True, text=True, check=False)
    return done.stdout if done.returncode == 0 else ""


def parse_keyvalue(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def split_image(ref):
    """'python:3.13.16-slim-trixie@sha256:ab..' -> ('python', '3.13.16-slim-trixie', 'sha256:ab..')."""
    name_tag, _, digest = ref.partition("@")
    name, _, tag = name_tag.rpartition(":")
    return name, tag, digest


def parse_requirements(text):
    """name==version lines -> {normalized name: (name as written, version)}."""
    out = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if "==" in line:
            name, version = line.split("==", 1)
            out[normalize(name)] = (name.strip(), version.strip())
    return out


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower().strip()


ARCHS = ("amd64", "arm64")


def parse_os_lock_archs(text):
    """os-packages.lock -> {arch: {package: version}}; lines: '<arch> <package>=<version>' ('all' without arch)."""
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        arch, _, entry = line.rpartition(" ")
        name, version = entry.split("=", 1)
        out.setdefault(arch or "all", {})[name] = version
    return out


def parse_os_lock(text):
    """{package: version} over all architectures; differs a version (e.g. arm64 rebuild '+b1'), both are named."""
    archs = parse_os_lock_archs(text)
    out = {}
    for name in sorted({n for packages in archs.values() for n in packages}):
        per_arch = {arch: packages[name] for arch, packages in sorted(archs.items()) if name in packages}
        values = set(per_arch.values())
        out[name] = values.pop() if len(values) == 1 else ", ".join(f"{a} {v}" for a, v in per_arch.items())
    return out


def parse_npm_lock(text):
    """package-lock.json -> {package name: version} for all packages (direct and indirect)."""
    if not text.strip():
        return {}
    data = json.loads(text)
    out = {}
    for path, info in (data.get("packages") or {}).items():
        if path and "version" in info:
            out[path.split("node_modules/")[-1]] = info["version"]
    return out


def requirements_header(req_in_text):
    digest = hashlib.sha256(req_in_text.encode("utf-8")).hexdigest()[:16]
    return (
        "# Exact lock list of all Python packages (including dependencies) for reproducible builds.\n"
        "# Renewed by scripts/pins.py within the limits (same major version, below 1.0 same minor version) and\n"
        "# checked with the test suite in the image. Do not edit by hand.\n"
        f"# requirements.in: {digest}\n"
    )


# ---------------------------------------------------------------------------------------------------------------------
# Network: Docker Hub (base images)
# ---------------------------------------------------------------------------------------------------------------------
def http_json(url, headers=None, method="GET", timeout=30):
    req = urllib.request.Request(url, headers=headers or {}, method=method)  # noqa: S310 - fixed https URLs
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URLs
        body = resp.read()
        return json.loads(body) if body else {}, dict(resp.headers)


def hub_tags(repo, name_filter):
    """All tags of library/<repo> on Docker Hub whose name contains name_filter."""
    url = f"https://hub.docker.com/v2/repositories/library/{repo}/tags?page_size=100&name={name_filter}"
    tags = []
    for _ in range(30):
        data, _headers = http_json(url)
        tags += [r["name"] for r in data.get("results", [])]
        url = data.get("next")
        if not url:
            break
    return tags


def registry_digest(repo, tag):
    """Digest of the multi-platform index of library/<repo>:<tag> (directly from the registry)."""
    token, _ = http_json(
        f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/{repo}:pull"
    )
    accept = ", ".join(
        [
            "application/vnd.oci.image.index.v1+json",
            "application/vnd.docker.distribution.manifest.list.v2+json",
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        ]
    )
    _, headers = http_json(
        f"https://registry-1.docker.io/v2/library/{repo}/manifests/{tag}",
        headers={"Authorization": f"Bearer {token['token']}", "Accept": accept},
        method="HEAD",
    )
    digest = {k.lower(): v for k, v in headers.items()}.get("docker-content-digest", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise PinError(f"No digest for {repo}:{tag}")
    return digest


def newest_python_tag(series, tags):
    major, minor, distro = series
    best, best_patch = None, -1
    for tag in tags:
        match = PY_TAG_RE.match(tag)
        if (
            match
            and match.group(3)
            and (match.group(1), match.group(2), match.group(4)) == (major, minor, distro)
            and int(match.group(3)) > best_patch
        ):
            best, best_patch = tag, int(match.group(3))
    if not best:
        raise PinError(f"No image python:{major}.{minor}.x-slim-{distro} found")
    return best


def newest_node_tag(series, tags):
    major, distro = series
    best, best_key = None, None
    for tag in tags:
        match = NODE_TAG_RE.match(tag)
        if match and match.group(2) and (match.group(1), match.group(4)) == (major, distro):
            key = (int(match.group(2)), int(match.group(3)))
            if best_key is None or key > best_key:
                best, best_key = tag, key
    if not best:
        raise PinError(f"No image node:{major}.x.y-{distro}-slim found")
    return best


# ---------------------------------------------------------------------------------------------------------------------
# update: renew all pins within the limits
# ---------------------------------------------------------------------------------------------------------------------
def docker(*args, stdin=None, check=True):
    done = subprocess.run(["docker", *args], input=stdin, capture_output=True, text=True, check=False)
    if check and done.returncode != 0:
        raise PinError(f"docker {' '.join(args[:2])} failed:\n{done.stderr.strip()[-3000:]}")
    return done


def python_constraints(old_requirements):
    """Limits for the new resolution: every package from the current lock list stays in its series."""
    lines = []
    for name, version in parse_requirements(old_requirements).values():
        bound = upper_bound(version)
        lines.append(f"{name}>={version}" + (f",<{bound}" if bound else ""))
    return "\n".join(lines) + "\n"


def resolve_python(py_image, req_in, constraints):
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "requirements.in").write_text(req_in, encoding="utf-8")
        Path(tmp, "constraints.txt").write_text(constraints, encoding="utf-8")
        done = docker(
            "run",
            "--rm",
            "-v",
            f"{tmp}:/w:ro",
            "-e",
            "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "--entrypoint",
            "sh",
            py_image,
            "-ec",
            # gssapi and krb5 have no Linux wheels: compiler and Kerberos headers only for this resolution
            "apt-get update -qq >&2 && DEBIAN_FRONTEND=noninteractive apt-get install -qq -y --no-install-recommends "
            "gcc libc6-dev libkrb5-dev >&2; "
            "python -m venv /tmp/v >/dev/null; "
            "/tmp/v/bin/pip install --quiet --no-cache-dir -r /w/requirements.in -c /w/constraints.txt >&2; "
            "/tmp/v/bin/pip check >&2; /tmp/v/bin/pip freeze --all --exclude pip --exclude setuptools --exclude wheel",
        )
    pins = [line.strip() for line in done.stdout.splitlines() if "==" in line]
    if len(pins) < 5:
        raise PinError("The Python resolution returned no usable list:\n" + done.stdout[-2000:])
    return sorted(pins, key=str.lower)


def npm_range(version):
    """Range for the update: 3.4.17 -> ^3.4.17 (same major version), 0.3.2 -> ~0.3.2 (same minor version)."""
    parts = version_parts(version)
    if parts is None:
        raise PinError(f"npm version not understood: {version}")
    if parts[0] >= CALENDAR_MAJOR:
        return f">={version}"
    return f"~{version}" if parts[0] == 0 else f"^{version}"


def resolve_npm(node_image, package_json, package_lock):
    pkg = json.loads(package_json)
    ranged = dict(pkg)
    ranged["dependencies"] = {name: npm_range(v) for name, v in (pkg.get("dependencies") or {}).items()}
    with tempfile.TemporaryDirectory() as tmp:
        Path(tmp, "package.ranged.json").write_text(json.dumps(ranged, indent=2) + "\n", encoding="utf-8")
        if package_lock.strip():
            Path(tmp, "package-lock.json").write_text(package_lock, encoding="utf-8")
        script = (
            "mkdir -p /tmp/p && cd /tmp/p && cp /w/package.ranged.json package.json && "
            "if [ -f /w/package-lock.json ]; then cp /w/package-lock.json .; fi && "
            "npm update --package-lock-only --ignore-scripts --no-audit --no-fund >&2 && "
            "npm install --package-lock-only --ignore-scripts --no-audit --no-fund >&2 && "
            'node -e \'const l=require("/tmp/p/package-lock.json");const p=require("/tmp/p/package.json");'
            'for (const n of Object.keys(p.dependencies)) p.dependencies[n]=l.packages["node_modules/"+n].version;'
            'require("fs").writeFileSync("/tmp/p/package.json", JSON.stringify(p,null,2)+"\\n");\' && '
            "npm install --package-lock-only --ignore-scripts --no-audit --no-fund >&2 && "
            "cat package.json && echo '---8<---' && cat package-lock.json"
        )
        done = docker("run", "--rm", "-v", f"{tmp}:/w:ro", "--entrypoint", "sh", node_image, "-ec", script)
    new_pkg, _, new_lock = done.stdout.partition("---8<---\n")
    json.loads(new_pkg)  # both must be valid JSON
    json.loads(new_lock)
    return new_pkg, new_lock


def snapshot_now():
    """Debian snapshot (snapshot.debian.org): the archive as of this time; the build always gets exactly that state."""
    now = dt.datetime.now(dt.timezone.utc).replace(minute=0, second=0, microsecond=0) - dt.timedelta(hours=1)
    return now.strftime("%Y%m%dT%H%M%SZ")


def images_lock_text(python_ref, node_ref, snapshot):
    py_major, py_minor, distro = python_series(split_image(python_ref)[1])
    node_major, _ = node_series(split_image(node_ref)[1])
    return (
        "# Base of the build - exact versions with digest. Renewed by scripts/pins.py (weekly on GitHub), but only\n"
        f"# within the base: Python {py_major}.{py_minor}, Node {node_major}, "
        f'Debian {DEBIAN_RELEASES.get(distro, "?")} "{distro}". Raising the base is a deliberate, manual change.\n'
        "# DEBIAN_SNAPSHOT: Debian packages from snapshot.debian.org as of this time (same time = same packages).\n"
        f"PYTHON_IMAGE={python_ref}\n"
        f"NODE_IMAGE={node_ref}\n"
        f"DEBIAN_SNAPSHOT={snapshot}\n"
    )


def cmd_update(_args):
    lock = parse_keyvalue(read_text(IMAGES_LOCK))
    py_name, py_tag, _ = split_image(lock.get("PYTHON_IMAGE", ""))
    node_name, node_tag, _ = split_image(lock.get("NODE_IMAGE", ""))
    py_ser, node_ser = python_series(py_tag), node_series(node_tag)
    if py_ser[2] != node_ser[1]:
        raise PinError(f"Python ({py_ser[2]}) and Node ({node_ser[1]}) must use the same Debian release")

    new_py_tag = newest_python_tag(py_ser, hub_tags(py_name, f"{py_ser[0]}.{py_ser[1]}."))
    new_node_tag = newest_node_tag(node_ser, hub_tags(node_name, f"{node_ser[0]}."))
    python_ref = f"{py_name}:{new_py_tag}@{registry_digest(py_name, new_py_tag)}"
    node_ref = f"{node_name}:{new_node_tag}@{registry_digest(node_name, new_node_tag)}"
    print(f"Python image: {python_ref}\nNode image:   {node_ref}")

    req_in = read_text(REQ_IN)
    pins = resolve_python(python_ref, req_in, python_constraints(read_text(REQ_TXT)))
    new_pkg, new_lock = resolve_npm(node_ref, read_text(PKG_JSON), read_text(PKG_LOCK))

    (ROOT / IMAGES_LOCK).write_text(images_lock_text(python_ref, node_ref, snapshot_now()), encoding="utf-8")
    (ROOT / REQ_TXT).write_text(requirements_header(req_in) + "\n".join(pins) + "\n", encoding="utf-8")
    (ROOT / PKG_JSON).write_text(new_pkg if new_pkg.endswith("\n") else new_pkg + "\n", encoding="utf-8")
    (ROOT / PKG_LOCK).write_text(new_lock if new_lock.endswith("\n") else new_lock + "\n", encoding="utf-8")
    print("Pins renewed. Next: build the image, then 'os-lock IMAGE' and 'changes'.")


def cmd_build_args(_args):
    lock = parse_keyvalue(read_text(IMAGES_LOCK))
    for key in ("PYTHON_IMAGE", "NODE_IMAGE", "DEBIAN_SNAPSHOT"):
        if not lock.get(key):
            raise PinError(f"{IMAGES_LOCK}: {key} is missing")
        print(f"--build-arg={key}={lock[key]}")


# ---------------------------------------------------------------------------------------------------------------------
# os-lock: Debian packages of the built image
# ---------------------------------------------------------------------------------------------------------------------
def image_os_packages(image):
    done = docker("run", "--rm", "--entrypoint", "dpkg-query", image, "-W", "-f", "${Package}=${Version}\\n")
    return sorted(line for line in done.stdout.splitlines() if "=" in line)


def os_lock_text(archs, snapshot):
    lines = [f"{arch} {name}={version}" for arch in sorted(archs) for name, version in sorted(archs[arch].items())]
    return (
        "# All Debian packages in the finished image per architecture (<arch> name=version), from the Debian\n"
        f"# snapshot in images.lock ({snapshot}). Written by scripts/pins.py os-lock; every build is compared.\n"
        "# Debian sometimes rebuilds a package for one architecture only (version with '+b1').\n"
        + "\n".join(lines)
        + "\n"
    )


def cmd_os_lock(args):
    if args.arch not in ARCHS:
        raise PinError(f"Unknown architecture: {args.arch}")
    have = dict(line.split("=", 1) for line in image_os_packages(args.image))
    archs = parse_os_lock_archs(read_text(OS_LOCK))
    if args.check:
        want = archs.get(args.arch, {})
        if want != have:
            diff = [
                f"{n}: {want.get(n, '-')} -> {have.get(n, '-')}"
                for n in sorted(set(want) | set(have))
                if want.get(n) != have.get(n)
            ]
            raise PinError(
                f"Debian packages in the image ({args.arch}) do not match os-packages.lock (not reproducible):\n"
                + "\n".join(diff[:40])
            )
        print(f"Debian packages ({args.arch}) match {OS_LOCK} ({len(have)} packages).")
        return
    archs.pop("all", None)
    archs[args.arch] = have
    snapshot = parse_keyvalue(read_text(IMAGES_LOCK)).get("DEBIAN_SNAPSHOT", "?")
    (ROOT / OS_LOCK).write_text(os_lock_text(archs, snapshot), encoding="utf-8")
    print(f"{OS_LOCK} written for {args.arch} ({len(have)} packages).")


def cmd_os_lock_merge(args):
    """Security update: each platform pins its Debian packages on its own runner (os-lock, then only its own lines
    handed over); here the parts become os-packages.lock again - every architecture exactly once."""
    archs = {}
    for name in args.parts:
        for arch, packages in parse_os_lock_archs(Path(name).read_text(encoding="utf-8")).items():
            if arch not in ARCHS:
                raise PinError(f"{name}: unknown architecture {arch!r}")
            if arch in archs:
                raise PinError(f"{name}: {arch} is in more than one part")
            archs[arch] = packages
    missing = [arch for arch in ARCHS if not archs.get(arch)]
    if missing:
        raise PinError(f"Debian packages missing for: {', '.join(missing)}")
    snapshot = parse_keyvalue(read_text(IMAGES_LOCK)).get("DEBIAN_SNAPSHOT", "?")
    (ROOT / OS_LOCK).write_text(os_lock_text(archs, snapshot), encoding="utf-8")
    print(f"{OS_LOCK} written from {len(args.parts)} parts ({', '.join(sorted(archs))}).")


# ---------------------------------------------------------------------------------------------------------------------
# changes: what is different compared with a git revision, and are the limits kept?
# ---------------------------------------------------------------------------------------------------------------------
def diff_versions(old, new):
    changed, added, removed = [], [], []
    for name in sorted(set(old) | set(new), key=str.lower):
        if name in old and name in new and old[name] != new[name]:
            changed.append((name, old[name], new[name]))
        elif name in new and name not in old:
            added.append((name, new[name]))
        elif name in old and name not in new:
            removed.append((name, old[name]))
    return changed, added, removed


def compare(old_files, new_files):
    """old_files/new_files: {file name: text}. Returns (changes, violations).
    changes: {"images": [...], "debian": {...}, "python": {...}, "npm": {...}} with (name, old, new) entries."""
    violations = []
    changes = {}

    old_lock, new_lock = parse_keyvalue(old_files.get(IMAGES_LOCK, "")), parse_keyvalue(new_files.get(IMAGES_LOCK, ""))
    images = []
    for key, label, series in (("PYTHON_IMAGE", "Python", python_series), ("NODE_IMAGE", "Node", node_series)):
        old_ref, new_ref = old_lock.get(key, ""), new_lock.get(key, "")
        if not new_ref or "@sha256:" not in new_ref:
            violations.append(f"{label} image without digest in images.lock: {new_ref or '-'}")
            continue
        if old_ref and series(split_image(old_ref)[1]) != series(split_image(new_ref)[1]):
            before, after = split_image(old_ref)[1], split_image(new_ref)[1]
            violations.append(f"{label} image leaves its series: {before} -> {after}")
        if old_ref != new_ref:
            images.append((f"{label} ({split_image(new_ref)[0]})", short_image(old_ref), short_image(new_ref)))
    changes["images"] = images

    for key, parse in (
        ("debian", parse_os_lock),
        ("python", lambda t: {v[0]: v[1] for v in parse_requirements(t).values()}),
        ("npm", parse_npm_lock),
    ):
        name = {"debian": OS_LOCK, "python": REQ_TXT, "npm": PKG_LOCK}[key]
        old, new = parse(old_files.get(name, "")), parse(new_files.get(name, ""))
        changed, added, removed = diff_versions(old, new)
        if key != "debian":  # Debian packages come from the fixed release (snapshot of the same suites)
            for pkg, before, after in changed:
                if not within_limit(before, after):
                    violations.append(f"{key}: {pkg} {before} -> {after} leaves its series")
        changes[key] = {"changed": changed, "added": added, "removed": removed}
    return changes, violations


def short_image(ref):
    if not ref:
        return "-"
    _, tag, digest = split_image(ref)
    return f"{tag}@{digest[7:19]}" if digest else tag


def has_changes(changes):
    if changes.get("images"):
        return True
    return any(changes[k][part] for k in ("debian", "python", "npm") for part in ("changed", "added", "removed"))


CURRENT_FILES = (IMAGES_LOCK, OS_LOCK, REQ_TXT, PKG_LOCK)


def cmd_changes(args):
    old = {name: git_show(args.base, name) for name in CURRENT_FILES}
    new = {name: read_text(name) for name in CURRENT_FILES}
    changes, violations = compare(old, new)
    changed = has_changes(changes)
    if args.out:
        Path(args.out).write_text(json.dumps(changes, indent=1), encoding="utf-8")
    set_output("changed", "true" if changed else "false")
    md = changes_markdown(changes, "en")
    summary("### Changes compared with the repository\n\n" + (md or "No changes."))
    print(md or "No changes.")
    if violations:
        raise PinError("Limits violated - nothing is published:\n" + "\n".join(violations))


def changes_markdown(changes, lang):
    t = {
        "de": {
            "images": "Basis-Images",
            "debian": "Debian-Pakete",
            "python": "Python-Pakete",
            "npm": "npm-Pakete (nur beim Bauen der Oberfläche, nicht im Image)",
            "new": "neu",
            "gone": "entfernt",
        },
        "en": {
            "images": "Base images",
            "debian": "Debian packages",
            "python": "Python packages",
            "npm": "npm packages (only for building the interface, not in the image)",
            "new": "new",
            "gone": "removed",
        },
    }[lang]
    out = []
    if changes.get("images"):
        out.append(f"- {t['images']}:")
        out += [f"  - {name}: `{a}` → `{b}`" for name, a, b in changes["images"]]
    for key in ("debian", "python", "npm"):
        part = changes.get(key) or {}
        items = [f"  - {n} `{a}` → `{b}`" for n, a, b in part.get("changed", [])]
        items += [f"  - {n} `{v}` ({t['new']})" for n, v in part.get("added", [])]
        items += [f"  - {n} `{v}` ({t['gone']})" for n, v in part.get("removed", [])]
        if items:
            out.append(f"- {t[key]}:")
            out += items
    return "\n".join(out)


# ---------------------------------------------------------------------------------------------------------------------
# Tags: <version>-s<counter>, changelog, registry
# ---------------------------------------------------------------------------------------------------------------------
def program_version(root=ROOT):
    match = re.search(r'^VERSION = "([^"]+)"', read_text("samonboarding/config.py", root), re.M)
    if not match:
        raise PinError("VERSION not found in samonboarding/config.py")
    return match.group(1)


def security_counter(version, changelog_text):
    found = [int(n) for n in re.findall(rf"^## {re.escape(version)}-s(\d+)\b", changelog_text, re.M)]
    return max(found, default=0)


def next_tag(root=ROOT):
    version = program_version(root)
    return f"{version}-s{security_counter(version, read_text(CHANGELOGS['de'], root)) + 1}"


def current_tag(root=ROOT):
    version = program_version(root)
    counter = security_counter(version, read_text(CHANGELOGS["de"], root))
    return f"{version}-s{counter}" if counter else version


def changelog_entry(tag, changes, lang, date=None):
    date = date or dt.date.today().isoformat()
    head = {
        "de": "Sicherheit: Sicherheitsupdate ohne Programmänderung: gleiches Programm, aktualisierte Pakete.",
        "en": "Security: security update without program changes: same program, updated packages.",
    }[lang]
    return f"## {tag} – {date}\n- {head}\n" + changes_markdown(changes, lang) + "\n\n"


def insert_changelog(text, entry):
    index = text.find("\n## ")
    if index < 0:
        return text.rstrip("\n") + "\n\n" + entry
    return text[: index + 1] + entry + text[index + 1 :]


def cmd_changelog(args):
    changes = json.loads(Path(args.changes).read_text(encoding="utf-8"))
    for lang, name in CHANGELOGS.items():
        path = ROOT / name
        path.write_text(insert_changelog(path.read_text(encoding="utf-8"), changelog_entry(args.tag, changes, lang)))
    print(f"Changelog entry {args.tag} added.")


def changelog_section(text, tag):
    """Body of the changelog entry '## <tag> – <date>' (without the heading); '' if there is none."""
    lines, inside = [], False
    for line in text.splitlines():
        if line.startswith("## "):
            if inside:
                break
            inside = re.match(rf"^## {re.escape(tag)}(\s|$)", line) is not None
            continue
        if inside:
            lines.append(line)
    return "\n".join(lines).strip()


def release_notes(tag, image, root=ROOT):
    """Text of the GitHub release: changelog entry in English and German, plus how to get the update."""
    de = changelog_section(read_text(CHANGELOGS["de"], root), tag)
    en = changelog_section(read_text(CHANGELOGS["en"], root), tag)
    if not de or not en:
        raise PinError(f"No changelog entry for {tag} (CHANGELOG.de.md / CHANGELOG.md)")
    kind = (
        "Security update: same program, updated packages. / Sicherheitsupdate: gleiches Programm, aktualisierte Pakete."
        if "-s" in tag
        else "New program version. / Neue Programmversion."
    )
    active = active_auto_exceptions(read_text(TRIVYIGNORE, root))
    exceptions = ""
    if active:
        exceptions = (
            "Temporary exceptions (a fix is announced, but the fixed package was not installable yet; the daily "
            "security update brings it as soon as it is available) / Befristete Ausnahmen (Korrektur angekündigt, "
            "aber noch nicht installierbar; das tägliche Sicherheitsupdate holt sie, sobald sie da ist):\n\n"
            + "\n".join(f"- {e['id']} – until/bis {e['exp'].isoformat()}" for e in active)
            + "\n\n---\n\n"
        )
    return (
        f"{kind}\n\n{en}\n\n---\n\n**Deutsch**\n\n{de}\n\n---\n\n" + exceptions + f"Image: `{image}:{tag}`\n\n"
        "Update: container manager (Dockhand, Watchtower, …) or "
        "`docker compose pull && docker compose up -d` or `sudo sh update.sh`.\n"
        "Without internet: `samonboarding-<version>-<amd64|arm64>.tar.gz` → "
        "`sudo sh update.sh --offline <file>`\n"
    )


def cmd_release_notes(args):
    text = release_notes(args.tag, args.image)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(text)


def ghcr_token(repo):
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {}
    if token:
        headers["Authorization"] = "Basic " + base64.b64encode(f"x:{token}".encode()).decode()
    data, _ = http_json(f"https://ghcr.io/token?service=ghcr.io&scope=repository:{repo}:pull", headers=headers)
    return data.get("token", "")


def registry_tags(image):
    """Published tags of ghcr.io/<owner>/<name>; empty list if nothing was published yet."""
    repo = image.removeprefix("ghcr.io/").lower()
    try:
        token = ghcr_token(repo)
        tags, url = [], f"https://ghcr.io/v2/{repo}/tags/list?n=1000"
        while url:
            req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
            with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
                tags += json.loads(resp.read()).get("tags") or []
                link = resp.headers.get("Link", "")
            match = re.search(r"<([^>]+)>;\s*rel=\"next\"", link)
            url = ("https://ghcr.io" + match.group(1)) if match else ""
        return tags
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []
        raise PinError(f"Registry ghcr.io not readable ({e.code}) - is packages: read set?") from e


def cmd_tags(args):
    if args.what == "next":
        print(next_tag())
    elif args.what == "current":
        print(current_tag())


def cmd_is_highest(args):
    sys.exit(0 if is_highest(args.tag, args.others) else 1)


def cmd_registry_tags(args):
    print("\n".join(registry_tags(args.image)))


def plan(mode, changed, published, root=ROOT):
    """What does this run do? -> {action: publish | skip | nothing, tag, latest, commit, reason}.
    release:          the program version, unless it is already published (never overwritten)
    security-update:  changed -> next <version>-s<counter>; unchanged -> nothing, unless the current state is
                      missing in the registry (e.g. the previous push failed) - then it is published now.
                      A program version that is not released yet -> nothing (the release by hand comes first)"""
    result = _plan(mode, changed, published, root)
    tag = result["tag"]
    minor = ".".join(tag.split("-s")[0].split(".")[:2])
    same_minor = [t for t in published if tag_key(t) is not None and t.split("-s")[0].startswith(minor + ".")]
    result["minor"] = minor  # e.g. 2.0: the newest 2.0.x including its security updates
    result["minor_latest"] = result["action"] == "publish" and is_highest(tag, same_minor)
    return result


def _plan(mode, changed, published, root):
    version = program_version(root)
    published = [t for t in published if tag_key(t) is not None]
    if mode == "release":
        if version in published:
            return {
                "action": "skip",
                "tag": version,
                "latest": False,
                "commit": False,
                "reason": f"{version} is already published and is never overwritten - raise VERSION for a new release",
            }
        tag, commit = version, False
    elif mode == "security-update":
        if version not in published and not any(t.startswith(version + "-s") for t in published):
            # Code audit 2026-11b: a merged but not yet released version must never go out via patch day - only
            # the release by hand (after the owner's go) publishes a new version
            return {
                "action": "nothing",
                "tag": version,
                "latest": False,
                "commit": False,
                "reason": f"{version} is not released yet - the security update waits for the release",
            }
        if changed:
            counters = [security_counter(version, read_text(CHANGELOGS["de"], root))]
            keys = [tag_key(t) for t in published if t.startswith(version + "-s")]
            counters += [key[3] for key in keys if key is not None]
            tag, commit = f"{version}-s{max(counters) + 1}", True
        else:
            tag, commit = current_tag(root), False
            if tag in published:
                return {
                    "action": "nothing",
                    "tag": tag,
                    "latest": False,
                    "commit": False,
                    "reason": f"No package has changed and {tag} is published - nothing to do",
                }
    else:
        raise PinError(f"Unknown mode: {mode}")
    if tag in published:
        raise PinError(f"{tag} is already published - published versions are never overwritten")
    return {
        "action": "publish",
        "tag": tag,
        "latest": is_highest(tag, published),
        "commit": commit,
        "reason": f"publish {tag}"
        + (" and :latest" if is_highest(tag, published) else " (:latest stays on a higher version)"),
    }


def cmd_plan(args):
    result = plan(args.mode, args.changed == "true", registry_tags(args.image))
    for key in ("action", "tag", "latest", "commit", "minor", "minor_latest"):
        value = result[key]
        set_output(key, str(value).lower() if isinstance(value, bool) else value)
    annotate("notice", f"Plan: {result['action']} {result['tag']}", result["reason"])
    summary(f"### Plan\n\n**{result['action']}** `{result['tag']}` - {result['reason']}")
    print(json.dumps(result))


def cmd_bundle(_args):
    """Dry run: hand over the renewed pin files (gzip + base64) as notices on the run page."""
    import gzip
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name in (IMAGES_LOCK, OS_LOCK, REQ_TXT, PKG_JSON, PKG_LOCK, *CHANGELOGS.values()):
            if (ROOT / name).exists():
                tar.add(ROOT / name, arcname=name)
    data = base64.b64encode(gzip.compress(buf.getvalue(), 9)).decode()
    size = 4000  # GitHub cuts annotations after 4096 characters
    chunks = [data[i : i + size] for i in range(0, len(data), size)]
    if len(chunks) > 10:  # at most 10 notices per step
        raise PinError(f"Bundle too large for notices ({len(chunks)} parts)")
    for number, chunk in enumerate(chunks, 1):
        annotate("notice", f"pins bundle {number}/{len(chunks)}", chunk)


RETRY_HINTS = ("Temporary failure", "Connection timed out", "Could not connect", "503", "502", "504", "429",
               "Connection reset", "TLS handshake timeout", "i/o timeout", "Hash Sum mismatch")  # fmt: skip
ERROR_RE = re.compile(r"(^E: |ERROR|error:|Error:|failed|Failed|Err:)")


def cmd_run(args):
    """Run a command (e.g. a docker build); on failure the decisive lines are shown on the run page.
    A network problem (e.g. snapshot.debian.org briefly not reachable) is retried once after a pause."""
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    for attempt in (1, 2):
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in proc.stdout or []:  # stdout=PIPE: always set
            sys.stdout.write(line)
            lines.append(line.rstrip("\n"))
            del lines[:-400]
        if proc.wait() == 0:
            return
        text = "\n".join(lines)
        if attempt == 1 and any(hint in text for hint in RETRY_HINTS):
            annotate("warning", f"{args.title}: retry", "network problem - trying again in 60 seconds")
            subprocess.run(["sleep", "60"], check=False)
            continue
        relevant = [line for line in lines if ERROR_RE.search(line)][-15:]
        raise PinError(f"{args.title} failed:\n" + "\n".join(relevant + ["..."] + lines[-10:]))


# ---------------------------------------------------------------------------------------------------------------------
# Tests and start check in the image
# ---------------------------------------------------------------------------------------------------------------------
def cmd_test_image(args):
    """The test suite with the Python, packages and system libraries of the image (checkout read-only)."""
    base = ["run", "--rm", "-v", f"{ROOT}:/src:ro", "-w", "/src", "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "HOME=/tmp"]
    base += ["-e", "DATA_DIR=/tmp/samonboarding-test-data"]  # the checkout is read-only
    for cmd in (["-m", "unittest", "discover", "-s", "tests"], ["tests/smoke_app.py"]):
        done = subprocess.run(
            ["docker", *base, "--entrypoint", "python", args.image, *cmd], capture_output=True, text=True, check=False
        )
        output = done.stdout + done.stderr
        print(output[-20000:])
        if done.returncode != 0:
            failed = [line for line in output.splitlines() if re.match(r"^(FAIL|ERROR): ", line)]
            details = "\n".join(failed[:30]) or "\n".join(output.splitlines()[-25:])
            raise PinError(f"Tests in the image {args.image} failed ({' '.join(cmd)}):\n{details}")
    print(f"Tests in the image {args.image} passed.")


def cmd_smoke(args):
    """Start the server in the image and query it via HTTPS. With --as-root like the docker-compose.yml: started as
    root with only DAC_READ_SEARCH/CHOWN/SETUID/SETGID and a closed data folder (0700) of another owner - the start
    script must hand the folder over and then run the program as user 10001 without any rights."""
    name = "samonb-smoke-" + re.sub(r"[^a-z0-9]", "", args.image.lower())[-20:] + ("-root" if args.as_root else "")
    docker("rm", "-f", name, check=False)
    options = []
    if args.as_root:
        data = tempfile.mkdtemp(prefix="samonb-data-", dir=os.environ.get("RUNNER_TEMP") or None)
        options = ["--user", "0:0", "--cap-drop", "ALL", "--cap-add", "DAC_READ_SEARCH", "--cap-add", "CHOWN"]
        options += ["--cap-add", "SETUID"]
        options += ["--cap-add", "SETGID", "--security-opt", "no-new-privileges:true", "-v", f"{data}:/app/data"]
    docker("run", "-d", "--name", name, *options, args.image)
    probe = (
        "import ssl, urllib.request; print(urllib.request.urlopen('https://localhost:9500/api/public-config', "
        "timeout=3, context=ssl._create_unverified_context()).read().decode())"
    )
    try:
        for _ in range(45):
            if docker("exec", name, "python", "-c", probe, check=False).returncode == 0:
                break
            subprocess.run(["sleep", "2"], check=False)
        else:
            logs = docker("logs", name, check=False)
            raise PinError(
                f"The server in {args.image} does not answer on HTTPS:\n{(logs.stdout + logs.stderr)[-2000:]}"
            )
        if args.as_root:
            status = docker("exec", name, "cat", "/proc/1/status").stdout
            uid = re.search(r"^Uid:\s+(\d+)\s+(\d+)", status, re.M)
            caps = re.search(r"^CapEff:\s+([0-9a-f]+)", status, re.M)
            owner = docker("exec", name, "stat", "-c", "%u", "/app/data").stdout.strip()
            state = docker("exec", name, "test", "-f", "/app/data/datenstand.json", check=False).returncode
            if not uid or uid.groups() != ("10001", "10001") or not caps or int(caps.group(1), 16) != 0:
                raise PinError(f"The program does not run as user 10001 without rights:\n{status[:600]}")
            if owner != "10001" or state != 0:
                raise PinError(f"The data folder was not handed over (owner {owner}, datenstand.json: {state == 0})")
            print(f"Started as root: data folder handed over, program runs as 10001 without rights ({args.image}).")
        print(f"Server in {args.image} answers on HTTPS.")
    finally:
        docker("rm", "-f", name, check=False)


# ---------------------------------------------------------------------------------------------------------------------
# Trivy: only HIGH/CRITICAL with an available fix stop the release
# ---------------------------------------------------------------------------------------------------------------------
IGNORE_RE = re.compile(r"^(\S+)\s+exp:(\d{4}-\d{2}-\d{2})\s*$")


# Automatic temporary exceptions: a fix is listed for a vulnerability, but the fixed package is not installable in the
# build yet (e.g. not on the Debian mirror). A security update or release then does not stop: it enters the finding
# here with an expiry date - counted from the first time, never extended. Before the expiry date every daily security
# update tries again to get the fix; once it is in the build the entry is removed. After the expiry date the run is red
# again and someone has to look at it. A CVE whose exception (automatic or by hand) has expired never gets a new one.
AUTO_PREFIX = "# automatic "
AUTO_HEADER = "# --- Automatic temporary exceptions (written by the security update and the release - do not edit) ---"
AUTO_DAYS = {"CRITICAL": 7, "HIGH": 14}
SEVERITY_RANK = {"HIGH": 1, "CRITICAL": 2}


def trivyignore_entries(text):
    """.trivyignore -> [{id, exp (date), auto, reason}] in file order."""
    entries, previous = [], ""
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            previous = ""
            continue
        if line.startswith("#"):
            previous = line
            continue
        match = IGNORE_RE.match(line)
        if match:
            entries.append(
                {
                    "id": match.group(1),
                    "exp": dt.date.fromisoformat(match.group(2)),
                    "auto": previous.startswith(AUTO_PREFIX),
                    "reason": previous,
                }
            )
        previous = ""
    return entries


def manual_trivyignore(text):
    """.trivyignore without the automatic exceptions (for Trivy: those are evaluated by scan itself)."""
    out, pending = [], []
    for raw in text.splitlines():
        line = raw.strip()
        if line == AUTO_HEADER:
            continue
        if line.startswith(AUTO_PREFIX):
            pending = [raw]
            continue
        if pending:
            pending = []
            if IGNORE_RE.match(line):
                continue  # the entry belonging to the automatic reason
        out.append(raw)
    return "\n".join(out).rstrip("\n") + "\n"


def classify_vulns(vulns, entries, today):
    """Sort the findings (HIGH/CRITICAL with a fix, manual exceptions already applied by Trivy) by CVE:
    kept     covered by a valid automatic exception
    expired  an exception for this CVE (automatic or by hand) has expired - never a new one, someone has to look
    new      no exception yet"""
    out = {"kept": {}, "expired": {}, "new": {}}
    for vuln in vulns:
        own = [e for e in entries if e["id"] == vuln["id"]]
        if any(e["exp"] >= today and e["auto"] for e in own):
            kind = "kept"
        elif any(e["exp"] >= today for e in own):
            continue  # valid exception by hand (Trivy applies those itself)
        elif own:
            kind = "expired"
        else:
            kind = "new"
        out[kind].setdefault(vuln["id"], []).append(vuln)
    return out


def auto_needed(groups):
    """{CVE: {severity, packages}} for scan --auto-out: everything that still needs a temporary exception."""
    needed = {}
    for kind in ("kept", "new"):
        for cve, vulns in groups[kind].items():
            item = needed.setdefault(cve, {"severity": "HIGH", "packages": []})
            for v in vulns:
                if SEVERITY_RANK.get(v["severity"], 0) > SEVERITY_RANK[item["severity"]]:
                    item["severity"] = v["severity"]
                pkg = f"{v['pkg']} {v['installed']} (fix {v['fixed']})"
                if pkg not in item["packages"]:
                    item["packages"].append(pkg)
    return needed


def apply_auto_exceptions(text, needed, today):
    """New .trivyignore: manual part unchanged; automatic part = exactly the CVEs in needed. An existing valid entry
    keeps its date and reason (the time limit is never extended); a CVE with an expired exception gets none."""
    entries = trivyignore_entries(text)
    lines = []
    for cve in sorted(needed):
        own = [e for e in entries if e["id"] == cve]
        if any(e["exp"] >= today and not e["auto"] for e in own):
            continue  # covered by hand
        valid = [e for e in own if e["auto"] and e["exp"] >= today]
        if valid:
            lines += [valid[0]["reason"], f"{cve} exp:{valid[0]['exp'].isoformat()}"]
        elif own:
            continue  # expired: scan reports it as an error
        else:
            item = needed[cve]
            exp = today + dt.timedelta(days=AUTO_DAYS.get(item["severity"], AUTO_DAYS["CRITICAL"]))
            reason = (
                f"{AUTO_PREFIX}{today.isoformat()}: {item['severity']} {', '.join(sorted(item['packages']))} - "
                "fixed version not installable in the build yet"
            )
            lines += [reason, f"{cve} exp:{exp.isoformat()}"]
    out = manual_trivyignore(text).rstrip("\n") + "\n"
    if lines:
        out += "\n" + AUTO_HEADER + "\n\n" + "\n\n".join("\n".join(lines[i : i + 2]) for i in range(0, len(lines), 2))
        out += "\n"
    return out


def active_auto_exceptions(text, today=None):
    today = today or dt.date.today()
    return [e for e in trivyignore_entries(text) if e["auto"] and e["exp"] >= today]


def cmd_trivyignore_auto(args):
    needed = {}
    for name in args.files:
        path = Path(name)
        if not path.exists():
            continue
        for cve, item in json.loads(path.read_text(encoding="utf-8")).items():
            merged = needed.setdefault(cve, {"severity": item["severity"], "packages": []})
            if SEVERITY_RANK.get(item["severity"], 0) > SEVERITY_RANK.get(merged["severity"], 0):
                merged["severity"] = item["severity"]
            merged["packages"] += [p for p in item["packages"] if p not in merged["packages"]]
    old = read_text(TRIVYIGNORE)
    new = apply_auto_exceptions(old, needed, dt.date.today())
    changed = new != old
    if changed:
        (ROOT / TRIVYIGNORE).write_text(new, encoding="utf-8")
    set_output("changed", str(changed).lower())
    active = active_auto_exceptions(new)
    lines = [f"- {e['id']} until {e['exp'].isoformat()}: {e['reason'][len(AUTO_PREFIX) :]}" for e in active]
    for e in active:
        annotate(
            "warning", f"Temporary exception {e['id']} until {e['exp'].isoformat()}", e["reason"][len(AUTO_PREFIX) :]
        )
    summary("### Automatic temporary exceptions\n\n" + ("\n".join(lines) if lines else "None."))
    print(f".trivyignore {'updated' if changed else 'unchanged'}: {len(active)} automatic temporary exception(s).")


def trivyignore_problems(text, today=None):
    """Every entry: a comment line with the reason directly above it and an expiry date (ID exp:YYYY-MM-DD)."""
    today = today or dt.date.today()
    problems, previous = [], ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line:
            previous = ""
            continue
        if line.startswith("#"):
            previous = line
            continue
        match = IGNORE_RE.match(line)
        if not match:
            problems.append(f"line {number}: '{line}' needs an expiry date: <ID> exp:YYYY-MM-DD")
        else:
            if dt.date.fromisoformat(match.group(2)) - today > dt.timedelta(days=366):
                problems.append(f"line {number}: {match.group(1)} expires more than a year from now - check again")
        if not previous.lstrip("#").strip():
            problems.append(f"line {number}: the reason is missing (comment line directly above)")
        previous = ""
    return problems


def cmd_trivyignore_check(_args):
    problems = trivyignore_problems(read_text(TRIVYIGNORE))
    if problems:
        raise PinError(".trivyignore:\n" + "\n".join(problems))
    print(".trivyignore is fine.")


def trivy_vulns(report):
    """Trivy JSON -> findings that count (HIGH/CRITICAL with a fixed version), each once."""
    found, seen = [], set()
    for result in report.get("Results") or []:
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") not in ("HIGH", "CRITICAL") or not vuln.get("FixedVersion"):
                continue
            key = (vuln.get("VulnerabilityID"), vuln.get("PkgName"), vuln.get("InstalledVersion"))
            if key in seen:
                continue
            seen.add(key)
            found.append(
                {
                    "id": str(vuln.get("VulnerabilityID")),
                    "severity": vuln.get("Severity"),
                    "pkg": str(vuln.get("PkgName")),
                    "installed": str(vuln.get("InstalledVersion")),
                    "fixed": str(vuln.get("FixedVersion")),
                    "where": str(vuln.get("PkgPath") or result.get("Target")),
                }
            )
    return found


def vuln_text(v):
    return f"{v['severity']} {v['id']} {v['pkg']} {v['installed']} -> {v['fixed']} ({v['where']})"


def trivy_findings(report):
    """Trivy JSON -> list of findings that stop the release (HIGH/CRITICAL with a fixed version)."""
    return [vuln_text(v) for v in trivy_vulns(report)]


def inherited(vuln, rev):
    """Is the package in exactly this version already in the pins at rev (e.g. main before this pull request)?
    Then the finding was not brought in by the change - it is handled by the security update on main."""
    if not hasattr(inherited, "cache"):
        inherited.cache = {}
    if rev not in inherited.cache:
        os_lock = parse_os_lock_archs(git_show(rev, OS_LOCK))
        python = parse_requirements(git_show(rev, REQ_TXT))
        inherited.cache[rev] = (os_lock, python)
    os_lock, python = inherited.cache[rev]
    if any(packages.get(vuln["pkg"]) == vuln["installed"] for packages in os_lock.values()):
        return True
    return python.get(normalize(vuln["pkg"]), (None, None))[1] == vuln["installed"]


def run_trivy(image, ignorefile):
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp, "trivy.json")
        ignore = Path(tmp, "trivyignore")
        ignore.write_text(ignorefile, encoding="utf-8")
        cmd = [
            "trivy",
            "image",
            "--quiet",
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--ignore-unfixed",
            "--ignorefile",
            str(ignore),
            "--format",
            "json",
            "--output",
            str(out),
            "--exit-code",
            "0",
            image,
        ]
        done = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if done.returncode != 0 or not out.exists():
            raise PinError(f"Trivy could not scan {image}:\n{(done.stderr or done.stdout)[-2000:]}")
        return json.loads(out.read_text(encoding="utf-8") or "{}")


def cmd_scan(args, today=None):
    """Exit code 0 = nothing stops; 1 = stop (or Trivy failed). --report-only: 3 = there is something to fix."""
    today = today or dt.date.today()
    text = read_text(TRIVYIGNORE)
    problems = trivyignore_problems(text, today)
    if problems:
        raise PinError(".trivyignore:\n" + "\n".join(problems))
    report = run_trivy(args.image, manual_trivyignore(text))
    vulns = trivy_vulns(report)
    groups = classify_vulns(vulns, trivyignore_entries(text), today)
    label = args.label or args.image
    if args.report_only:
        # daily: is there anything a security update could fix (also behind a temporary exception)?
        if vulns:
            print(f"Trivy: {label}: {len(vulns)} vulnerabilities with an available fix - security update due")
            return 3
        print(f"Trivy: {label}: nothing to fix")
        return 0
    expired = [v for vs in groups["expired"].values() for v in vs]
    new = [v for vs in groups["new"].values() for v in vs]
    kept = [v for vs in groups["kept"].values() for v in vs]
    allowed, stop = [], list(expired)
    if args.auto_out:
        allowed = new
        Path(args.auto_out).write_text(json.dumps(auto_needed(groups), indent=1, sort_keys=True), encoding="utf-8")
    elif args.inherited_from:
        allowed = [v for v in new if inherited(v, args.inherited_from)]
        stop += [v for v in new if v not in allowed]
    else:
        stop += new
    lines = []
    valid = {e["id"]: e for e in trivyignore_entries(text) if e["auto"] and e["exp"] >= today}
    for v in kept:
        until = valid[v["id"]]["exp"].isoformat()
        annotate("warning", f"Temporary exception until {until}", vuln_text(v))
        lines.append(f"- temporary exception until {until}: {vuln_text(v)}")
    for v in allowed:
        why = (
            "gets a temporary exception (fixed package not in the build yet)"
            if args.auto_out
            else "already on main with the same version - fixed by the security update there, does not stop this check"
        )
        annotate("warning", f"Not stopped: {v['id']}", f"{vuln_text(v)} - {why}")
        lines.append(f"- {why}: {vuln_text(v)}")
    for v in expired:
        lines.append(f"- EXCEPTION EXPIRED: {vuln_text(v)}")
    for v in stop:
        if v not in expired:
            lines.append(f"- stops: {vuln_text(v)}")
    if stop:
        summary(f"### Trivy: {label}\n\n" + "\n".join(lines))
        hint = f"\n{args.hint}" if getattr(args, "hint", "") else ""
        note = f"\n{len(expired)} of them had an exception that has expired - check them by hand." if expired else ""
        raise PinError(
            f"Trivy found {len(stop)} vulnerabilities (HIGH/CRITICAL with a fix) in {label}:\n"
            + "\n".join(vuln_text(v) for v in stop[:60])
            + note
            + hint
        )
    if lines:
        summary(f"### Trivy: {label}\n\n" + "\n".join(lines))
        count = len(kept) + len(allowed)
        print(f"Trivy: {label}: nothing stops ({count} findings with a temporary exception or inherited).")
        return 0
    summary(f"### Trivy: {label}\n\nNo HIGH/CRITICAL vulnerabilities with an available fix.")
    print(f"Trivy: {label} has no HIGH/CRITICAL vulnerabilities with an available fix.")
    return 0


# ---------------------------------------------------------------------------------------------------------------------
# eol: how long does the base still get security updates?
# ---------------------------------------------------------------------------------------------------------------------
def base_cycles(lock_text):
    lock = parse_keyvalue(lock_text)
    py_major, py_minor, distro = python_series(split_image(lock.get("PYTHON_IMAGE", ""))[1])
    node_major, _ = node_series(split_image(lock.get("NODE_IMAGE", ""))[1])
    if distro not in DEBIAN_RELEASES:
        raise PinError(f"Unknown Debian release: {distro}")
    return [
        ("debian", DEBIAN_RELEASES[distro], f'Debian {DEBIAN_RELEASES[distro]} "{distro}"'),
        ("python", f"{py_major}.{py_minor}", f"Python {py_major}.{py_minor}"),
        ("nodejs", node_major, f"Node {node_major} (only for building)"),
    ]


def fetch_eol(product, cycle):
    """End of the security support from endoflife.date (new API, otherwise the old one). None = not reachable."""
    for url, pick in (
        (f"https://endoflife.date/api/v1/products/{product}/releases/{cycle}", lambda d: d["result"].get("eolFrom")),
        (f"https://endoflife.date/api/{product}/{cycle}.json", lambda d: d.get("eol")),
    ):
        try:
            data, _ = http_json(url, headers={"Accept": "application/json", "User-Agent": "samonboarding-eol-check"})
            value = pick(data)
            if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
                return value
        except (urllib.error.URLError, OSError, KeyError, ValueError, TypeError):
            continue
    return None


def eol_level(end, today):
    days = (dt.date.fromisoformat(end) - today).days
    if days < EOL_ERROR_DAYS:
        return "error", days
    if days < EOL_WARN_DAYS:
        return "warning", days
    return "ok", days


def cmd_eol(_args, fetch=fetch_eol, today=None):
    today = today or dt.date.today()
    errors, rows = [], []
    for product, cycle, label in base_cycles(read_text(IMAGES_LOCK)):
        end = fetch(product, cycle)
        source = "endoflife.date"
        if end is None:
            end = EOL_FALLBACK.get((product, cycle))
            source = "stored date (endoflife.date not reachable)"
            annotate("warning", "Base support", f"{label}: endoflife.date not reachable, stored date used")
        if end is None:
            errors.append(f"{label}: end of support unknown")
            continue
        level, days = eol_level(end, today)
        rows.append(f"| {label} | {end} | {days} | {source} |")
        if level == "error":
            errors.append(f"{label}: security updates end on {end} (in {days} days) - raise the base now")
        elif level == "warning":
            text = f"{label}: security updates end on {end} (in {days} days) - plan the change"
            annotate("warning", "Base support", text)
    table = "| Part | Until | Days | Source |\n|---|---|---|---|\n" + "\n".join(rows)
    summary("### Security updates of the base\n\n" + table)
    print("\n".join(rows))
    if errors:
        raise PinError("\n".join(errors))


# ---------------------------------------------------------------------------------------------------------------------
def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("update").set_defaults(fn=cmd_update)
    sub.add_parser("build-args").set_defaults(fn=cmd_build_args)
    p = sub.add_parser("os-lock")
    p.add_argument("image")
    p.add_argument("--arch", required=True, choices=ARCHS)
    p.add_argument("--check", action="store_true")
    p.set_defaults(fn=cmd_os_lock)
    p = sub.add_parser("os-lock-merge")
    p.add_argument("parts", nargs="+")
    p.set_defaults(fn=cmd_os_lock_merge)
    p = sub.add_parser("changes")
    p.add_argument("--base", default="HEAD")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_changes)
    sub.add_parser("next-tag").set_defaults(fn=cmd_tags, what="next")
    sub.add_parser("current-tag").set_defaults(fn=cmd_tags, what="current")
    p = sub.add_parser("changelog")
    p.add_argument("tag")
    p.add_argument("changes")
    p.set_defaults(fn=cmd_changelog)
    p = sub.add_parser("is-highest")
    p.add_argument("tag")
    p.add_argument("others", nargs="*")
    p.set_defaults(fn=cmd_is_highest)
    p = sub.add_parser("registry-tags")
    p.add_argument("image")
    p.set_defaults(fn=cmd_registry_tags)
    p = sub.add_parser("test-image")
    p.add_argument("image")
    p.set_defaults(fn=cmd_test_image)
    p = sub.add_parser("smoke")
    p.add_argument("image")
    p.add_argument("--as-root", action="store_true")
    p.set_defaults(fn=cmd_smoke)
    p = sub.add_parser("scan")
    p.add_argument("image")
    p.add_argument("--label")
    p.add_argument("--hint", default="")
    mode = p.add_mutually_exclusive_group()
    mode.add_argument("--auto-out", help="release/security update: new findings get a temporary exception (JSON)")
    mode.add_argument("--inherited-from", help="check: findings already in the pins at this git revision only warn")
    mode.add_argument("--report-only", action="store_true", help="exit code 3 if a security update could fix something")
    p.set_defaults(fn=cmd_scan)
    p = sub.add_parser("plan")
    p.add_argument("--mode", required=True, choices=["release", "security-update"])
    p.add_argument("--changed", default="false")
    p.add_argument("--image", required=True)
    p.set_defaults(fn=cmd_plan)
    sub.add_parser("bundle").set_defaults(fn=cmd_bundle)
    p = sub.add_parser("release-notes")
    p.add_argument("tag")
    p.add_argument("--image", required=True)
    p.add_argument("--out")
    p.set_defaults(fn=cmd_release_notes)
    p = sub.add_parser("run")
    p.add_argument("title")
    p.add_argument("command", nargs=argparse.REMAINDER)
    p.set_defaults(fn=cmd_run)
    sub.add_parser("trivyignore-check").set_defaults(fn=cmd_trivyignore_check)
    p = sub.add_parser("trivyignore-auto")
    p.add_argument("files", nargs="*")
    p.set_defaults(fn=cmd_trivyignore_auto)
    sub.add_parser("eol").set_defaults(fn=cmd_eol)
    args = parser.parse_args(argv)
    try:
        code = args.fn(args)
    except PinError as e:
        first, _, rest = str(e).partition("\n")
        annotate("error", first[:120], rest or first)
        print(str(e), file=sys.stderr)
        return 1
    return 3 if code == 3 else 0  # 3: scan --report-only found something a security update could fix


if __name__ == "__main__":
    sys.exit(main())
