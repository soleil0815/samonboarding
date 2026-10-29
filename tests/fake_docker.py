#!/usr/bin/env python3
"""Nachgebautes docker (und docker compose) fuer die Tests von update.sh - aendert nur eine Zustandsdatei.

Zustand (JSON, Pfad in FAKE_DOCKER_STATE):
  registry   {ref: image_id}            was "docker pull" holen kann
  tags       {ref: image_id}            lokal vorhandene Images
  labels     {image_id: version}        org.opencontainers.image.version
  compose    {image_id: text}           /app/docker-compose.yml im Image
  health     {image_id: status}         Gesundheit eines Containers mit diesem Image (Standard: healthy)
  container  {id, image, ref} | null    der laufende Dienst "samonboarding"
  mounts     [pfad, ...]                Quellen eingebundener Ordner (docker inspect .Mounts)
  calls      [[arg, ...], ...]          Protokoll aller Aufrufe
"""

import json
import os
import re
import sys

STATE = os.environ["FAKE_DOCKER_STATE"]


def load():
    with open(STATE, encoding="utf-8") as fh:
        return json.load(fh)


def save(state):
    with open(STATE, "w", encoding="utf-8") as fh:
        json.dump(state, fh)


def image_id(state, ref):
    if ref in state["tags"]:
        return state["tags"][ref]
    if ref in state["labels"]:  # schon eine Image-ID
        return ref
    return None


def compose_ref():
    """Das Image, das docker compose starten wuerde (docker-compose.yml + .env im aktuellen Ordner)."""
    env = {}
    if os.path.exists(".env"):
        for line in open(".env", encoding="utf-8"):
            if "=" in line and not line.startswith("#"):
                key, value = line.rstrip("\n").split("=", 1)
                env[key] = value
    text = open("docker-compose.yml", encoding="utf-8").read()
    image = re.search(r"^\s*image:\s*(\S+)", text, re.M).group(1)

    def subst(match):
        name, default = match.group(1), match.group(2) or ""
        return env.get(name) or default

    return re.sub(r"\$\{(\w+):-([^}]*)\}", subst, image)


def compose(state, args):
    if args[:1] == ["version"]:
        return 0 if not os.environ.get("FAKE_NO_COMPOSE") else 1
    cmd = args[0]
    if cmd == "ps":
        if state["container"] and state["container"].get("running", True):
            print(state["container"]["id"])
        return 0
    if cmd == "up":
        ref = compose_ref()
        image = image_id(state, ref)
        if image is None:
            print(f"pull access denied for {ref}", file=sys.stderr)
            return 1
        number = state.get("next", 1)
        state["next"] = number + 1
        state["container"] = {"id": f"cid{number}", "image": image, "ref": ref, "running": True}
        return 0
    if cmd == "stop":
        if state["container"]:
            state["container"]["running"] = False
        return 0
    return 0


def inspect(state, fmt, target):
    c = state["container"]
    if c and target == c["id"]:
        if ".State.Health" in fmt:
            print(state["health"].get(c["image"], "healthy"))
        elif ".RestartCount" in fmt:
            print(state.get("restarts", {}).get(c["image"], 0))
        elif ".Config.Image" in fmt:
            print(c["ref"])
        elif ".Image" in fmt:
            print(c["image"])
        elif ".Mounts" in fmt:
            for path in state.get("mounts", []):
                print(path)
        return 0
    if target.startswith("other") and ".Mounts" in fmt:
        for path in state.get("mounts", []):
            print(path)
        return 0
    return 1


def main(argv):
    state = load()
    state["calls"].append(argv)
    code = 0
    if argv[:1] == ["compose"]:
        code = compose(state, argv[1:])
    elif argv[0] == "pull":
        ref = argv[1]
        if ref in state["registry"]:
            state["tags"][ref] = state["registry"][ref]
        else:
            print(f"manifest unknown: {ref}", file=sys.stderr)
            code = 1
    elif argv[0] == "tag":
        source = image_id(state, argv[1])
        if source is None:
            code = 1
        else:
            state["tags"][argv[2]] = source
    elif argv[:2] == ["image", "inspect"]:
        target = argv[-1]
        image = image_id(state, target)
        if image is None:
            code = 1
        else:
            print(state["labels"].get(image, ""))
    elif argv[:2] == ["image", "prune"]:
        pass
    elif argv[0] == "inspect":
        code = inspect(state, argv[2], argv[3])
    elif argv[0] == "create":
        image = image_id(state, argv[1])
        print(f"tmp-{image}")
    elif argv[0] == "cp":
        source, dest = argv[1], argv[2]
        image = source.split(":", 1)[0].removeprefix("tmp-")
        text = state["compose"].get(image)
        if text is None:
            code = 1
        else:
            with open(dest, "w", encoding="utf-8") as fh:
                fh.write(text)
    elif argv[0] == "rm":
        pass
    elif argv[0] == "load":
        ref, image, version = open(argv[2], encoding="utf-8").read().split()
        state["tags"][ref] = image
        state["labels"][image] = version
        print(f"Loaded image: {ref}")
    elif argv[0] == "logs":
        print("fake log line")
    elif argv[0] == "ps":
        ids = []
        if state["container"]:
            ids.append(state["container"]["id"])
        if state.get("mounts"):
            ids.append("other1")
        print("\n".join(ids))
    save(state)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
