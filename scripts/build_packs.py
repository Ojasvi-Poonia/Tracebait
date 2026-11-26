"""Rebuild the shipped incident packs from their pinned upstream files.

Usage:
    uv run python scripts/build_packs.py           # download, verify and write the packs
    uv run python scripts/build_packs.py --check   # fail if a shipped pack is out of date

The recipes live in scripts/pack_recipes.py. Selected records are kept verbatim except
for the conversions in tracebait.otrf and tracebait.cloudtrail (rendered Message dropped,
nested CloudTrail keys dotted, scalars written as text, nginx lines mapped to ECS) and
the fields a recipe drops.
"""

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from functools import cache
from pathlib import Path

from pack_recipes import PACKS, Format, PackRecipe, Recipe

from tracebait.cloudtrail import cloudtrail_entry
from tracebait.field_registry import load_registry
from tracebait.models import Incident, LogEntry
from tracebait.nginx import ecs_entry, parse_kv_line
from tracebait.otrf import SYSMON_CHANNEL, sysmon_entry
from tracebait.packs import Pack, PackSource, pack_problems
from tracebait.records import drop_fields, read_records

ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = ROOT / "src" / "tracebait" / "data" / "packs"
DOWNLOAD_TIMEOUT_SECONDS = 60


@cache
def download(source: PackSource) -> bytes:
    if not source.url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS url {source.url}")
    with urllib.request.urlopen(source.url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310 - https only, checked above
        data: bytes = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source.sha256:
        raise ValueError(f"{source.url}: sha256 {digest}, expected {source.sha256}")
    return data


def entries_in(data: bytes, fmt: Format) -> tuple[LogEntry, ...]:
    match fmt:
        case Format.OTRF_ZIP:
            with zipfile.ZipFile(io.BytesIO(data)) as zipped:
                (name,) = (n for n in zipped.namelist() if n.endswith(".json"))
                text = zipped.read(name).decode("utf-8")
            records = read_records(text.splitlines())
            return tuple(sysmon_entry(r) for r in records if r.get("Channel") == SYSMON_CHANNEL)
        case Format.CLOUDTRAIL_JSONL:
            records = read_records(data.decode("utf-8").splitlines())
            return tuple(cloudtrail_entry(r) for r in records)
        case Format.NGINX_KV:
            lines = data.decode("utf-8").splitlines()
            return tuple(ecs_entry(parse_kv_line(line)) for line in lines if line.strip())


def build_incident(recipe: Recipe) -> Incident:
    entries = entries_in(download(recipe.source), recipe.format)
    for rule in recipe.select:
        if not any(rule.matches(e.fields) for e in entries):
            raise ValueError(f"{recipe.incident_id}: no entry matches {dict(rule.where)}")
    # Keep upstream order (it breaks timestamp ties) and one copy of repeated records.
    selected = list(
        dict.fromkeys(
            drop_fields(entry, rule.drop)
            for entry in entries
            for rule in recipe.select
            if rule.matches(entry.fields)
        )
    )
    selected.sort(key=lambda e: e.fields.get(recipe.order_by, ""))
    return Incident(
        id=recipe.incident_id,
        source=recipe.source.id,
        attack_technique=recipe.attack_technique,
        entries=tuple(selected),
        ground_truth_disposition=recipe.disposition,
    )


def build_pack(pack_id: str, recipe: PackRecipe) -> str:
    pack = Pack(
        version=1,
        id=pack_id,
        title=recipe.title,
        # Several incidents may be sliced from one source; list it once.
        sources=tuple(dict.fromkeys(r.source for r in recipe.recipes)),
        incidents=tuple(build_incident(r) for r in recipe.recipes),
    )
    problems = pack_problems(pack, load_registry())
    if problems:
        raise ValueError(f"{pack_id}: " + "; ".join(problems))
    return pack.model_dump_json(indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="Rebuild the shipped incident packs.")
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    stale = []
    for pack_id, recipe in PACKS.items():
        path = PACKS_DIR / f"{pack_id}.json"
        text = build_pack(pack_id, recipe)
        if args.check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(path.name)
        else:
            path.write_text(text, encoding="utf-8")
            sys.stdout.write(f"wrote {path.relative_to(ROOT)}\n")
    if stale:
        sys.stderr.write(f"out of date: {', '.join(stale)}; run scripts/build_packs.py\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
