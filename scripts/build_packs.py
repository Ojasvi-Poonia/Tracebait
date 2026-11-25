"""Rebuild the shipped incident packs from their pinned upstream archives.

Usage:
    uv run python scripts/build_packs.py           # download, verify and write the packs
    uv run python scripts/build_packs.py --check   # fail if a shipped pack is out of date

Each recipe names an archive at a pinned commit and its SHA-256, and selects a few Sysmon
events by exact field values. Selected records are kept verbatim except that the rendered
Message is dropped and numbers become strings (see tracebait.otrf).
"""

import argparse
import hashlib
import io
import sys
import urllib.request
import zipfile
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tracebait.field_registry import load_registry
from tracebait.models import Disposition, Incident
from tracebait.otrf import SYSMON_CHANNEL, read_records, sysmon_entry
from tracebait.packs import Pack, PackSource, pack_problems

ROOT = Path(__file__).resolve().parent.parent
PACKS_DIR = ROOT / "src" / "tracebait" / "data" / "packs"
OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
OTRF_HOST = f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}/datasets/atomic/windows"
DOWNLOAD_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class Select:
    """Sysmon events with this ID whose fields equal these values (case-insensitively)."""

    event_id: int
    where: Mapping[str, str]

    def matches(self, record: Mapping[str, Any]) -> bool:
        return record.get("EventID") == self.event_id and all(
            str(record.get(key, "")).casefold() == value.casefold()
            for key, value in self.where.items()
        )


@dataclass(frozen=True)
class Recipe:
    incident_id: str
    source: PackSource
    attack_technique: tuple[str, ...]
    disposition: Disposition
    select: tuple[Select, ...]


RUNDLL32 = "C:\\Windows\\System32\\rundll32.exe"
ESENTUTL = "C:\\Windows\\System32\\esentutl.exe"

CREDENTIAL_ACCESS = (
    Recipe(
        incident_id="otrf-lsass-dump-comsvcs",
        source=PackSource(
            id="OTRF:SDWIN-201018195009",
            title="Lsass Memory Dump via Comsvcs.dll",
            url=f"{OTRF_HOST}/credential_access/host/psh_lsass_memory_dump_comsvcs.zip",
            sha256="0af9e920220d746432f0972be83ad057629695540aecd68c15869d190786e1ae",
            commit=OTRF_COMMIT,
            licence="MIT",
        ),
        attack_technique=("T1003.001",),
        disposition=Disposition.MALICIOUS,
        select=(
            Select(1, {"Image": RUNDLL32}),
            Select(
                10, {"SourceImage": RUNDLL32, "TargetImage": "C:\\windows\\system32\\lsass.exe"}
            ),
            Select(
                11,
                {
                    "Image": RUNDLL32,
                    "TargetFilename": "C:\\Users\\wardog\\AppData\\Local\\Temp\\lsass-comsvcs.dmp",
                },
            ),
        ),
    ),
    Recipe(
        incident_id="otrf-sam-copy-esentutl",
        source=PackSource(
            id="OTRF:SDWIN-201019002900",
            title="SAM Copy via Esentutl VSS",
            url=f"{OTRF_HOST}/credential_access/host/cmd_sam_copy_esentutl.zip",
            sha256="f7a71135778aeff605abcb88a14a076f0814ab5cb136d07103bdf13c45551b64",
            commit=OTRF_COMMIT,
            licence="MIT",
        ),
        attack_technique=("T1003.002",),
        disposition=Disposition.MALICIOUS,
        select=(
            Select(1, {"Image": ESENTUTL}),
            Select(11, {"Image": ESENTUTL, "TargetFilename": "C:\\ProgramData\\SAM"}),
        ),
    ),
)

PACKS = {"otrf-credential-access": ("OTRF credential access", CREDENTIAL_ACCESS)}


def download(source: PackSource) -> bytes:
    if not source.url.startswith("https://"):
        raise ValueError(f"refusing non-HTTPS url {source.url}")
    with urllib.request.urlopen(source.url, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:  # noqa: S310 - https only, checked above
        data: bytes = response.read()
    digest = hashlib.sha256(data).hexdigest()
    if digest != source.sha256:
        raise ValueError(f"{source.url}: sha256 {digest}, expected {source.sha256}")
    return data


def records_in(archive: bytes) -> tuple[dict[str, Any], ...]:
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        (name,) = (n for n in zipped.namelist() if n.endswith(".json"))
        text = zipped.read(name).decode("utf-8")
    return read_records(text.splitlines())


def build_incident(recipe: Recipe) -> Incident:
    sysmon = [r for r in records_in(download(recipe.source)) if r.get("Channel") == SYSMON_CHANNEL]
    selected = [r for r in sysmon if any(s.matches(r) for s in recipe.select)]
    for rule in recipe.select:
        if not any(rule.matches(r) for r in selected):
            raise ValueError(f"{recipe.incident_id}: no record matches {rule}")
    selected.sort(key=lambda r: str(r.get("UtcTime", "")))
    return Incident(
        id=recipe.incident_id,
        source=recipe.source.id,
        attack_technique=recipe.attack_technique,
        entries=tuple(sysmon_entry(r) for r in selected),
        ground_truth_disposition=recipe.disposition,
    )


def build_pack(pack_id: str, title: str, recipes: tuple[Recipe, ...]) -> str:
    pack = Pack(
        version=1,
        id=pack_id,
        title=title,
        sources=tuple(r.source for r in recipes),
        incidents=tuple(build_incident(r) for r in recipes),
    )
    problems = pack_problems(pack, load_registry())
    if problems:
        raise ValueError(f"{pack_id}: " + "; ".join(problems))
    return pack.model_dump_json(indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args()
    stale = []
    for pack_id, (title, recipes) in PACKS.items():
        path = PACKS_DIR / f"{pack_id}.json"
        text = build_pack(pack_id, title, recipes)
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
