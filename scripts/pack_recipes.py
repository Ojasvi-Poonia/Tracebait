"""Recipes for the shipped incident packs: which upstream events each incident holds.

Every source is pinned to an upstream commit and the SHA-256 of the file at that commit.
A Select keeps the converted entries whose fields equal its values (case-insensitively)
and drops the named fields from them, for copies the record echoes of its own values.
"""

from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum

from tracebait.models import Disposition
from tracebait.packs import PackSource


class Format(StrEnum):
    OTRF_ZIP = "otrf_zip"  # a zip holding one JSON Lines export of Windows event logs
    CLOUDTRAIL_JSONL = "cloudtrail_jsonl"  # one CloudTrail record per line


@dataclass(frozen=True)
class Select:
    where: Mapping[str, str]
    drop: frozenset[str] = field(default_factory=frozenset)

    def matches(self, fields: Mapping[str, str]) -> bool:
        return all(
            fields.get(key, "").casefold() == value.casefold() for key, value in self.where.items()
        )


@dataclass(frozen=True)
class Recipe:
    incident_id: str
    source: PackSource
    format: Format
    attack_technique: tuple[str, ...]
    disposition: Disposition
    order_by: str  # the timestamp field entries are sorted on
    select: tuple[Select, ...]


@dataclass(frozen=True)
class PackRecipe:
    title: str
    recipes: tuple[Recipe, ...]


OTRF_COMMIT = "d9d40ef123d2c87d5d3df28c96bcab4f0faccc87"
OTRF_HOST = (
    f"https://raw.githubusercontent.com/OTRF/Security-Datasets/{OTRF_COMMIT}"
    "/datasets/atomic/windows"
)
SPLUNK_COMMIT = "68ab23c7527fa826ed4986c7bab7e3d18ec20eaf"
# attack_data stores datasets in Git LFS; this host serves the LFS object at a commit.
SPLUNK_HOST = (
    f"https://media.githubusercontent.com/media/splunk/attack_data/{SPLUNK_COMMIT}"
    "/datasets/attack_techniques"
)

RUNDLL32 = "C:\\Windows\\System32\\rundll32.exe"
ESENTUTL = "C:\\Windows\\System32\\esentutl.exe"
LSASS = "C:\\windows\\system32\\lsass.exe"
LSASS_DUMP = "C:\\Users\\wardog\\AppData\\Local\\Temp\\lsass-comsvcs.dmp"

OTRF_CREDENTIAL_ACCESS = PackRecipe(
    title="OTRF credential access",
    recipes=(
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
            format=Format.OTRF_ZIP,
            attack_technique=("T1003.001",),
            disposition=Disposition.MALICIOUS,
            order_by="UtcTime",
            select=(
                Select({"EventID": "1", "Image": RUNDLL32}),
                Select({"EventID": "10", "SourceImage": RUNDLL32, "TargetImage": LSASS}),
                Select({"EventID": "11", "Image": RUNDLL32, "TargetFilename": LSASS_DUMP}),
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
            format=Format.OTRF_ZIP,
            attack_technique=("T1003.002",),
            disposition=Disposition.MALICIOUS,
            order_by="UtcTime",
            select=(
                Select({"EventID": "1", "Image": ESENTUTL}),
                Select(
                    {"EventID": "11", "Image": ESENTUTL, "TargetFilename": "C:\\ProgramData\\SAM"}
                ),
            ),
        ),
    ),
)

SPLUNK_AWS_IAM = PackRecipe(
    title="splunk/attack_data AWS IAM",
    recipes=(
        Recipe(
            incident_id="splunk-aws-createaccesskey",
            source=PackSource(
                id="splunk-attack-data:T1078/aws_createaccesskey",
                title="AWS CreateAccessKey for another user",
                url=f"{SPLUNK_HOST}/T1078/aws_createaccesskey/aws_cloudtrail_events.json",
                sha256="88c3aadd3cd9afc4db25fecd488b7eced3b1e0160f1f20592c043b327e853a8e",
                commit=SPLUNK_COMMIT,
                licence="Apache-2.0",
            ),
            format=Format.CLOUDTRAIL_JSONL,
            attack_technique=("T1078",),
            disposition=Disposition.MALICIOUS,
            order_by="eventTime",
            select=(
                Select(
                    {"eventID": "5772e8d5-cccc-470d-81ef-acacfe85a804"},
                    drop=frozenset({"responseElements.accessKey.userName"}),
                ),
            ),
        ),
        Recipe(
            incident_id="splunk-aws-createloginprofile",
            source=PackSource(
                id="splunk-attack-data:T1078/aws_createloginprofile",
                title="AWS CreateLoginProfile for another user, then console login",
                url=f"{SPLUNK_HOST}/T1078/aws_createloginprofile/aws_cloudtrail_events.json",
                sha256="6825bd4e351d0bec876dd146dd0731c27b99b571c88cb6fea91dd0d447810d52",
                commit=SPLUNK_COMMIT,
                licence="Apache-2.0",
            ),
            format=Format.CLOUDTRAIL_JSONL,
            attack_technique=("T1078",),
            disposition=Disposition.MALICIOUS,
            order_by="eventTime",
            select=(
                Select(
                    {"eventID": "2ae5bd94-c6dc-4b78-b2bb-0c8749eaad08"},
                    drop=frozenset({"responseElements.loginProfile.userName"}),
                ),
                Select({"eventID": "8a01edb7-fbd0-4ac6-96a2-8867a6bd2540"}),
            ),
        ),
    ),
)

PACKS = {
    "otrf-credential-access": OTRF_CREDENTIAL_ACCESS,
    "splunk-aws-iam": SPLUNK_AWS_IAM,
}
