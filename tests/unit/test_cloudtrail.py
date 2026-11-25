import pytest

from tracebait.cloudtrail import cloudtrail_entry
from tracebait.models import LogSchema
from tracebait.records import RecordError

CREATE_ACCESS_KEY = {
    "eventVersion": "1.08",
    "userIdentity": {"type": "IAMUser", "userName": "bhavin_cli"},
    "eventName": "CreateAccessKey",
    "userAgent": "aws-cli/2.0.62 Python/3.9.0",
    "requestParameters": {"userName": "AtomicRedTeam"},
    "responseElements": {"accessKey": {"userName": "AtomicRedTeam", "status": "Active"}},
    "readOnly": False,
    "errorCode": None,
}


class TestCloudtrailEntry:
    def test_flattens_nested_objects_into_dotted_keys(self) -> None:
        entry = cloudtrail_entry(CREATE_ACCESS_KEY)

        assert entry.schema_name is LogSchema.CLOUDTRAIL
        assert entry.fields["requestParameters.userName"] == "AtomicRedTeam"
        assert entry.fields["userIdentity.type"] == "IAMUser"
        assert entry.fields["responseElements.accessKey.status"] == "Active"

    def test_writes_scalars_as_json_text(self) -> None:
        entry = cloudtrail_entry({**CREATE_ACCESS_KEY, "apiVersion": 2})

        assert entry.fields["readOnly"] == "false"
        assert entry.fields["apiVersion"] == "2"

    def test_drops_nulls_and_empty_objects(self) -> None:
        entry = cloudtrail_entry({**CREATE_ACCESS_KEY, "requestParameters": None, "tls": {}})

        assert "errorCode" not in entry.fields
        assert not any(key.startswith(("requestParameters", "tls")) for key in entry.fields)

    def test_writes_lists_as_compact_json(self) -> None:
        resources = [{"ARN": "arn:aws:iam::1:user/x", "type": "AWS::IAM::User"}]

        entry = cloudtrail_entry({**CREATE_ACCESS_KEY, "resources": resources})

        assert entry.fields["resources"] == (
            '[{"ARN":"arn:aws:iam::1:user/x","type":"AWS::IAM::User"}]'
        )

    def test_rejects_keys_that_collide_after_flattening(self) -> None:
        record = {**CREATE_ACCESS_KEY, "requestParameters.userName": "other"}

        with pytest.raises(RecordError, match=r"requestParameters\.userName"):
            cloudtrail_entry(record)
