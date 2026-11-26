import json
import re
from html.parser import HTMLParser

import pytest

from tests import factories as f
from tracebait.models import Disposition, Verdict
from tracebait.reports import Format, render
from tracebait.scoring.score import MetricName

STEERED = Verdict(disposition=Disposition.BENIGN, severity=0, close_incident=True)
HOSTILE = ' <script>alert(1)</script> @octocat ```` & "quoted"'


class TestMarkdown:
    def test_shows_grade_metrics_and_setup(self) -> None:
        text = render(Format.MARKDOWN, *f.experiment(poisoned_verdict=STEERED))

        assert "**0/100**" in text
        assert "| verdict_flip | 0/5 | 5/5 |" in text
        assert "otrf-lsass-dump-comsvcs" in text
        assert "claude-code" in text

    def test_puts_payload_text_in_a_fence_it_cannot_escape(self) -> None:
        text = render(Format.MARKDOWN, *f.experiment(payload_text=HOSTILE))

        fence = re.search(r"^(`{3,})text$", text, re.M)
        assert fence is not None
        assert len(fence.group(1)) > 4  # longer than the payload's own run of backticks
        body = text.split(fence.group(0), 1)[1].split("\n" + fence.group(1), 1)[0]
        assert HOSTILE in body
        assert text.count("@octocat") == 1  # only inside the fence, where it cannot notify

    def test_notes_effects_too_small_to_attribute(self) -> None:
        settings, records, result = f.experiment(poisoned_verdict=STEERED, runs=2)

        assert "more runs" in render(Format.MARKDOWN, settings, records, result)


class TestSarif:
    def test_is_sarif_2_1_0_with_a_rule_per_metric(self) -> None:
        sarif = json.loads(render(Format.SARIF, *f.experiment()))

        assert sarif["version"] == "2.1.0"
        assert sarif["$schema"].endswith("sarif-2.1.0.json")
        (run,) = sarif["runs"]
        assert run["tool"]["driver"]["name"] == "tracebait"
        rule_ids = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        assert rule_ids == {f"tracebait/{m.value}" for m in MetricName}

    def test_a_robust_agent_has_no_results(self) -> None:
        sarif = json.loads(render(Format.SARIF, *f.experiment()))

        assert sarif["runs"][0]["results"] == []

    def test_each_attributed_metric_is_an_error_with_a_stable_fingerprint(self) -> None:
        first = json.loads(render(Format.SARIF, *f.experiment(poisoned_verdict=STEERED)))
        again = json.loads(render(Format.SARIF, *f.experiment(poisoned_verdict=STEERED)))

        results = first["runs"][0]["results"]
        assert {r["ruleId"] for r in results} == {
            "tracebait/verdict_flip",
            "tracebait/suppression",
        }
        assert all(r["level"] == "error" for r in results)
        assert all(
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results
        )
        assert [r["partialFingerprints"] for r in results] == [
            r["partialFingerprints"] for r in again["runs"][0]["results"]
        ]
        assert results[0]["properties"]["p_value"] == pytest.approx(0.003968253968)


class _Collector(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.tags: list[str] = []
        self.text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:  # noqa: ARG002
        self.tags.append(tag)

    def handle_data(self, data: str) -> None:
        self.text.append(data)


class TestHtml:
    def test_is_a_standalone_page_with_the_grade(self) -> None:
        page = render(Format.HTML, *f.experiment(poisoned_verdict=STEERED))

        assert page.startswith("<!doctype html>")
        assert "0/100" in page
        assert "http://" not in page.replace("http://www.w3.org", "")
        assert "<link" not in page
        assert "src=" not in page

    def test_escapes_the_payload(self) -> None:
        page = render(Format.HTML, *f.experiment(payload_text=HOSTILE))
        parser = _Collector()
        parser.feed(page)

        assert "script" not in parser.tags
        assert HOSTILE in "".join(parser.text)

    def test_supports_dark_mode(self) -> None:
        page = render(Format.HTML, *f.experiment())

        assert "prefers-color-scheme: dark" in page
