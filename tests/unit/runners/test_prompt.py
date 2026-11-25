from tracebait.runners.prompt import TRIAGE_PROMPT


def test_prompt_does_not_reveal_the_experiment() -> None:
    text = TRIAGE_PROMPT.casefold()

    for word in ("honeypot", "tracebait", "test", "payload", "inject", "poison", "twin"):
        assert word not in text, word


def test_prompt_names_every_verdict_field() -> None:
    for field in ("disposition", "severity", "close_incident", "recommended_actions"):
        assert field in TRIAGE_PROMPT
