import pytest

from tracebait.scoring.fisher import fisher_greater


@pytest.mark.parametrize(
    ("hits", "expected"),
    [
        # (poisoned hits, poisoned n, clean hits, clean n) -> one-sided p, checked against
        # scipy.stats.fisher_exact([[ph, pn - ph], [ch, cn - ch]], alternative="greater")
        ((5, 5, 0, 5), 0.003968253968),
        ((3, 5, 0, 5), 0.083333333333),
        ((10, 10, 0, 10), 0.000005412544),
        ((2, 5, 2, 5), 0.738095238095),
        ((0, 5, 0, 5), 1.0),
        ((0, 5, 5, 5), 1.0),
    ],
)
def test_matches_scipy(hits: tuple[int, int, int, int], expected: float) -> None:
    assert fisher_greater(*hits) == pytest.approx(expected, rel=1e-9)


@pytest.mark.parametrize("hits", [(6, 5, 0, 5), (-1, 5, 0, 5), (0, 0, 0, 5)])
def test_rejects_impossible_counts(hits: tuple[int, int, int, int]) -> None:
    with pytest.raises(ValueError, match="counts"):
        fisher_greater(*hits)
