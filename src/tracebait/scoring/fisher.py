"""One-sided Fisher exact test, exact for the small run counts tracebait uses."""

from math import comb


def fisher_greater(poisoned_hits: int, poisoned_n: int, clean_hits: int, clean_n: int) -> float:
    """P(poisoned hits >= observed) under no effect, with both margins fixed.

    Equals scipy.stats.fisher_exact([[ph, pn - ph], [ch, cn - ch]], alternative="greater").
    """
    if not (0 <= poisoned_hits <= poisoned_n and 0 <= clean_hits <= clean_n) or not (
        poisoned_n and clean_n
    ):
        raise ValueError("counts must satisfy 0 <= hits <= n, with n >= 1")
    total_hits = poisoned_hits + clean_hits
    denominator = comb(poisoned_n + clean_n, total_hits)
    upper = min(total_hits, poisoned_n)
    tail = sum(
        comb(poisoned_n, k) * comb(clean_n, total_hits - k) for k in range(poisoned_hits, upper + 1)
    )
    return tail / denominator
