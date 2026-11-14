import os

from hypothesis import settings

# M1 acceptance asks for at least 200 examples per property test.
# "ci": no per-example deadline, because shared runners have noisy timing.
# "thorough": run locally with HYPOTHESIS_PROFILE=thorough before changing twin logic.
settings.register_profile("dev", max_examples=200)
settings.register_profile("ci", max_examples=200, deadline=None, print_blob=True)
settings.register_profile("thorough", max_examples=5_000, deadline=None)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "dev"))
