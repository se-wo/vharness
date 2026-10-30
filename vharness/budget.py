"""Budget accounting (SPEC 10): per-target invocation caps, run-wide USD cap, reserves."""

import math

RECON_CALLS = 3


class Budget:
    def __init__(self, store, run_id, cfg):
        self.store = store
        self.run_id = run_id
        self.cfg = cfg
        self.inflight = {}

    def begin(self, target):
        """Count an agent as spent from the moment it starts, so concurrent tasks cannot overrun the cap."""
        self.inflight[target] = self.inflight.get(target, 0) + 1

    def end(self, target):
        self.inflight[target] -= 1

    def spent(self, target):
        return self.store.invocation_count(self.run_id, target) + self.inflight.get(target, 0)

    def remaining(self, target):
        if self.cfg.budget is None:
            return math.inf
        return self.cfg.budget - self.spent(target)

    def usd_exhausted(self):
        return self.cfg.max_usd is not None and self.store.cost(self.run_id) >= self.cfg.max_usd

    def can_spend(self, target, n=1):
        return not self.usd_exhausted() and self.remaining(target) >= n

    def hunt_allowed(self, target):
        """A hunter may start only if the critic and validation reserves stay funded (SPEC 10.2)."""
        if self.usd_exhausted():
            return False
        remaining = self.remaining(target)
        if remaining == math.inf:
            return True
        after_critic = remaining - 1
        reserve = 1 + math.ceil(self.cfg.validation_reserve * max(after_critic, 0))
        return remaining - reserve >= 1

    def minimum_fundable(self):
        """R-BUD-01: recon + one critic + one validator per target."""
        return self.cfg.budget is None or self.cfg.budget >= RECON_CALLS + 2
