"""Budget accounting (SPEC 10): per-target invocation caps, run-wide USD cap, reserves."""

import math

RECON_CALLS = 3


class Budget:
    def __init__(self, store, run_id, cfg):
        self.store = store
        self.run_id = run_id
        self.cfg = cfg
        self.inflight = {}
        self.active_hunts = {}  # target -> task ids of hunters that passed the gate and have not reported yet

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

    def per_candidate(self):
        """Calls one candidate needs after it is found: validate, trace, and verify unless merged."""
        return 2 + (1 if self.cfg.prof.separate_verify else 0) + (1 if self.cfg.fix else 0)

    def downstream_demand(self, target, exclude_task=None):
        """Agent calls still owed to work already found or being found (SPEC 10.2 step 4).

        Each other running hunter counts as one expected candidate, because concurrent
        hunters cannot see each other's results yet.
        """
        verify = 1 if self.cfg.prof.separate_verify else 0
        others = self.active_hunts.get(target, set()) - {exclude_task}
        demand = len(others) * self.per_candidate()
        for c in self.store.candidates(self.run_id, target, ["pending", "dedup_pending", "primary"]):
            demand += 2 + verify + (1 if c["status"] == "dedup_pending" else 0)
        for r in self.store.records(self.run_id, target, ["confirmed", "needs_validation"]):
            if not r["final"]:
                demand += (0 if r["reachability"] else 1) + verify
        return demand

    def hunt_allowed(self, target, task_id=None):
        """A hunter may start only if it, its expected candidate, the critic, the open demand and the reserve stay funded."""
        if self.usd_exhausted():
            return False
        remaining = self.remaining(target)
        if remaining == math.inf:
            return True
        demand = self.downstream_demand(target, exclude_task=task_id)
        after = remaining - 1 - demand
        reserve = 1 + demand + math.ceil(self.cfg.validation_reserve * max(after, 0))
        if remaining - reserve >= 1 + self.per_candidate():
            self.active_hunts.setdefault(target, set()).add(task_id)
            return True
        return False

    def hunt_done(self, target, task_id):
        self.active_hunts.get(target, set()).discard(task_id)

    def minimum_fundable(self):
        """R-BUD-01: recon + one critic + one validator per target."""
        return self.cfg.budget is None or self.cfg.budget >= RECON_CALLS + 2
