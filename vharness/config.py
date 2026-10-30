"""Run configuration and profiles (SPEC 9.2, 9.3, 10)."""

from dataclasses import asdict, dataclass, field

DISCOVERY_ROLES = ("recon", "hunter", "critic", "dedup", "tracer")
VALIDATION_ROLES = ("validator", "verifier")


@dataclass(frozen=True)
class Profile:
    name: str
    max_waves: int
    units_per_hunter: int
    separate_verify: bool
    shallow_requeue: bool
    single_subsystem: bool


PROFILES = {
    "quick": Profile("quick", max_waves=1, units_per_hunter=4, separate_verify=False, shallow_requeue=False, single_subsystem=True),
    "standard": Profile("standard", max_waves=3, units_per_hunter=3, separate_verify=True, shallow_requeue=True, single_subsystem=False),
    "deep": Profile("deep", max_waves=5, units_per_hunter=2, separate_verify=True, shallow_requeue=True, single_subsystem=False),
}


@dataclass
class Config:
    profile: str = "standard"
    budget: int | None = None  # max agent invocations per target
    max_usd: float | None = None  # max USD for the whole run
    concurrency: int = 8
    discovery_model: str = "claude-opus-5-5"
    validation_model: str = "claude-sonnet-5-5"
    role_models: dict = field(default_factory=dict)
    allow_same_model: bool = False
    scope: list = field(default_factory=list)
    prior: str | None = None
    backend: str = "claude"
    effort: str | None = "high"
    context_window: int = 1_000_000
    context_windows: dict = field(default_factory=dict)
    context_fraction: float = 0.25
    max_turns: int = 60
    agent_timeout_s: int = 1800
    shallow_min_checks: int = 2
    shallow_min_turns: int = 4
    max_siblings_per_result: int = 2
    max_classes_per_surface: int = 4
    max_boundaries_per_surface: int = 2
    max_custom_classes: int = 6
    dedup_shortlist_max: int = 8
    rejection_notes_per_class: int = 5
    validation_reserve: float = 0.30

    @property
    def prof(self):
        return PROFILES[self.profile]

    def model_for(self, role):
        if role in self.role_models:
            return self.role_models[role]
        return self.validation_model if role in VALIDATION_ROLES else self.discovery_model

    def context_limit_tokens(self, model):
        window = self.context_windows.get(model, self.context_window)
        return int(window * self.context_fraction)

    def validate(self):
        if self.profile not in PROFILES:
            raise ValueError(f"unknown profile {self.profile!r}")
        if self.concurrency < 1:
            raise ValueError("concurrency must be at least 1")
        if not 0 < self.context_fraction <= 1:
            raise ValueError("context fraction must be in (0, 1]")
        if not self.allow_same_model:
            disc = {self.model_for(r) for r in DISCOVERY_ROLES}
            val = {self.model_for(r) for r in VALIDATION_ROLES}
            if disc & val:
                raise ValueError(
                    "validation model must differ from the discovery model (R-MOD-03); "
                    "pass --allow-same-model to override"
                )
        if self.budget is not None and self.budget < 5:
            raise ValueError("budget must fund 3 recon, 1 critic and 1 validator per target (R-BUD-01)")

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        return cls(**known)
