"""BroRL adapter — Thompson sampling for adaptive privacy enhancement.

Uses Beta distribution posteriors (same as goop-shield bayesian.py) to
learn which privacy enhancement techniques are most effective against
different WiFi sensing systems.

Techniques are rated by their ability to degrade sensing accuracy
while maintaining FCC compliance and minimal WiFi impact.
"""

from __future__ import annotations

import json
import logging
import random
from pathlib import Path

from goop_veil.config import AdversarialConfig

logger = logging.getLogger(__name__)


class TechniqueStats:
    """Beta distribution posterior for a privacy enhancement technique."""

    __slots__ = ("name", "alpha", "beta")

    def __init__(self, name: str, alpha: float = 1.0, beta: float = 1.0) -> None:
        self.name = name
        self.alpha = alpha
        self.beta = beta

    @property
    def success_rate(self) -> float:
        return self.alpha / (self.alpha + self.beta)

    def sample(self) -> float:
        """Thompson sample from the posterior."""
        return random.betavariate(self.alpha, self.beta)

    def to_dict(self) -> dict:
        return {
            "alpha": self.alpha,
            "beta": self.beta,
            "mean": round(self.success_rate, 4),
        }


class BroRLAdapter:
    """Adaptive defense technique selection using BroRL Beta distributions.

    Follows the same pattern as goop-shield's BayesianRankingBackend.
    """

    def __init__(self, config: AdversarialConfig | None = None) -> None:
        self._config = config or AdversarialConfig()
        self._lr = self._config.brorl_learning_rate
        self._posteriors: dict[str, TechniqueStats] = {}
        self._outcome_count = 0
        self._state_path = Path(self._config.brorl_state_path)

        # Try to load persisted state
        self._load_from_disk()

    def rank_techniques(self, technique_names: list[str]) -> list[tuple[str, float]]:
        """Rank techniques by Thompson sampling (highest = best).

        Returns list of (technique_name, sample_score) sorted descending.
        """
        ranked = []
        for name in technique_names:
            stats = self._get_or_create(name)
            ranked.append((name, stats.sample()))
        ranked.sort(key=lambda x: x[1], reverse=True)
        return ranked

    def record_outcome(self, technique_name: str, effective: bool) -> None:
        """Record whether a technique was effective at degrading sensing.

        Args:
            technique_name: Name of the technique used.
            effective: True if sensing accuracy was degraded.
        """
        stats = self._get_or_create(technique_name)

        if effective:
            stats.alpha += self._lr
        else:
            stats.beta += self._lr

        self._outcome_count += 1

        # Persist every 10 outcomes (same pattern as goop-shield)
        if self._outcome_count % 10 == 0:
            self._save_to_disk()

        logger.debug(
            "BroRL: %s %s → α=%.2f β=%.2f (mean=%.3f)",
            technique_name,
            "effective" if effective else "ineffective",
            stats.alpha,
            stats.beta,
            stats.success_rate,
        )

    def get_stats(self) -> dict:
        """Get current posterior statistics."""
        return {
            "backend": "bayesian",
            "num_techniques": len(self._posteriors),
            "learning_rate": self._lr,
            "posteriors": {
                name: stats.to_dict() for name, stats in self._posteriors.items()
            },
        }

    def get_posterior(self, name: str) -> tuple[float, float]:
        """Get (alpha, beta) for a technique."""
        stats = self._get_or_create(name)
        return (stats.alpha, stats.beta)

    def _get_or_create(self, name: str) -> TechniqueStats:
        if name not in self._posteriors:
            self._posteriors[name] = TechniqueStats(name)
        return self._posteriors[name]

    def _save_to_disk(self) -> None:
        """Persist posteriors to disk (atomic write)."""
        try:
            self._state_path.parent.mkdir(parents=True, exist_ok=True)
            data = {
                name: stats.to_dict() for name, stats in self._posteriors.items()
            }
            tmp = self._state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(data, indent=2))
            tmp.replace(self._state_path)
            logger.debug("BroRL state saved to %s", self._state_path)
        except Exception:
            logger.exception("Failed to save BroRL state")

    def _load_from_disk(self) -> None:
        """Load persisted posteriors from disk."""
        if not self._state_path.exists():
            return
        try:
            data = json.loads(self._state_path.read_text())
            for name, vals in data.items():
                self._posteriors[name] = TechniqueStats(
                    name=name,
                    alpha=vals.get("alpha", 1.0),
                    beta=vals.get("beta", 1.0),
                )
            logger.info("BroRL state loaded: %d techniques", len(self._posteriors))
        except Exception:
            logger.exception("Failed to load BroRL state")
