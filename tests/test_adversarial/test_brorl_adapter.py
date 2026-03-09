"""Tests for BroRLAdapter — Thompson sampling for adaptive privacy enhancement.

Validates ranking, outcome recording, posterior updates, state persistence,
and default priors.
"""

from __future__ import annotations

import json

import pytest

from goop_veil.adversarial.brorl_adapter import BroRLAdapter, TechniqueStats
from goop_veil.config import AdversarialConfig


class TestTechniqueStats:
    """TechniqueStats Beta distribution basics."""

    def test_default_priors(self):
        stats = TechniqueStats(name="test")
        assert stats.alpha == 1.0
        assert stats.beta == 1.0
        assert stats.success_rate == 0.5

    def test_success_rate_calculation(self):
        stats = TechniqueStats(name="test", alpha=9.0, beta=1.0)
        assert stats.success_rate == pytest.approx(0.9)

    def test_sample_in_range(self):
        stats = TechniqueStats(name="test")
        for _ in range(100):
            sample = stats.sample()
            assert 0.0 <= sample <= 1.0

    def test_to_dict(self):
        stats = TechniqueStats(name="test", alpha=2.0, beta=3.0)
        d = stats.to_dict()
        assert d["alpha"] == 2.0
        assert d["beta"] == 3.0
        assert "mean" in d


class TestRankTechniques:
    """Thompson sampling ranking."""

    def test_rank_returns_sorted(self):
        adapter = BroRLAdapter()
        techniques = ["tech_a", "tech_b", "tech_c"]
        ranked = adapter.rank_techniques(techniques)
        assert len(ranked) == 3
        # Sorted descending by sample score
        scores = [score for _, score in ranked]
        assert scores == sorted(scores, reverse=True)

    def test_rank_names_preserved(self):
        adapter = BroRLAdapter()
        techniques = ["alpha", "beta", "gamma"]
        ranked = adapter.rank_techniques(techniques)
        names = {name for name, _ in ranked}
        assert names == {"alpha", "beta", "gamma"}

    def test_rank_creates_posteriors(self):
        adapter = BroRLAdapter()
        adapter.rank_techniques(["new_tech"])
        alpha, beta = adapter.get_posterior("new_tech")
        assert alpha == 1.0
        assert beta == 1.0


class TestRecordOutcome:
    """Outcome recording updates posteriors."""

    def test_effective_increases_alpha(self):
        config = AdversarialConfig(brorl_learning_rate=0.1)
        adapter = BroRLAdapter(config=config)
        adapter.rank_techniques(["tech_a"])

        alpha_before, beta_before = adapter.get_posterior("tech_a")
        adapter.record_outcome("tech_a", effective=True)
        alpha_after, beta_after = adapter.get_posterior("tech_a")

        assert alpha_after > alpha_before
        assert beta_after == beta_before

    def test_ineffective_increases_beta(self):
        config = AdversarialConfig(brorl_learning_rate=0.1)
        adapter = BroRLAdapter(config=config)
        adapter.rank_techniques(["tech_a"])

        alpha_before, beta_before = adapter.get_posterior("tech_a")
        adapter.record_outcome("tech_a", effective=False)
        alpha_after, beta_after = adapter.get_posterior("tech_a")

        assert alpha_after == alpha_before
        assert beta_after > beta_before

    def test_many_successes_raise_success_rate(self):
        config = AdversarialConfig(brorl_learning_rate=0.5)
        adapter = BroRLAdapter(config=config)
        for _ in range(20):
            adapter.record_outcome("good_tech", effective=True)
        alpha, beta = adapter.get_posterior("good_tech")
        success_rate = alpha / (alpha + beta)
        assert success_rate > 0.8


class TestGetStats:
    """Statistics reporting format."""

    def test_stats_format(self, tmp_path):
        config = AdversarialConfig(brorl_state_path=str(tmp_path / "state.json"))
        adapter = BroRLAdapter(config=config)
        adapter.rank_techniques(["a", "b"])
        stats = adapter.get_stats()
        assert stats["backend"] == "bayesian"
        assert stats["num_techniques"] == 2
        assert "posteriors" in stats
        assert "a" in stats["posteriors"]
        assert "b" in stats["posteriors"]

    def test_stats_includes_learning_rate(self):
        config = AdversarialConfig(brorl_learning_rate=0.2)
        adapter = BroRLAdapter(config=config)
        stats = adapter.get_stats()
        assert stats["learning_rate"] == 0.2


class TestPersistence:
    """State persistence to disk and reload."""

    def test_save_and_reload(self, tmp_path):
        state_path = str(tmp_path / "brorl_state.json")
        config = AdversarialConfig(brorl_state_path=state_path)
        adapter = BroRLAdapter(config=config)

        # Record enough outcomes to trigger save (every 10)
        for i in range(10):
            adapter.record_outcome("persistent_tech", effective=True)

        # Verify file exists
        assert (tmp_path / "brorl_state.json").exists()

        # Create new adapter from same state file
        adapter2 = BroRLAdapter(config=config)
        alpha, beta = adapter2.get_posterior("persistent_tech")
        assert alpha > 1.0  # Should have loaded persisted state

    def test_no_state_file_starts_fresh(self, tmp_path):
        state_path = str(tmp_path / "nonexistent.json")
        config = AdversarialConfig(brorl_state_path=state_path)
        adapter = BroRLAdapter(config=config)
        stats = adapter.get_stats()
        assert stats["num_techniques"] == 0


class TestDefaultPriors:
    """Default Beta(1,1) priors for new techniques."""

    def test_new_technique_uniform_prior(self):
        adapter = BroRLAdapter()
        alpha, beta = adapter.get_posterior("never_seen")
        assert alpha == 1.0
        assert beta == 1.0
        assert alpha / (alpha + beta) == 0.5

    def test_get_posterior_creates_entry(self):
        adapter = BroRLAdapter()
        adapter.get_posterior("auto_created")
        stats = adapter.get_stats()
        assert "auto_created" in stats["posteriors"]
