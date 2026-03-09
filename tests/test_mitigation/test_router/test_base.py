"""Tests for router adapter base class and factory function."""

from __future__ import annotations

import pytest

from goop_veil.config import RouterConfig
from goop_veil.mitigation.router.base import BaseRouterAdapter, create_router_adapter
from goop_veil.mitigation.router.mock import MockRouterAdapter


class TestBaseRouterAdapterABC:
    """BaseRouterAdapter cannot be instantiated directly."""

    def test_abc_cannot_instantiate(self):
        with pytest.raises(TypeError):
            BaseRouterAdapter()  # type: ignore[abstract]

    def test_mock_is_subclass(self):
        assert issubclass(MockRouterAdapter, BaseRouterAdapter)


class TestCreateRouterAdapter:
    """Factory function create_router_adapter."""

    def test_mock_type_returns_mock(self):
        config = RouterConfig(adapter_type="mock")
        adapter = create_router_adapter(config)
        assert isinstance(adapter, MockRouterAdapter)

    def test_none_type_returns_none(self):
        config = RouterConfig(adapter_type="none")
        result = create_router_adapter(config)
        assert result is None

    def test_openwrt_type_returns_adapter(self):
        config = RouterConfig(adapter_type="openwrt", host="192.168.1.1")
        adapter = create_router_adapter(config)
        assert isinstance(adapter, BaseRouterAdapter)
        assert adapter.adapter_type == "openwrt"

    def test_unifi_type_returns_adapter(self):
        config = RouterConfig(adapter_type="unifi", host="192.168.1.1")
        adapter = create_router_adapter(config)
        assert isinstance(adapter, BaseRouterAdapter)
        assert adapter.adapter_type == "unifi"

    def test_tplink_type_returns_adapter(self):
        config = RouterConfig(adapter_type="tplink", host="192.168.1.1")
        adapter = create_router_adapter(config)
        assert isinstance(adapter, BaseRouterAdapter)
        assert adapter.adapter_type == "tplink"

    def test_unknown_type_raises(self):
        config = RouterConfig(adapter_type="none")
        # Temporarily bypass frozen model to test unknown type
        # The factory handles known types; unknown types raise ValueError
        with pytest.raises(ValueError, match="Unknown"):
            # We can't create a config with invalid adapter_type due to Literal
            # So we test via the factory with a patched config
            from types import SimpleNamespace

            fake_config = SimpleNamespace(adapter_type="unknown_brand")
            create_router_adapter(fake_config)
