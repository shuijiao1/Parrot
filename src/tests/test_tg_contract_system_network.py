"""Strict v0.31.13 network and monitor traces for TG-SYS-06/07."""
from __future__ import annotations

import pytest

from src.telegram import states
from src.telegram.menus import system_menu as sm
from src.tests.test_tg_contract_system_helpers import cases_for, run_and_compare

CASES = cases_for("TG-SYS-06", "TG-SYS-07")


def _network_menu(e):
    e.callback("sys:show:network")
    e.callback("sys:net:edit_dns")
    e.callback("sys:show:network", "dns-cancel-via-back")


def _dns_success(e):
    e.callback("sys:net:edit_dns")
    e.text("sys_net_dns", "bad-dns")
    e.text("sys_net_dns", "1.1.1.1, 8.8.8.8")
    e.callback("sys:net:dns_save")


def _dns_force(e):
    e.callback("sys:net:edit_dns")
    e.text("sys_net_dns", "9.9.9.9")
    e.callback("sys:net:dns_save", "failed-test-normal-save-blocked")
    e.callback("sys:net:dns_save_force")


def _dns_test_exception(e):
    e.callback("sys:net:edit_dns")
    e.text("sys_net_dns", "1.0.0.1")


def _dns_save_failure(e):
    e.callback("sys:net:dns_save_force")


def _dns_expired(e):
    e.advance(601)
    e.callback("sys:net:dns_save_force")


def _dns_sync(e):
    e.callback("sys:net:sync_dns")


def _dns_cache(e):
    e.callback("sys:net:dns_cache")
    e.callback("sys:net:dns_cache_clear")


def _socks_success(e):
    e.callback("sys:net:edit_socks5")
    e.text("sys_net_socks5", "bad-socks")
    e.text("sys_net_socks5", "user:test-only@proxy.invalid:1080")
    e.callback("sys:net:socks5_save")
    e.callback("sys:net:toggle_socks5")


def _socks_force(e):
    e.callback("sys:net:edit_socks5")
    e.text("sys_net_socks5", "socks5://proxy.invalid:1080")
    e.callback("sys:net:socks5_save", "failed-test-normal-save-blocked")
    e.callback("sys:net:socks5_save_force")


def _socks_test_exception(e):
    e.callback("sys:net:edit_socks5")
    e.text("sys_net_socks5", "proxy.invalid:1080")


def _socks_save_failure(e):
    e.callback("sys:net:socks5_save_force")


def _socks_expired(e):
    e.advance(601)
    e.callback("sys:net:socks5_save_force")


def _socks_no_url(e):
    e.callback("sys:net:toggle_socks5")


def _monitor_menu_toggles(e):
    e.callback("sys:mon:show")
    e.callback("sys:mon:history", "unavailable-separate-history-entry")
    for key in ("enabled", "dns", "socks5", "unknown"):
        e.callback("sys:mon:toggle:" + key)


def _monitor_interval(e):
    e.callback("sys:mon:edit_interval")
    e.text("sys_mon_interval", "bad")
    e.text("sys_mon_interval", "4")
    e.text("sys_mon_interval", "15")


def _monitor_core(e):
    e.callback("sys:mon:core")
    for key in ("openai", "claude", "cloudflare", "unknown"):
        e.callback("sys:mon:core_toggle:" + key)


def _monitor_channels(e):
    e.callback("sys:mon:channels")
    e.callback("sys:mon:channels_toggle")
    last = e.capture.calls[-1]["payload"]
    buttons = [b for row in last["reply_markup"]["inline_keyboard"] for b in row]
    toggle = next((b["callback_data"] for b in buttons if b["callback_data"].startswith("sys:mon:ch_toggle:")), None)
    if toggle:
        e.callback(toggle)
    e.callback("sys:mon:ch_toggle:deadbeef", "expired-channel-short-code")


def _monitor_run(e):
    e.callback("sys:mon:run_now")


RUNNERS = {
    "network_menu": _network_menu,
    "dns_success": _dns_success,
    "dns_force": _dns_force,
    "dns_test_exception": _dns_test_exception,
    "dns_save_failure": _dns_save_failure,
    "dns_expired": _dns_expired,
    "dns_sync": _dns_sync,
    "dns_cache": _dns_cache,
    "socks_success": _socks_success,
    "socks_force": _socks_force,
    "socks_test_exception": _socks_test_exception,
    "socks_save_failure": _socks_save_failure,
    "socks_expired": _socks_expired,
    "socks_no_url": _socks_no_url,
    "monitor_menu_toggles": _monitor_menu_toggles,
    "monitor_interval": _monitor_interval,
    "monitor_core": _monitor_core,
    "monitor_channels": _monitor_channels,
    "monitor_run": _monitor_run,
}


@pytest.mark.parametrize("case", CASES, ids=lambda case: case["caseId"])
def test_system_network_trace(case, monkeypatch):
    run_and_compare(case, monkeypatch, RUNNERS[case["entry"]["scenario"]])
