"""Regressions from the WorkBuddy development-instance user trial."""
from __future__ import annotations

import copy

import pytest

from src import config, oauth_manager as om
from src.channel import registry
from src.oauth.workbuddy import billing
from src.tests.test_workbuddy_lifecycle import account


def test_package_deduction_expiry_is_milliseconds_not_cycle_boundary():
    package = billing.normalize_package({
        "PackageName": "赠送包", "CycleCapacitySize": 1500, "CycleCapacityRemain": 1500,
        "CycleStartTime": "2026-09-07 19:14:17", "CycleEndTime": "2026-10-07 19:14:16",
        "DeductionEndTime": 1791371656000,
    }, "cn")
    assert package["expires_at"] == "2026-10-07T11:14:16Z"
    assert package["cycle_end"] == "2026-10-07T11:14:16Z"
    recurring = billing.normalize_package({
        "CycleCapacitySize": 500, "CycleCapacityRemain": 500,
        "CycleEndTime": "2026-09-30 23:59:59", "DeductionEndTime": 2049102854000,
    }, "cn")
    assert recurring["expires_at"] != recurring["cycle_end"]
    assert recurring["cycle_end"] == "2026-09-30T15:59:59Z"


@pytest.mark.parametrize("invalid", [None, "", "not-a-date", -1, 0, True, 10**30])
def test_missing_or_invalid_deduction_expiry_is_not_invented(invalid):
    package = billing.normalize_package({"DeductionEndTime": invalid, "CycleEndTime": "2026-09-30 23:59:59"}, "cn")
    assert package["expires_at"] is None


def test_explicit_package_expiry_keeps_precedence():
    package = billing.normalize_package({
        "PackageEndTime": "2026-10-01 00:00:00", "DeductionEndTime": 1791371656000,
    }, "cn")
    assert package["expires_at"] == "2026-09-30T16:00:00Z"


def test_deleted_oauth_identity_can_be_added_again_without_restart(account):
    entry = copy.deepcopy(om.get_account(account))
    config.update(lambda c: c["oauthAccounts"][0].update(models=["fixture-model"]))
    registry.rebuild_from_config()
    assert registry.get_channel("oauth:" + account) is not None
    om.delete_account(account)
    assert om.get_account(account) is None
    entry.update(access_token="new-fixture-at", refresh_token="new-fixture-rt", models=["fixture-model"])
    assert om.add_account_if_identity_absent(entry)["status"] == "added"
    registry.rebuild_from_config()
    assert registry.get_channel("oauth:" + account) is not None
    assert om.get_account(account)["access_token"] == "new-fixture-at"
