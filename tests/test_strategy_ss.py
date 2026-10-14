"""Routing and credit arithmetic against the actual kit prices."""
from agent.strategy import BudgetPacer, disciplined_round_cost, pick_replica


def test_known_drift_does_not_make_canonical_the_fresh_route():
    assert pick_replica(path_id="d8f95a7b", known_drifting=True).replica == "w"


def test_current_disciplined_plan_finishes_ten_rounds_without_bankruptcy():
    pacer = BudgetPacer()
    for round_number in range(1, 11):
        pacer.record_spend(round_number, disciplined_round_cost())
    assert pacer.credits_left == 10
    assert pacer.bankrupt_by() is None
    assert not pacer.is_affordable(10, -20)
