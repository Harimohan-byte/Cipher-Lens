"""Policy enforcement, scope boundary registry, and authorization gates."""

from cipher_lens.policy.action_classes import ActionClass
from cipher_lens.policy.approvals import (
    ApprovalError,
    ApprovalManager,
    ApprovalRejectedError,
    ApprovalRequiredError,
    requires_per_step_approval,
    requires_plan_approval,
)
from cipher_lens.policy.gate import Decision, PolicyGate, parse_target
from cipher_lens.policy.scope import Scope, ScopeRegistry

__all__ = [
    "ActionClass",
    "ApprovalError",
    "ApprovalManager",
    "ApprovalRejectedError",
    "ApprovalRequiredError",
    "Decision",
    "PolicyGate",
    "Scope",
    "ScopeRegistry",
    "parse_target",
    "requires_per_step_approval",
    "requires_plan_approval",
]
