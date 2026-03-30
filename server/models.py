"""
server/models.py — Typed Pydantic models for the OpenEnv interface.

OpenEnv requires three typed models: Action, Observation, Reward.
All models use Pydantic v2.
"""

from __future__ import annotations
from pydantic import BaseModel, Field


class ActionParameters(BaseModel):
    """Flexible parameter bag — different action types use different fields."""
    service: str | None = None
    severity: str | None = None
    failure_mode: str | None = None
    summary: str | None = None
    target_version: str | None = None
    replicas: int | None = None
    flag: str | None = None
    runbook_action: str | None = None
    target: str | None = None
    reasoning: str | None = None

    model_config = {"extra": "allow"}


class Action(BaseModel):
    """An action submitted by the agent to the environment."""
    action_type: str
    parameters: ActionParameters = Field(default_factory=ActionParameters)

    model_config = {"extra": "allow"}


class Observation(BaseModel):
    """Observation returned after reset() or step()."""
    episode_id: str
    task_id: str
    scenario_id: str
    step_count: int
    max_steps: int
    incident_summary: str
    alert: dict
    available_actions: list[str]
    queried_data: dict
    cumulative_reward: float
    done: bool
    feedback: str


class Reward(BaseModel):
    """Reward signal returned after each step()."""
    value: float
    reason: str
    cumulative: float


class EpisodeState(BaseModel):
    """Full episode state returned by GET /state."""
    episode_id: str
    task_id: str
    scenario_id: str
    step_count: int
    max_steps: int
    action_history: list[dict]
    queried_data: dict
    submitted: bool
    resolved: bool
    done: bool
    cumulative_reward: float
    feedback: str
