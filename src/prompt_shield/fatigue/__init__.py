"""Adversarial fatigue tracking — detect probing campaigns across scans.

See :class:`FatigueTracker` for the public API. The tracker is opt-in via
the ``fatigue.enabled`` config key; when disabled the module imposes zero
runtime cost on the scan path.
"""

from prompt_shield.fatigue.tracker import FatigueTracker

__all__ = ["FatigueTracker"]
