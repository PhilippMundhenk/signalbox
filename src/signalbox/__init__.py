"""Signalbox: see, check and configure every device of a small network in one place.

Components (see docs/DESIGN.md, "Components"):

- network model: :mod:`signalbox.model`, :mod:`signalbox.merge`
- integrations: :mod:`signalbox.adapters` (API) and ``signalbox.adapters.<id>``
- inventory: :mod:`signalbox.store`, :mod:`signalbox.config`, :mod:`signalbox.secrets`
- observation: :mod:`signalbox.runner`
- checks: :mod:`signalbox.rules`
- topology: :mod:`signalbox.topology`
- interfaces: :mod:`signalbox.web`, :mod:`signalbox.mqtt`
- planned: ``signalbox.desired`` (desired state), ``signalbox.changes`` (planner),
  ``signalbox.deploy`` (transactional deployment, rollback), ``signalbox.history`` (change log)
"""

__version__ = "0.1.0.dev0"
