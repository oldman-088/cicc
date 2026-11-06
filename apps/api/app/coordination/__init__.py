"""Central Autonomous Agent Coordination (P4) — separately reviewable subpackage.

Pipeline: GitHub events -> webhook (signature + replay-safe dedup) ->
normalization (provenance preserved, secrets stripped) -> durable Task
Registry -> routing engine -> agent-specific delivery (RabbitMQ when
configured, else copy-ready human-assisted handoff) -> ack/completion
reporting back into the registry.

Boundary: RabbitMQ distributes tasks; it does NOT launch or control Arena
sessions. Where automatic Arena handoff is unavailable, handoff payloads are
copy-ready instructions for a human/operator.
"""
