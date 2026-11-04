# Open-Source Research & Reuse Decisions — Central Coordination (M8)

Sources reviewed 2026-11-04 (web research; licenses per project docs). Decision rule: reuse/adapt only what removes real risk; do not import a platform wholesale into a multi-agent repo where agents own separate branches.

## Task queues / brokers

| Candidate | License | Verdict | Rationale |
|---|---|---|---|
| Celery (Redis/Rabbit/SQS) | BSD | **Adapt patterns, don't adopt** | Mature retry/canvas/DLQ patterns; but heavyweight for our scale and would add a second broker abstraction. We already use RabbitMQ directly via pika. |
| Dramatiq | MIT-like | **Adapt patterns** | "durable quorum queues + publisher confirms + tuned retries" matches our M7 delivery design (we implemented durable queue + persistent msg + confirm_delivery). Quorum queues need a cluster — noted for production runbook, not applicable to single-node verify. |
| Taskiq / FastStream | MIT | **No** | asyncio-native but adds dependency without unique value here. |
| Temporal / Inngest / Restate | various | **No (now)** | Durable workflow engines are the right answer for long-lived multi-step sagas and human-in-the-loop waits; our task registry + approvals already cover our current need at far lower ops cost. Re-evaluate if workflows span days with durable pause/resume. Their waitForEvent ≈ our WAITING_FOR_APPROVAL. |
| RabbitMQ itself | MPL-2.0 | **Adopted (already)** | DLX/DLQ, TTL, publisher confirms, quorum queues — all used or planned in `docs/RABBITMQ_VERIFICATION.md`. |

Key patterns adopted into our design: DLQ after max retries with replay (our dead_letter/BLOCKED + retry endpoint), publisher confirms required before "delivered" (M7), exponential backoff (planned: `CICC_COORD_RETRY_BACKOFF_S`), prefetch=1 for variable-duration tasks (runbook note).

## Multi-agent orchestration

| Candidate | License | Verdict | Rationale |
|---|---|---|---|
| LangGraph | MIT | **Adapt patterns** | Explicit state machine + checkpoints + interrupts ≈ our registry state machine + audit events + WAITING_FOR_APPROVAL. We keep our own (lighter, DB-backed, multi-tenant-ready) rather than depending on an LLM graph runtime. |
| CrewAI | MIT | **No** | Role/crew metaphor is nice but hides execution details; our explicit routing explanations are a deliberate contrast. |
| AutoGen / MS Agent Framework | MIT (AutoGen archived) | **No** | Conversation-driven coordination is harder to constrain/audit; our event→task→route→report model is auditable by design. |
| OpenHands / SWE-agent style | Apache-2.0 | **No** | Execution sandboxes belong to Agent 4's domain; we only hand off tasks. |

## Observability / registries / approvals

- **Agent registry**: no mature OSS "agent directory with heartbeats + workload + capability matching" fits a 4-agent repo; our `coord_agents` + routing scoring implements the pattern (service discovery analogs: Consul/etcd — overkill here; revisit if agents exceed a handful or span hosts).
- **Approval workflows**: LangGraph interrupts / Temporal signals / Inngest waitForEvent all = durable wait + resume; our `coord_approvals` + EXPIRED sweep implements the same semantics in SQL. Decision: keep own.
- **Event-driven ingestion**: GitHub webhooks + HMAC + replay-id dedup is the standard pattern (adopted M6); Kafka/EventBridge not needed at our scale.

## What we deliberately do NOT adopt
Whole platforms (Temporal server, Kafka, Consul) — they add operational infrastructure (clusters, ops burden) without removing risk at CICC's current scale. All are MPL/MIT/Apache so licensing is not the blocker; operational maturity is.

## Re-evaluation triggers
- Tasks spanning days with durable pause/resume → evaluate Temporal/Inngest.
- >10 agents across multiple hosts → Consul/etcd-style discovery or RabbitMQ-only registry.
- Broker cluster in production → quorum queues per Dramatiq guidance.
