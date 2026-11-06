import test from "node:test";
import assert from "node:assert/strict";

import {
  DOMAIN_GATEWAY_STATES,
  EXPECTED_DOMAIN_KINDS,
  normalizeDomainGateway,
} from "../lib/domain-gateway.mjs";

const emptyStatuses = () => ({ domains: [], statuses: {}, states: DOMAIN_GATEWAY_STATES });
const emptyMetrics = () => ({ domains: {}, labels: ["kind"], note: "bounded labels" });

test("M49: empty gateway responses show known TI/VI as NOT_MOUNTED, not healthy", () => {
  const snapshot = normalizeDomainGateway(emptyStatuses(), emptyMetrics());
  assert.deepEqual(
    snapshot.rows.map(({ kind, mounted, status }) => ({ kind, mounted, status })),
    EXPECTED_DOMAIN_KINDS.map((kind) => ({ kind, mounted: false, status: "NOT_MOUNTED" }))
  );
  assert.ok(snapshot.rows.every((row) => row.invokes === null && row.probeInFlight === null));
});

test("M49: mounted lifecycle and bounded probe evidence are normalized without metadata leakage", () => {
  const statusPayload = {
    domains: [{ kind: "threat_intel", status: "EXECUTION_VERIFIED", source_ref: "private-ref" }],
    statuses: {
      threat_intel: {
        status: "EXECUTION_VERIFIED",
        version: "private-version",
        source_ref: "private-ref",
        invokes: 4,
        successes: 3,
        last_invoke_at: "2026-11-06T12:30:00Z",
        circuit: { probe_inflight: true, probe_lease_expires_in_s: 2.5 },
      },
    },
  };
  const metricsPayload = {
    domains: {
      threat_intel: {
        invokes: 4,
        successes: 3,
        circuit: { probe_inflight: true, probe_lease_expires_in_s: 2.5, probe_lease_expirations: 2 },
      },
    },
  };
  const snapshot = normalizeDomainGateway(statusPayload, metricsPayload);
  assert.deepEqual(snapshot.rows[0], {
    kind: "threat_intel",
    mounted: true,
    status: "EXECUTION_VERIFIED",
    invokes: 4,
    successes: 3,
    probeInFlight: true,
    probeLeaseExpiresInS: 2.5,
    probeLeaseExpirations: 2,
    lastInvokeAt: "2026-11-06T12:30:00Z",
  });
  assert.equal(JSON.stringify(snapshot).includes("private-ref"), false);
  assert.equal(JSON.stringify(snapshot).includes("private-version"), false);
});

test("M49: unknown or contradictory lifecycle states fail closed to UNKNOWN", () => {
  const snapshot = normalizeDomainGateway(
    {
      domains: [],
      statuses: {
        vuln_intel: { status: "AVAILABLE", invokes: -1, successes: "3", circuit: { probe_inflight: "yes" } },
      },
    },
    {
      domains: {
        threat_intel: { status: "GREEN" },
        vuln_intel: { status: "MOUNTED", invokes: 2 },
      },
    }
  );
  assert.equal(snapshot.rows[0].status, "UNKNOWN");
  assert.equal(snapshot.rows[1].status, "UNKNOWN");
  assert.equal(snapshot.rows[1].invokes, null);
  assert.equal(snapshot.rows[1].successes, null);
  assert.equal(snapshot.rows[1].probeInFlight, null);
});

test("M49: invalid response shapes stay unavailable instead of implying NOT_MOUNTED", () => {
  assert.equal(normalizeDomainGateway(null, emptyMetrics()), null);
  assert.equal(normalizeDomainGateway({ statuses: {} }, emptyMetrics()), null);
  assert.equal(normalizeDomainGateway(emptyStatuses(), { domains: [] }), null);
});

test("M49: custom kind labels are validated and bounded", () => {
  const statuses = {};
  const metricRows = {};
  for (let i = 0; i < 80; i += 1) {
    const kind = `custom_${String(i).padStart(2, "0")}`;
    statuses[kind] = { status: "NOT_MOUNTED" };
    metricRows[kind] = { invokes: i };
  }
  statuses["bad kind"] = { status: "EXECUTION_VERIFIED" };
  const snapshot = normalizeDomainGateway(
    { domains: [], statuses },
    { domains: metricRows }
  );
  assert.equal(snapshot.rows.length, 64);
  assert.ok(snapshot.rows.every((row) => /^[a-z0-9][a-z0-9_]{0,63}$/.test(row.kind)));
  assert.ok(!snapshot.rows.some((row) => row.kind === "bad kind"));
});
