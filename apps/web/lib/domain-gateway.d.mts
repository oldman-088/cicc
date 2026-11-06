import type { DomainGatewaySnapshot, DomainGatewayStatus } from "./types";

export const EXPECTED_DOMAIN_KINDS: readonly string[];
export const DOMAIN_GATEWAY_STATES: readonly DomainGatewayStatus[];

export function normalizeDomainGateway(
  statusPayload: unknown,
  metricsPayload: unknown,
): DomainGatewaySnapshot | null;
