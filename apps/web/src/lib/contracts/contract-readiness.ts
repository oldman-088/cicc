export type ContractOwner = "Agent 1" | "Agent 2" | "Agent 3";
export type PackageContractState = "proposed" | "documented-candidate";
export type HostBindingState = "unverified" | "not-mounted";

export type BetaIntegrationContract = {
  id: "domain-lifecycle" | "threat-intelligence" | "vulnerability-intelligence";
  owner: ContractOwner;
  packageContract: PackageContractState;
  hostBinding: HostBindingState;
  frontendAdapter: "type-only";
  reviewedHead: string;
  sourceDocument: string;
  liveProviderVerified: false;
};

/**
 * Reviewed package/document evidence only. These entries are not runtime
 * connection checks and intentionally contain no endpoint or host URL.
 */
export const betaIntegrationContracts: readonly BetaIntegrationContract[] = [
  {
    id: "domain-lifecycle",
    owner: "Agent 1",
    packageContract: "documented-candidate",
    hostBinding: "unverified",
    frontendAdapter: "type-only",
    reviewedHead: "2ef50e77a429fed35b8cc3991301608e9537d313",
    sourceDocument: "DOMAIN_STATUS_CONTRACT.md (M44)",
    liveProviderVerified: false,
  },
  {
    id: "threat-intelligence",
    owner: "Agent 2",
    packageContract: "documented-candidate",
    hostBinding: "not-mounted",
    frontendAdapter: "type-only",
    reviewedHead: "2752b48f0b6244b4f17dffa1986165d1832e89ef",
    sourceDocument: "THREAT_RELATIONSHIP_API_CONTRACT.md",
    liveProviderVerified: false,
  },
  {
    id: "vulnerability-intelligence",
    owner: "Agent 3",
    packageContract: "proposed",
    hostBinding: "not-mounted",
    frontendAdapter: "type-only",
    reviewedHead: "1b945c04e609de00b7e13d0523d87ec931eaafc6",
    sourceDocument: "docs/vulnerability-intelligence/FRONTEND_HANDOFF.md + openapi.yaml",
    liveProviderVerified: false,
  },
] as const;

export const betaIntegrationContractById = Object.fromEntries(
  betaIntegrationContracts.map((contract) => [contract.id, contract]),
) as Record<BetaIntegrationContract["id"], BetaIntegrationContract>;
