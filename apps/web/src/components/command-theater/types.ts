export const SUPPORTED_LOCALES = ["en", "ar", "fa"] as const;

export type Locale = (typeof SUPPORTED_LOCALES)[number];

export type IntelligenceEntityType =
  | "threat-actor"
  | "campaign"
  | "domain"
  | "incident"
  | "asset";

export type IntelligenceRelationshipType =
  | "associated-with"
  | "uses"
  | "observed-in"
  | "affects";

export type IntelligenceNode = {
  id: string;
  label: string;
  type: IntelligenceEntityType;
  position: { x: number; y: number; z: number };
  /** Illustrative only. This sample graph contains no verified intelligence. */
  confidence: number;
  provenance: string;
};

export type IntelligenceRelationship = {
  id: string;
  sourceId: string;
  targetId: string;
  type: IntelligenceRelationshipType;
  /** Illustrative only. This sample graph contains no verified intelligence. */
  confidence: number;
  provenance: string;
};

export function isLocale(value: string): value is Locale {
  return SUPPORTED_LOCALES.some((locale) => locale === value);
}
