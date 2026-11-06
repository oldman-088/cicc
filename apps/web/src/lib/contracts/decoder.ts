export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export class ContractShapeError extends Error {
  constructor(path: string, expectation: string) {
    super(`Contract payload at ${path} must be ${expectation}`);
    this.name = "ContractShapeError";
  }
}

export function contractObject(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new ContractShapeError(path, "an object");
  }
  return value as Record<string, unknown>;
}

export function contractArray<T>(
  value: unknown,
  path: string,
  decode: (item: unknown, itemPath: string) => T,
): T[] {
  if (!Array.isArray(value)) throw new ContractShapeError(path, "an array");
  return value.map((item, index) => decode(item, `${path}[${index}]`));
}

export function contractString(value: unknown, path: string): string {
  if (typeof value !== "string") throw new ContractShapeError(path, "a string");
  return value;
}

export function contractNonEmptyString(value: unknown, path: string): string {
  const result = contractString(value, path);
  if (result.trim().length === 0) throw new ContractShapeError(path, "a non-empty string");
  return result;
}

export function contractNullableString(value: unknown, path: string): string | null {
  if (value === null) return null;
  return contractString(value, path);
}

export function contractBoolean(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new ContractShapeError(path, "a boolean");
  return value;
}

export function contractNumber(value: unknown, path: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    throw new ContractShapeError(path, "a finite number");
  }
  return value;
}

export function contractNonNegativeNumber(value: unknown, path: string): number {
  const result = contractNumber(value, path);
  if (result < 0) throw new ContractShapeError(path, "a non-negative number");
  return result;
}

export function contractInteger(value: unknown, path: string): number {
  const result = contractNumber(value, path);
  if (!Number.isInteger(result)) throw new ContractShapeError(path, "an integer");
  return result;
}

export function contractNonNegativeInteger(value: unknown, path: string): number {
  const result = contractInteger(value, path);
  if (result < 0) throw new ContractShapeError(path, "a non-negative integer");
  return result;
}

export function contractStringArray(value: unknown, path: string): string[] {
  return contractArray(value, path, contractString);
}

export function contractJsonValue(value: unknown, path: string): JsonValue {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((item, index) => contractJsonValue(item, `${path}[${index}]`));
  if (typeof value === "object") {
    const result: JsonObject = {};
    for (const [key, item] of Object.entries(value)) result[key] = contractJsonValue(item, `${path}.${key}`);
    return result;
  }
  throw new ContractShapeError(path, "a JSON value");
}

export function contractJsonObject(value: unknown, path: string): JsonObject {
  const input = contractObject(value, path);
  const result: JsonObject = {};
  for (const [key, item] of Object.entries(input)) result[key] = contractJsonValue(item, `${path}.${key}`);
  return result;
}

export function contractEnum<const Values extends readonly string[]>(
  value: unknown,
  values: Values,
  path: string,
): Values[number] {
  const result = contractString(value, path);
  if (!values.includes(result)) {
    throw new ContractShapeError(path, `one of ${values.join(", ")}`);
  }
  return result as Values[number];
}

export function contractTimestamp(value: unknown, path: string): string {
  const result = contractNonEmptyString(value, path);
  // Wire timestamps in these proposals are ISO 8601 with an explicit timezone.
  if (!/(?:Z|[+-]\d{2}:\d{2})$/i.test(result) || !Number.isFinite(Date.parse(result))) {
    throw new ContractShapeError(path, "an ISO 8601 timestamp with an explicit timezone");
  }
  return result;
}

export function contractNullableTimestamp(value: unknown, path: string): string | null {
  if (value === null) return null;
  return contractTimestamp(value, path);
}
