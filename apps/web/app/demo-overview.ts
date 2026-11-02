/** Contract of the public, synthetic-only demo. This is not an operational intelligence schema. */
export type DemoRecord = {id:string;title:string;category:string;severity:string;source:string;observed_at:string;confidence:number;description:string;synthetic:true};
export type DemoOverview = {mode:'synthetic-demo';notice:string;records:DemoRecord[];sources:{name:string;status:'not configured'}[]};

const object = (value:unknown): value is Record<string,unknown> => typeof value === 'object' && value !== null && !Array.isArray(value);
const keys = (value:Record<string,unknown>, allowed:string[]) => Object.keys(value).every(key => allowed.includes(key));
const text = (value:unknown, max:number): value is string => typeof value === 'string' && value.trim().length > 0 && value.length <= max;

/** Fail closed: malformed or non-synthetic responses must not be presented as demo intelligence. */
export function isDemoOverview(value:unknown): value is DemoOverview {
  if (!object(value) || !keys(value,['mode','notice','records','sources']) || value.mode !== 'synthetic-demo' || !text(value.notice,1000) ||
      !Array.isArray(value.records) || value.records.length > 100 ||
      !Array.isArray(value.sources) || value.sources.length > 100) return false;
  const ids = new Set<string>();
  for (const record of value.records) {
    if (!object(record) || !keys(record,['id','title','category','severity','source','observed_at','confidence','description','synthetic']) || !text(record.id,100) || ids.has(record.id) ||
        !text(record.title,500) || !text(record.category,100) || !text(record.severity,100) ||
        !text(record.source,200) || !text(record.description,4000) ||
        !text(record.observed_at,100) || !Number.isFinite(Date.parse(record.observed_at)) ||
        typeof record.confidence !== 'number' || !Number.isFinite(record.confidence) ||
        record.confidence < 0 || record.confidence > 100 || record.synthetic !== true) return false;
    ids.add(record.id);
  }
  return value.sources.every(source => object(source) && keys(source,['name','status']) && text(source.name,200) && source.status === 'not configured');
}
