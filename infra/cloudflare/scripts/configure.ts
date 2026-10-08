import { readFileSync, writeFileSync } from "node:fs";

const base = JSON.parse(readFileSync("wrangler.jsonc", "utf8"));
// No Worker placement: the Worker runs at the client's nearest edge and
// forwards to the region's Durable Object, which fronts the container.
// Pinning the Worker to a cloud region added a detour to every message.
for (const [region, hint, constraint] of [
  ["us", "enam", "ENAM"],
  ["eu", "weur", "WEUR"],
  ["sea", "apac", "APAC"],
]) {
  const config = structuredClone(base);
  config.name = `zkfetch-notary-${region}`;
  config.vars.LOCATION_HINT = hint;
  config.vars.DEPLOYMENT_REGION = region;
  config.containers[0].constraints.regions = [constraint];
  writeFileSync(`wrangler.${region}.jsonc`, JSON.stringify(config, null, 2) + "\n");
}
