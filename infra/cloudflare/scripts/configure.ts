import { readFileSync, writeFileSync } from "node:fs";

const base = JSON.parse(readFileSync("wrangler.jsonc", "utf8"));
for (const [region, cloudRegion, hint, constraint] of [
  ["us", "aws:us-east-1", "enam", "ENAM"],
  ["eu", "aws:eu-central-1", "weur", "WEUR"],
  ["sea", "aws:ap-southeast-1", "apac", "APAC"],
]) {
  const config = structuredClone(base);
  config.name = `zkfetch-notary-${region}`;
  config.placement.region = cloudRegion;
  config.vars.LOCATION_HINT = hint;
  config.vars.DEPLOYMENT_REGION = region;
  config.containers[0].constraints.regions = [constraint];
  writeFileSync(`wrangler.${region}.jsonc`, JSON.stringify(config, null, 2) + "\n");
}
