import deployments from "../../../infra/cloudflare/deployments.json";

// Hosted SEA region, proxy transport.
// TLS auto and the QuickSilver backend are left at their SDK defaults.
export const NOTARY = deployments.sea;
export const DUOLINGO = "https://www.duolingo.com";
export const API = `${DUOLINGO}/2017-06-30`;
export const DEFAULT_USERNAME = "anudit";
export const DISCLOSURES = ["username", "streakData.longestStreak"];
