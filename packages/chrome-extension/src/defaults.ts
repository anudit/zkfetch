import deployment from "../../../infra/aws/deployment.json";

// Notary admission capability, injected by build.ts from ZKF_NOTARY_CAPABILITY
// or the git-ignored .zkf/notary-capability.token. Never committed.
declare const __ZKF_NOTARY_CAPABILITY__: string | undefined;
const CAPABILITY = typeof __ZKF_NOTARY_CAPABILITY__ === "string" ? __ZKF_NOTARY_CAPABILITY__ : "";

// Mumbai (ap-south-1) EC2 notary, proxy transport.
// TLS auto and the QuickSilver backend are left at their SDK defaults.
export const NOTARY = {
  ...deployment,
  url: CAPABILITY ? `${deployment.url}?capability=${CAPABILITY}` : deployment.url,
};
export const DUOLINGO = "https://www.duolingo.com";
export const API = `${DUOLINGO}/2017-06-30`;
export const DEFAULT_USERNAME = "anudit";
export const DISCLOSURES = ["username", "streakData.longestStreak"];
