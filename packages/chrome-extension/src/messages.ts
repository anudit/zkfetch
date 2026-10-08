import type { NotarizeTimings, VerifyOutput } from "@omnid/zkfetch";
import type { Auth } from "./auth";

export type BackgroundRequest =
  | { type: "status" }
  | { type: "auth" }
  | { type: "open-duolingo"; focus?: boolean };

export interface Status {
  tabOpen: boolean;
  hasToken: boolean;
  source?: Auth["source"];
}

export type BackgroundReply =
  | { ok: true; status: Status; auth?: Auth }
  | { ok: false; error: string };

export interface Proof {
  presentation: string;
  username: string;
  longestStreak: number;
  elapsedMs: number;
  presentMs: number;
  timings: NotarizeTimings;
  tlsVersion?: string;
  /** Prover worker threads; 0 when single-threaded. */
  threads?: number;
}

/** Messages to the long-lived prover worker (one per open panel). */
export type ProverRequest =
  | { type: "init"; wasmUrl: string; threadsUrl?: string }
  | { type: "prepare" }
  | { type: "dispose" }
  | { type: "prove"; auth: Auth }
  | { type: "verify"; presentation: string };

export type ProverReply =
  | { type: "loaded"; threads: number }
  | { type: "prepared"; ok: boolean; setupMs?: number }
  | { type: "prepared-expired" }
  | { type: "progress"; text: string }
  | { type: "proof"; proof: Proof }
  | { type: "verified"; verified: VerifyOutput; elapsedMs: number; username: string; longestStreak: number }
  | { type: "error"; error: string };
