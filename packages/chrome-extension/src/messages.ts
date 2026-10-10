import type { MemberPredicate, NotarizeTimings, VerifyOutput, VerifyV2Output } from "@omnid/zkfetch";
import type { Auth } from "./auth";

export type BackgroundRequest =
  | { type: "status" }
  | { type: "auth" }
  | { type: "open-duolingo"; focus?: boolean }
  | { type: "theme"; theme: "dark" | "light" };

export interface Status {
  tabOpen: boolean;
  hasToken: boolean;
  source?: Auth["source"];
}

export type BackgroundReply =
  | { ok: true; status: Status; auth?: Auth }
  | { ok: false; error: string };

interface ProofBase {
  presentation: string;
  elapsedMs: number;
  presentMs: number;
  timings: NotarizeTimings;
  tlsVersion?: string;
  /** Prover worker threads; 0 when single-threaded. */
  threads?: number;
}

export type ProofVersion = 1 | 2;
export type Proof = ProofBase & (
  | { version: 1; username: string; longestStreak: number }
  | { version: 2; predicate: MemberPredicate; nonce: string }
);

/** Messages to the long-lived prover worker (one per open panel). */
export type ProverRequest =
  | { type: "init"; wasmUrl: string; threadsUrl?: string }
  | { type: "prepare"; version: ProofVersion }
  | { type: "dispose" }
  | ({ type: "prove"; auth: Auth } & ({ version: 1 } | { version: 2; nonce: string }))
  | ({ type: "verify"; presentation: string } & ({ version: 1 } | { version: 2; predicate: MemberPredicate; nonce: string }));

export type ProverReply =
  | { type: "loaded"; threads: number }
  | { type: "prepared"; version: ProofVersion; ok: boolean; setupMs?: number }
  | { type: "prepared-expired" }
  | { type: "progress"; text: string }
  | { type: "proof"; proof: Proof }
  | { type: "verified"; version: 1; verified: VerifyOutput; elapsedMs: number; username: string; longestStreak: number }
  | { type: "verified"; version: 2; verified: VerifyV2Output; elapsedMs: number }
  | { type: "error"; error: string };
