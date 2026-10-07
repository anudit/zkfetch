import { Container, switchPort } from "@cloudflare/containers";

// The Cloudflare Container lifecycle binding currently requires a JS class;
// the public fetch handler and MPC service are both implemented in Rust.
export class NotaryContainer extends Container<Env> {
  defaultPort = 7047;
  requiredPorts = [7047, 9001];
  sleepAfter = "5m";
  // Proxy mode: the notary dials the target server (port 443 only).
  enableInternet = true;
  envVars = {
    ZKF_NOTARY_ADDR: "0.0.0.0:7047",
    ZKF_HEALTH_ADDR: "0.0.0.0:9001",
    ZKF_NOTARY_KEY: this.env.ZKF_NOTARY_KEY,
    ZKF_REQUIRE_KEY: "1",
    ZKF_MAX_SESSIONS: "4",
    ZKF_SESSION_TIMEOUT_SECS: "120",
    RAYON_NUM_THREADS: "2",
  };

  override async fetch(request: Request): Promise<Response> {
    if (!this.env.ZKF_NOTARY_KEY) return new Response("Notary signing key is not configured", { status: 503 });
    return super.fetch(new URL(request.url).pathname === "/health" ? switchPort(request, 9001) : request);
  }
}
