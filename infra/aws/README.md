# Mumbai notary on EC2

A single `t4g.small` (2 Graviton vCPUs, 2 GB) in `ap-south-1`, closer to
India than the Cloudflare notaries (which India reaches via Hong Kong or
Singapore). It runs the same notary binary, built natively for arm64 so PMULL
and the AES instructions are used, as a systemd service behind native Caddy for HTTPS, with 4 session
slots. New instances default to a 4 GiB gp3 root disk, using Amazon Linux 2027
Preview minimal ARM64 with English locales only and 512 MiB of host swap. Package caches
are cleaned, the cache timer disabled, and the unused server-side AWS CLI removed. It signs with `.zkf/hosted-notary.key`, so its public key matches the
Cloudflare deployments and existing pins keep working.

```sh
infra/aws/up.sh      # build, launch (or update) and print wss://<ip>.sslip.io/notarize
infra/aws/down.sh    # list and delete everything it created (-y skips the prompt)
```

Credentials come from `AWS_ACCESS_KEY` and `AWS_SECRET_KEY` in the repo `.env`
(or the standard `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`). The IAM user
needs only [`iam-policy.json`](iam-policy.json): EC2 in `ap-south-1`, the
Amazon Linux AMI lookup, and `sts:GetCallerIdentity`.

- Every resource is tagged `project=zkfetch-notary`; `down.sh` deletes only
  tagged resources, so it is safe to run any time and more than once.
- The hostname is `<ip>.sslip.io` by default. To use your own name, point a
  DNS-only A record at the instance IP and run `NOTARY_DOMAIN=notary.example.com infra/aws/up.sh`.
  (Proxying the record through Cloudflare would route India via Hong Kong again.)
- SSH is open only to the IP that last ran `up.sh`; the key and state live in
  `.zkf/aws/` (git-ignored). Logs: `sudo journalctl -u zkf-notary -f`.
- `up.sh` again redeploys the notary on the same instance. The IP changes only
  if the instance is replaced.
- Cost: about $10 per month for the instance and its public IPv4 address,
  plus outbound data. Proxy-mode sessions transfer little; MPC mode transfers
  tens of MB per session.

The 2026-10-09 [load test](../../docs/ec2-minimal-load-test-2026-10-09.md)
found 2/4 concurrent sessions reliable for the tested proxy workload; 8/16
triggered memory-limit OOM kills. Four is the default global ceiling, not a
guarantee for arbitrary transcript sizes. `MAX_SESSIONS` and
`MAX_SESSIONS_PER_CLIENT` override the admission limits; `ROOT_VOLUME_GIB`
overrides the disk size for newly launched instances. Existing instances keep
their disk, AMI, locales and swap settings when redeployed. The native deployment has been tested on a fresh 4 GiB root volume.

## Native services

EC2 runs no Docker daemon or containers. `zkf-notary.service` binds only
`127.0.0.1:7047` and its health/metrics listener to `127.0.0.1:9001`.
`caddy.service` exposes HTTPS/HTTP on 443/80 and keeps certificates under
`/var/lib/caddy`. Caddy is pinned to 2.10.2 with the official SHA-512 archive
checksum verified before deployment.

The notary runs as a dedicated unprivileged user, with a 1.5 GiB memory ceiling,
zero service swap, 256 tasks and no capabilities. A boot-time
`zkf-egress.service` restricts that user's outbound traffic to configured DNS
resolvers and public IPv4 HTTPS; new connections to loopback, private ranges
and metadata are rejected. Caddy forwards over loopback, so established replies
remain allowed. The firewall does not restrict the deployer's SSH session.
Journald is bounded to 50 MiB on disk and 16 MiB in volatile storage.

`Dockerfile.native` is a **local build environment** for Linux ARM64, not an
EC2 runtime. To skip Docker entirely, provide a prebuilt Linux ARM64 notary:

```sh
NOTARY_BINARY=/path/to/zkf-notary ZKF_CAPABILITIES_FILE=/private/capabilities.json infra/aws/up.sh
```

The binary must be compatible with the host's glibc; the current binary built
against the AL2023-compatible baseline also runs on AL2027. Shared-library
resolution is checked before startup. No compiler, source tree or build cache is uploaded.
Service units live in [`systemd/`](systemd/). Logs and service status:

```sh
sudo journalctl -u zkf-notary -u caddy -f
sudo systemctl status zkf-notary caddy zkf-egress
```

See the [native deployment comparison](../../docs/ec2-native-2026-10-09.md).

## AL2027 migration

The default AMI lookup is
`/aws/service/ami-amazon-linux-latest/al2027-preview-ami-minimal-kernel-default-arm64`.
AL2027 is currently a [preview intended for evaluation/testing](https://docs.aws.amazon.com/linux/al2027/ug/what-is-amazon-linux-2027.html).
It does not automatically install updates; patch explicitly and replace preview
hosts with GA images when available. SELinux remains enforcing; deployment
restores file labels before starting the native services.

An AMI change requires a replacement instance. To migrate an AL2023 host:

```sh
NEW_INSTANCE=1 NOTARY_BINARY=/path/to/zkf-notary \
  ZKF_CAPABILITIES_FILE=/private/capabilities.json infra/aws/up.sh
```

This launches another tagged instance and publishes its endpoint after a pinned-key
HTTPS health check. Test presentations against it before terminating the old instance
by its exact instance ID. Rebuild/reload the extension to pick up the new hostname.
Do not use `down.sh` for this cutover: it deletes both tagged hosts.
`INSTANCE_ID` selects a specific host when redeploying during a migration;
`AMI_PARAMETER` overrides the AMI lookup for future launches.

The [AL2027 migration measurements](../../docs/benchmarks/d1-d3-baseline/hosted-al2027-2026-10-09.json)
record 12/12 verified D1 requests at four parallel sessions and fresh/warm
legacy verification, using the same notary binary as the AL2023 deployment.
