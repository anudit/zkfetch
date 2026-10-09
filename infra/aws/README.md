# Mumbai notary on EC2

A single `t4g.small` (2 Graviton vCPUs, 2 GB) in `ap-south-1`, closer to
India than the Cloudflare notaries (which India reaches via Hong Kong or
Singapore). It runs the same notary binary, built natively for arm64 so PMULL
and the AES instructions are used, behind Caddy for HTTPS, with 4 session
slots. New instances default to a 4 GiB gp3 root disk, using Amazon Linux 2023
minimal with English locales only and 512 MiB of host swap. Package caches
are cleaned and the cache timer disabled. It signs with `.zkf/hosted-notary.key`, so its public key matches the
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
  `.zkf/aws/` (git-ignored). Logs: `sudo docker logs -f zkf-notary`.
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
their disk, AMI, locales and swap settings when redeployed. The currently
running instance was tested on a 6 GiB root volume; these defaults apply to
the next new instance.
