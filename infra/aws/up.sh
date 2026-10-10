#!/usr/bin/env bash
# Starts (or updates) the zkfetch notary on a t4g.small in ap-south-1 (Mumbai).
#
#   infra/aws/up.sh
#
# Builds the Linux arm64 notary binary locally, creates a tagged key pair, security
# group and instance, then runs the notary behind Caddy (automatic HTTPS) at
# wss://<ip>.sslip.io/notarize, or wss://$NOTARY_DOMAIN/notarize if set (point
# that DNS name at the printed IP first). Signs with .zkf/hosted-notary.key,
# the key the extension pins. Re-running redeploys the notary.
# Delete everything with infra/aws/down.sh.
source "$(dirname "$0")/common.sh"

INSTANCE_TYPE=${INSTANCE_TYPE:-t4g.small}
AMI_PARAMETER=${AMI_PARAMETER:-/aws/service/ami-amazon-linux-latest/al2027-preview-ami-minimal-kernel-default-arm64}
NEW_INSTANCE=${NEW_INSTANCE:-0}
[[ "$NEW_INSTANCE" == 0 || "$NEW_INSTANCE" == 1 ]] || { echo "NEW_INSTANCE must be 0 or 1" >&2; exit 1; }
ARTIFACTS="$STATE/artifacts"
CADDY_VERSION=2.10.2
# Official release archive checksum (SHA-512).
CADDY_SHA512=6ce061a690312ab38367df3c5d5f89a2e4a263e7300d300d87356211bb81e79b15933e6d6203e03fbf26f15cc0311f264805f336147dbdd24938d84b57a4421c
ROOT_VOLUME_GIB=${ROOT_VOLUME_GIB:-4}
MAX_SESSIONS=${MAX_SESSIONS:-4}
MAX_SESSIONS_PER_CLIENT=${MAX_SESSIONS_PER_CLIENT:-4}
[[ "$ROOT_VOLUME_GIB" =~ ^[0-9]+$ && "$ROOT_VOLUME_GIB" -ge 2 ]] || { echo "ROOT_VOLUME_GIB must be >= 2" >&2; exit 1; }
[[ "$MAX_SESSIONS" =~ ^[0-9]+$ && "$MAX_SESSIONS" -ge 1 && "$MAX_SESSIONS" -le 128 ]] || { echo "MAX_SESSIONS must be 1..128" >&2; exit 1; }
[[ "$MAX_SESSIONS_PER_CLIENT" =~ ^[0-9]+$ && "$MAX_SESSIONS_PER_CLIENT" -ge 1 ]] || { echo "MAX_SESSIONS_PER_CLIENT must be >= 1" >&2; exit 1; }
KEY_FILE="$ROOT/.zkf/hosted-notary.key"
SSH_KEY="$STATE/id_ed25519"
mkdir -p "$STATE" && chmod 700 "$STATE"
[[ -f "$KEY_FILE" ]] || { echo "Missing $KEY_FILE (the hosted notary signing key)" >&2; exit 1; }

ADMISSION_FILE=${ZKF_CAPABILITIES_FILE:?Set ZKF_CAPABILITIES_FILE to the private JSON capability configuration}
[[ -f "$ADMISSION_FILE" ]] || { echo "Missing capability configuration" >&2; exit 1; }

mkdir -p "$ARTIFACTS"
if [[ -n "${NOTARY_BINARY:-}" ]]; then
  cp "$NOTARY_BINARY" "$ARTIFACTS/zkf-notary"
else
  log "Building Linux ARM64 binary locally (no Docker on EC2)"
  docker buildx build --platform linux/arm64 -f "$ROOT/infra/aws/Dockerfile.native" \
    --output "type=local,dest=$ARTIFACTS" "$ROOT"
fi
log "Fetching pinned Caddy $CADDY_VERSION"
ARCHIVE="$ARTIFACTS/caddy.tar.gz"
if [[ ! -f "$ARCHIVE" ]] || ! printf '%s  %s\n' "$CADDY_SHA512" "$ARCHIVE" | shasum -a 512 -c - >/dev/null 2>&1; then
  curl -fsSL --retry 3 "https://github.com/caddyserver/caddy/releases/download/v$CADDY_VERSION/caddy_${CADDY_VERSION}_linux_arm64.tar.gz" -o "$ARCHIVE"
fi
printf '%s  %s\n' "$CADDY_SHA512" "$ARCHIVE" | shasum -a 512 -c -
tar -xzf "$ARCHIVE" -C "$ARTIFACTS" caddy

log "Key pair"
if [[ ! -f "$SSH_KEY" ]]; then
  ssh-keygen -q -t ed25519 -N "" -C "$NAME" -f "$SSH_KEY"
  aws ec2 delete-key-pair --key-name "$NAME" >/dev/null 2>&1 || true
fi
if ! aws ec2 describe-key-pairs --key-names "$NAME" >/dev/null 2>&1; then
  aws ec2 import-key-pair --key-name "$NAME" --public-key-material "fileb://$SSH_KEY.pub" \
    --tag-specifications "ResourceType=key-pair,Tags=[{$TAG}]" >/dev/null
fi

log "Security group"
MY_IP=$(curl -fsS https://checkip.amazonaws.com | tr -d '[:space:]')
SG=$(aws ec2 describe-security-groups --filters "$FILTER" --query 'SecurityGroups[0].GroupId' --output text)
if [[ "$SG" == "None" ]]; then
  VPC=$(aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[0].VpcId' --output text)
  [[ "$VPC" != "None" ]] || { echo "No default VPC in $REGION" >&2; exit 1; }
  SG=$(aws ec2 create-security-group --group-name "$NAME" --description "zkfetch notary: HTTPS, ACME, SSH from deployer" \
    --vpc-id "$VPC" --tag-specifications "ResourceType=security-group,Tags=[{$TAG}]" --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id "$SG" --ip-permissions \
    'IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]' \
    'IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges=[{CidrIp=0.0.0.0/0}],Ipv6Ranges=[{CidrIpv6=::/0}]' >/dev/null
fi
# SSH only from this machine's current IP.
aws ec2 authorize-security-group-ingress --group-id "$SG" \
  --ip-permissions "IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges=[{CidrIp=$MY_IP/32,Description=deployer}]" >/dev/null 2>&1 || true

log "Instance"
AMI=$(aws ssm get-parameter --name "$AMI_PARAMETER" --query Parameter.Value --output text)
INSTANCE=${INSTANCE_ID:-None}
if [[ "$INSTANCE" == None && "$NEW_INSTANCE" == 0 ]]; then
  INSTANCE=$(aws ec2 describe-instances --filters "$FILTER" Name=instance-state-name,Values=pending,running \
    --query 'Reservations[0].Instances[0].InstanceId' --output text)
fi
if [[ "$INSTANCE" != None ]]; then
  IMAGE_NAME=$(aws ec2 describe-instances --instance-ids "$INSTANCE" --query 'Reservations[0].Instances[0].ImageId' --output text)
  IMAGE_NAME=$(aws ec2 describe-images --image-ids "$IMAGE_NAME" --query 'Images[0].Name' --output text)
  if [[ "$AMI_PARAMETER" == *al2027-* && "$IMAGE_NAME" != al2027-* ]]; then
    echo "Existing $INSTANCE uses $IMAGE_NAME. Use NEW_INSTANCE=1 to launch AL2027; validate it before terminating the old instance." >&2
    exit 1
  fi
fi
if [[ "$INSTANCE" == "None" ]]; then
  USER_DATA=$(cat <<'EOF'
#!/bin/bash
set -euo pipefail
# Keep English locales and translations on this dedicated notary host.
printf '%%_install_langs en:en_US\n' > /etc/rpm/macros.zkfetch-languages
dnf install -y iptables glibc-langpack-en
REMOVE=()
for package in glibc-all-langpacks awscli-2 awscli; do
  if rpm -q "$package" >/dev/null 2>&1; then REMOVE+=("$package"); fi
done
if (( ${#REMOVE[@]} )); then
  dnf remove -y --setopt=clean_requirements_on_remove=False "${REMOVE[@]}"
fi
localectl set-locale LANG=en_US.UTF-8
systemctl disable --now dnf-makecache.timer || true
dnf clean all
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/zkfetch.conf <<JOURNAL
[Journal]
Storage=persistent
SystemMaxUse=50M
RuntimeMaxUse=16M
JOURNAL
systemctl restart systemd-journald
# Small host-only safety margin; the notary service has swap disabled.
fallocate -l 512M /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
echo '/swapfile none swap defaults 0 0' >> /etc/fstab
touch /var/lib/zkf-ready
EOF
)
  INSTANCE=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$INSTANCE_TYPE" --key-name "$NAME" \
    --security-group-ids "$SG" --user-data "$USER_DATA" \
    --metadata-options HttpTokens=required,HttpEndpoint=enabled \
    --block-device-mappings "DeviceName=/dev/xvda,Ebs={VolumeSize=$ROOT_VOLUME_GIB,VolumeType=gp3,DeleteOnTermination=true}" \
    --tag-specifications "ResourceType=instance,Tags=[{$TAG},{Key=Name,Value=$NAME}]" \
                         "ResourceType=volume,Tags=[{$TAG}]" \
    --query 'Instances[0].InstanceId' --output text)
  echo "launched $INSTANCE"
fi
aws ec2 wait instance-running --instance-ids "$INSTANCE"
IP=$(aws ec2 describe-instances --instance-ids "$INSTANCE" --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)
HOST=${NOTARY_DOMAIN:-${IP//./-}.sslip.io}
echo "$INSTANCE at $IP ($HOST)"

SSH=(ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new
     -o UserKnownHostsFile="$STATE/known_hosts" -o ConnectTimeout=10 "ec2-user@$IP")
log "Waiting for SSH and native host bootstrap"
for _ in $(seq 60); do "${SSH[@]}" test -f /var/lib/zkf-ready 2>/dev/null && break; sleep 5; done
"${SSH[@]}" test -f /var/lib/zkf-ready

log "Uploading native binaries and service units"
REMOTE_STAGE=$("${SSH[@]}" mktemp -d /tmp/zkfetch-deploy.XXXXXX)
[[ "$REMOTE_STAGE" =~ ^/tmp/zkfetch-deploy\.[a-zA-Z0-9]+$ ]] || { echo "invalid staging path" >&2; exit 1; }
tar -czf - -C "$ARTIFACTS" zkf-notary caddy -C "$ROOT/infra/aws" notary-egress.sh systemd \
  | "${SSH[@]}" "tar -xzf - -C '$REMOTE_STAGE'"
# Only PID 1 reads this root-only file; credentials are never in user data.
{
  printf 'ZKF_NOTARY_KEY=%s\n' "$(tr -d '[:space:]' < "$KEY_FILE")"
  printf 'ZKF_CAPABILITIES=%s\n' "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$ADMISSION_FILE")"
  printf 'ZKF_NOTARY_ADDR=127.0.0.1:7047\nZKF_HEALTH_ADDR=127.0.0.1:9001\nZKF_REQUIRE_KEY=1\n'
  printf 'ZKF_MAX_SESSIONS=%s\nZKF_MAX_SESSIONS_PER_CLIENT=%s\n' "$MAX_SESSIONS" "$MAX_SESSIONS_PER_CLIENT"
  printf 'ZKF_TRUST_FORWARDED=1\nZKF_SESSION_TIMEOUT_SECS=120\nRAYON_NUM_THREADS=2\n'
} | "${SSH[@]}" "sudo sh -c 'umask 077; cat > /etc/zkf-notary.env'"

log "Installing and starting systemd services"
"${SSH[@]}" sudo HOST="$HOST" STAGE="$REMOTE_STAGE" bash -s <<'EOF'
set -euo pipefail
getent passwd zkf-notary >/dev/null || useradd --system --no-create-home --shell /sbin/nologin zkf-notary
getent passwd caddy >/dev/null || useradd --system --home-dir /var/lib/caddy --no-create-home --shell /sbin/nologin caddy
systemctl stop zkf-notary.service 2>/dev/null || true
install -d /etc/zkfetch /etc/caddy
# Replace binaries atomically so an existing process never sees a partial file.
for binary in zkf-notary caddy; do
  install -m755 "$STAGE/$binary" "/usr/local/bin/$binary.next"
  mv -f "/usr/local/bin/$binary.next" "/usr/local/bin/$binary"
done
# Fail before startup if the supplied notary has incompatible shared libraries.
ldd /usr/local/bin/zkf-notary > "$STAGE/ldd.txt"
cat "$STAGE/ldd.txt"
! grep -q 'not found' "$STAGE/ldd.txt"
install -m755 "$STAGE/notary-egress.sh" /etc/zkfetch/notary-egress.sh
install -m644 "$STAGE/systemd/"*.service /etc/systemd/system/
# AL2027 enforces SELinux: staging files must acquire their destination labels.
restorecon -RF /usr/local/bin/zkf-notary /usr/local/bin/caddy /etc/zkfetch /etc/systemd/system
cat > /etc/caddy/Caddyfile <<CADDY
$HOST {
	handle /health {
		reverse_proxy 127.0.0.1:9001
	}
	handle {
		reverse_proxy 127.0.0.1:7047
	}
}
CADDY
restorecon -RF /etc/caddy
/usr/local/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
systemd-analyze verify /etc/systemd/system/zkf-{egress,notary}.service /etc/systemd/system/caddy.service
systemctl daemon-reload
systemctl enable zkf-egress.service zkf-notary.service caddy.service
systemctl restart zkf-egress.service
systemctl start zkf-notary.service
systemctl restart caddy.service
rm -rf "$STAGE"
EOF

log "Waiting for https://$HOST/health (first certificate takes up to a minute)"
# Same key as before: existing pins (extension, verifiers) keep working.
EXPECTED=$(jq -r .publicKey "$ROOT/infra/aws/deployment.json" 2>/dev/null || true)
for _ in $(seq 40); do
  KEY=$(curl -fsS -m 10 "https://$HOST/health" 2>/dev/null | jq -r .publicKey 2>/dev/null || true)
  [[ -n "$KEY" ]] && break; sleep 5
done
[[ -n "$KEY" && ( -z "$EXPECTED" || "$KEY" == "$EXPECTED" ) ]] || { echo "health check failed (public key: ${KEY:-none})" >&2; exit 1; }

jq -n --arg url "wss://$HOST/notarize" --arg health "https://$HOST/health" --arg key "$KEY" \
  --arg instance "$INSTANCE" --arg ip "$IP" --arg type "$INSTANCE_TYPE" --arg amiParameter "$AMI_PARAMETER" \
  '{url:$url, health:$health, publicKey:$key, location:"ap-south-1", instance:$instance, ip:$ip, instanceType:$type, amiParameter:$amiParameter}' \
  > "$STATE/deployment.json"
# Public manifest (no instance details), read by the Chrome extension build.
jq '{url, health, publicKey, location, instanceType, deployedAt: (now|todate)}' "$STATE/deployment.json" \
  > "$ROOT/infra/aws/deployment.json"
log "Notary live: wss://$HOST/notarize"
echo "SSH: ssh -i $SSH_KEY ec2-user@$IP    Logs: sudo journalctl -u zkf-notary -f"
