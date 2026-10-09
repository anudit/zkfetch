#!/usr/bin/env bash
# Starts (or updates) the zkfetch notary on a t4g.small in ap-south-1 (Mumbai).
#
#   infra/aws/up.sh
#
# Builds the arm64 notary image locally, creates a tagged key pair, security
# group and instance, then runs the notary behind Caddy (automatic HTTPS) at
# wss://<ip>.sslip.io/notarize, or wss://$NOTARY_DOMAIN/notarize if set (point
# that DNS name at the printed IP first). Signs with .zkf/hosted-notary.key,
# the key the extension pins. Re-running redeploys the notary.
# Delete everything with infra/aws/down.sh.
source "$(dirname "$0")/common.sh"

INSTANCE_TYPE=${INSTANCE_TYPE:-t4g.small}
IMAGE=zkfetch-notary:arm64
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

log "Building $IMAGE"
docker build --platform linux/arm64 -f "$ROOT/infra/aws/Dockerfile.notary" -t "$IMAGE" "$ROOT"

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
INSTANCE=$(aws ec2 describe-instances --filters "$FILTER" Name=instance-state-name,Values=pending,running \
  --query 'Reservations[0].Instances[0].InstanceId' --output text)
if [[ "$INSTANCE" == "None" ]]; then
  AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-minimal-kernel-default-arm64 \
    --query Parameter.Value --output text)
  USER_DATA=$(cat <<'EOF'
#!/bin/bash
set -e
# Keep English locales and translations on this dedicated notary host.
printf '%%_install_langs en:en_US\n' > /etc/rpm/macros.zkfetch-languages
dnf install -y docker iptables glibc-langpack-en
dnf remove -y --setopt=clean_requirements_on_remove=False glibc-all-langpacks
localectl set-locale LANG=en_US.UTF-8
systemctl disable --now dnf-makecache.timer || true
dnf clean all
systemctl enable --now docker
usermod -aG docker ec2-user
# Small host-only safety margin; the notary container has swap disabled.
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
log "Waiting for SSH and Docker"
for _ in $(seq 60); do "${SSH[@]}" test -f /var/lib/zkf-ready 2>/dev/null && break; sleep 5; done
"${SSH[@]}" test -f /var/lib/zkf-ready

log "Uploading the notary image"
docker save "$IMAGE" | gzip -1 | "${SSH[@]}" 'gunzip | sudo docker load'
# The signing key goes over SSH into a root-only file, never into user data.
{
  printf 'ZKF_NOTARY_KEY=%s\n' "$(tr -d '[:space:]' < "$KEY_FILE")"
  printf 'ZKF_CAPABILITIES=%s\n' "$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])), separators=(",", ":")))' "$ADMISSION_FILE")"
} | "${SSH[@]}" "sudo sh -c 'umask 077; cat > /etc/zkf-notary.env'"
"${SSH[@]}" 'sudo mkdir -p /etc/zkfetch'
cat "$ROOT/infra/aws/notary-egress.sh" | "${SSH[@]}" "sudo sh -c 'cat > /etc/zkfetch/notary-egress.sh'"

log "Starting the notary and Caddy"
"${SSH[@]}" sudo HOST="$HOST" IMAGE="$IMAGE" MAX_SESSIONS="$MAX_SESSIONS" MAX_SESSIONS_PER_CLIENT="$MAX_SESSIONS_PER_CLIENT" bash -s <<'EOF'
set -euo pipefail
cat > /etc/zkf-Caddyfile <<CADDY
$HOST {
	handle /health {
		reverse_proxy zkf-notary:9001
	}
	handle {
		reverse_proxy zkf-notary:7047
	}
}
CADDY
docker network inspect zkf >/dev/null 2>&1 || docker network create zkf >/dev/null
bash /etc/zkfetch/notary-egress.sh
docker rm -f zkf-notary zkf-caddy >/dev/null 2>&1 || true
docker run -d --name zkf-notary --network zkf --restart unless-stopped \
  --memory=1536m --memory-swap=1536m --pids-limit=256 \
  --security-opt=no-new-privileges --cap-drop=ALL \
  --env-file /etc/zkf-notary.env -e ZKF_MAX_SESSIONS="$MAX_SESSIONS" -e ZKF_MAX_SESSIONS_PER_CLIENT="$MAX_SESSIONS_PER_CLIENT" \
  -e ZKF_TRUST_FORWARDED=1 -e ZKF_SESSION_TIMEOUT_SECS=120 -e RAYON_NUM_THREADS=2 \
  --log-opt max-size=10m --log-opt max-file=3 "$IMAGE" >/dev/null
docker run -d --name zkf-caddy --network zkf --restart unless-stopped \
  -p 80:80 -p 443:443 -v caddy_data:/data -v /etc/zkf-Caddyfile:/etc/caddy/Caddyfile:ro \
  --log-opt max-size=10m --log-opt max-file=3 caddy:2.10@sha256:c3d7ee5d2b11f9dc54f947f68a734c84e9c9666c92c88a7f30b9cba5da182adb >/dev/null
docker image prune -f >/dev/null
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
  --arg instance "$INSTANCE" --arg ip "$IP" --arg type "$INSTANCE_TYPE" \
  '{url:$url, health:$health, publicKey:$key, location:"ap-south-1", instance:$instance, ip:$ip, instanceType:$type}' \
  > "$STATE/deployment.json"
# Public manifest (no instance details), read by the Chrome extension build.
jq '{url, health, publicKey, location, instanceType, deployedAt: (now|todate)}' "$STATE/deployment.json" \
  > "$ROOT/infra/aws/deployment.json"
log "Notary live: wss://$HOST/notarize"
echo "SSH: ssh -i $SSH_KEY ec2-user@$IP    Logs: sudo docker logs -f zkf-notary"
