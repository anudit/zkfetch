#!/usr/bin/env bash
# Deletes every AWS resource tagged project=zkfetch-notary in ap-south-1
# (instances and their volumes, security groups, key pairs, Elastic IPs), plus
# the local SSH key and state. Untagged resources are never touched.
#
#   infra/aws/down.sh        lists what it will delete and asks first
#   infra/aws/down.sh -y     no prompt
source "$(dirname "$0")/common.sh"

q() { aws ec2 "$@" --filters "$FILTER" --output text; }
INSTANCES=$(q describe-instances --query 'Reservations[].Instances[?State.Name!=`terminated`].InstanceId[]' \
  | tr '\t' ' ' | xargs)
GROUPS_=$(q describe-security-groups --query 'SecurityGroups[].GroupId' | xargs)
KEYS=$(q describe-key-pairs --query 'KeyPairs[].KeyName' | xargs)
ADDRESSES=$(q describe-addresses --query 'Addresses[].AllocationId' | xargs)
VOLUMES=$(aws ec2 describe-volumes --filters "$FILTER" Name=status,Values=available \
  --query 'Volumes[].VolumeId' --output text | xargs)

echo "Tagged project=$NAME in $REGION:"
echo "  instances:       ${INSTANCES:--}"
echo "  security groups: ${GROUPS_:--}"
echo "  key pairs:       ${KEYS:--}"
echo "  elastic IPs:     ${ADDRESSES:--}"
echo "  loose volumes:   ${VOLUMES:--}"
echo "  local state:     $( [[ -d "$STATE" ]] && echo "$STATE" || echo - )"
if [[ -z "$INSTANCES$GROUPS_$KEYS$ADDRESSES$VOLUMES" && ! -d "$STATE" ]]; then
  echo "Nothing to delete."; exit 0
fi
if [[ "${1:-}" != "-y" ]]; then
  read -r -p "Delete all of the above? [y/N] " answer
  [[ "$answer" == [yY]* ]] || { echo "Aborted."; exit 1; }
fi

for id in $ADDRESSES; do log "Releasing $id"; aws ec2 release-address --allocation-id "$id"; done
if [[ -n "$INSTANCES" ]]; then
  log "Terminating $INSTANCES"
  aws ec2 terminate-instances --instance-ids $INSTANCES >/dev/null
  aws ec2 wait instance-terminated --instance-ids $INSTANCES
fi
for id in $VOLUMES; do log "Deleting volume $id"; aws ec2 delete-volume --volume-id "$id"; done
for id in $GROUPS_; do
  log "Deleting security group $id"
  # The network interface can take a moment to detach after termination.
  for attempt in $(seq 12); do
    aws ec2 delete-security-group --group-id "$id" 2>/dev/null && break
    [[ $attempt == 12 ]] && { echo "could not delete $id" >&2; exit 1; }
    sleep 5
  done
done
for name in $KEYS; do log "Deleting key pair $name"; aws ec2 delete-key-pair --key-name "$name" >/dev/null; done
rm -rf "$STATE"
log "Done. Nothing tagged project=$NAME is left in $REGION."
