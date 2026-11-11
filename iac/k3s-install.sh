#!/usr/bin/env bash
# Install K3s on a fresh Hetzner server and deploy Meitaka CTI.
# Usage: bash k3s-install.sh [SERVER_IP]
set -euo pipefail

SERVER_IP="${1:-}"
if [[ -z "$SERVER_IP" ]]; then
  echo "Usage: $0 <server-ip>" >&2
  exit 1
fi

echo "==> Installing K3s on $SERVER_IP"
ssh root@"$SERVER_IP" 'curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable traefik" sh -'

echo "==> Fetching kubeconfig"
mkdir -p ~/.kube
ssh root@"$SERVER_IP" 'cat /etc/rancher/k3s/k3s.yaml' \
  | sed "s/127.0.0.1/$SERVER_IP/" > ~/.kube/meitaka.yaml
export KUBECONFIG=~/.kube/meitaka.yaml

echo "==> Installing helmfile + helm-diff"
helm plugin install https://github.com/databus23/helm-diff 2>/dev/null || true
helmfile apply --file "$(dirname "$0")/helmfile.yaml"

echo "==> Done — KUBECONFIG=$KUBECONFIG"
