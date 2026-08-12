#!/usr/bin/env bash
# Run two isolated wgf peers without mounting host filesystems or changing the
# host network. The caller supplies a Linux wgf binary, normally built with:
# GOOS=linux GOARCH=arm64 go build -o /tmp/wgf-linux ./cmd/wgf
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root inside a disposable Linux VM" >&2
  exit 1
fi

wgf_bin=${1:?usage: linux-netns-smoke.sh /path/to/wgf}
if [[ ! -x ${wgf_bin} ]]; then
  echo "not executable: ${wgf_bin}" >&2
  exit 1
fi

suffix=$RANDOM$RANDOM
ns_a="wgf-smoke-a-${suffix}"
ns_b="wgf-smoke-b-${suffix}"
veth_a="wgfv${suffix:0:8}a"
veth_b="wgfv${suffix:0:8}b"
if_a=wgfsa
if_b=wgfsb
tmpdir=$(mktemp -d /tmp/wgf-netns.XXXXXX)
pid_a=
pid_b=
created_a=0
created_b=0

cleanup() {
  [[ -n ${pid_a} ]] && kill "${pid_a}" 2>/dev/null || true
  [[ -n ${pid_b} ]] && kill "${pid_b}" 2>/dev/null || true
  [[ ${created_a} -eq 1 ]] && ip netns del "${ns_a}" 2>/dev/null || true
  [[ ${created_b} -eq 1 ]] && ip netns del "${ns_b}" 2>/dev/null || true
  rm -rf "${tmpdir}"
}
trap cleanup EXIT

private_a=$("${wgf_bin}" genkey)
private_b=$("${wgf_bin}" genkey)
public_a=$(printf '%s\n' "${private_a}" | "${wgf_bin}" pubkey)
public_b=$(printf '%s\n' "${private_b}" | "${wgf_bin}" pubkey)

umask 077
cat >"${tmpdir}/a.conf" <<EOF
[Interface]
PrivateKey = ${private_a}
ListenPort = 51820
MTU = 9612

[Peer]
PublicKey = ${public_b}
Endpoint = 198.18.0.2:51821
AllowedIPs = 10.2.0.0/24
EOF
cat >"${tmpdir}/b.conf" <<EOF
[Interface]
PrivateKey = ${private_b}
ListenPort = 51821
MTU = 9612

[Peer]
PublicKey = ${public_a}
Endpoint = 198.18.0.1:51820
AllowedIPs = 10.1.0.0/24
EOF

ip netns add "${ns_a}"
created_a=1
ip netns add "${ns_b}"
created_b=1
ip link add "${veth_a}" type veth peer name "${veth_b}"
ip link set "${veth_a}" netns "${ns_a}"
ip link set "${veth_b}" netns "${ns_b}"
ip -n "${ns_a}" link set lo up
ip -n "${ns_a}" addr add 198.18.0.1/30 dev "${veth_a}"
ip -n "${ns_a}" link set "${veth_a}" up
ip -n "${ns_b}" link set lo up
ip -n "${ns_b}" addr add 198.18.0.2/30 dev "${veth_b}"
ip -n "${ns_b}" link set "${veth_b}" up

ip netns exec "${ns_a}" "${wgf_bin}" run "${if_a}" --config "${tmpdir}/a.conf" >"${tmpdir}/a.log" 2>&1 &
pid_a=$!
ip netns exec "${ns_b}" "${wgf_bin}" run "${if_b}" --config "${tmpdir}/b.conf" >"${tmpdir}/b.log" 2>&1 &
pid_b=$!

for _ in {1..50}; do
  if ip -n "${ns_a}" link show dev "${if_a}" >/dev/null 2>&1 && ip -n "${ns_b}" link show dev "${if_b}" >/dev/null 2>&1; then
    break
  fi
  sleep 0.1
done
ip -n "${ns_a}" link show dev "${if_a}" >/dev/null
ip -n "${ns_b}" link show dev "${if_b}" >/dev/null

ip -n "${ns_a}" addr add 10.1.0.1/24 dev "${if_a}"
ip -n "${ns_a}" link set "${if_a}" up
ip -n "${ns_a}" route replace 10.2.0.0/24 dev "${if_a}"
ip -n "${ns_b}" addr add 10.2.0.1/24 dev "${if_b}"
ip -n "${ns_b}" link set "${if_b}" up
ip -n "${ns_b}" route replace 10.1.0.0/24 dev "${if_b}"

ip netns exec "${ns_a}" ping -I "${if_a}" -M do -c 3 -W 2 -s 1472 10.2.0.1
ip netns exec "${ns_a}" ping -I "${if_a}" -M do -c 3 -W 2 -s 9584 10.2.0.1

echo "linux netns smoke: PASS (1500 and 9612 byte inner IP packets)"
