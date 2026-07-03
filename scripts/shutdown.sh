#!/usr/bin/env bash
# shutdown.sh — upf-edge 개발 환경 종료
#
# 사용법:
#   ./scripts/shutdown.sh           # 전체 종료 (upf-edge + Docker + 정리)
#   ./scripts/shutdown.sh upf       # upf-edge 프로세스만
#   ./scripts/shutdown.sh xdp       # XDP detach만
#   ./scripts/shutdown.sh docker    # Docker compose만
#   ./scripts/shutdown.sh net       # veth + iptables 제거
#
# 멱등: 이미 정리된 step은 skip.

set -uo pipefail  # -e 제외 (다운은 실패해도 다음 단계 진행)

UE_SUBNET="192.168.100.0/24"
VETH_HOST="upfedge0"
VETH_PEER="upfedge1"
DOCKER_COMPOSE_DIR="$HOME/docker-open5gs"

color_ok="\033[32m"
color_warn="\033[33m"
color_err="\033[31m"
color_reset="\033[0m"

log_ok()   { echo -e "${color_ok}[ok]${color_reset}   $*"; }
log_warn() { echo -e "${color_warn}[warn]${color_reset} $*"; }
log_info() { echo -e "[info] $*"; }
log_step() { echo -e "\n=== $* ==="; }

# ─────────────────────────────────────────────────────────
# Step 1: upf-edge 프로세스 종료
# ─────────────────────────────────────────────────────────
stop_upf() {
    log_step "upf-edge 프로세스 종료"

    if ! pgrep -f "target/release/upf-edge" >/dev/null; then
        log_ok "upf-edge 실행 중 아님"
        return 0
    fi

    log_info "SIGTERM 전송..."
    sudo pkill -TERM -f "target/release/upf-edge" || true

    # 5초 대기
    for i in 1 2 3 4 5; do
        sleep 1
        if ! pgrep -f "target/release/upf-edge" >/dev/null; then
            log_ok "upf-edge 정상 종료"
            return 0
        fi
    done

    log_warn "graceful 종료 실패, SIGKILL 전송"
    sudo pkill -KILL -f "target/release/upf-edge" || true
    sleep 1
    log_ok "upf-edge 강제 종료"
}

# ─────────────────────────────────────────────────────────
# Step 2: XDP detach (남아있는 경우)
# ─────────────────────────────────────────────────────────
detach_xdp() {
    log_step "XDP detach"

    for iface in "$VETH_HOST" "$VETH_PEER"; do
        if ! ip link show "$iface" &>/dev/null; then
            continue
        fi

        if ip link show "$iface" | grep -qi xdp; then
            sudo ip link set dev "$iface" xdpgeneric off 2>/dev/null || true
            sudo ip link set dev "$iface" xdp off 2>/dev/null || true
            log_ok "$iface XDP detached"
        else
            log_ok "$iface XDP 없음"
        fi
    done

    # Docker bridge에도 XDP 붙어있을 수 있어 (BPF가 bridge에 attach)
    local bridges
    bridges=$(ip -4 addr show | awk '/^[0-9]+:/{name=$2; sub(":","",name)} /inet 172\.22\./{print name}' | sort -u)

    for br in $bridges; do
        if ip link show "$br" | grep -qi xdp; then
            sudo ip link set dev "$br" xdpgeneric off 2>/dev/null || true
            sudo ip link set dev "$br" xdp off 2>/dev/null || true
            log_ok "$br XDP detached"
        fi
    done

    # gNB 측 veth (Docker가 동적으로 만든 것) — 패턴으로 찾기
    local docker_veths
    docker_veths=$(ip link show | awk '/^[0-9]+: veth[a-f0-9]+@/{print $2}' | sed 's/@.*//')
    for veth in $docker_veths; do
        if ip link show "$veth" | grep -qi xdp; then
            sudo ip link set dev "$veth" xdpgeneric off 2>/dev/null || true
            sudo ip link set dev "$veth" xdp off 2>/dev/null || true
            log_ok "$veth XDP detached"
        fi
    done
}

# ─────────────────────────────────────────────────────────
# Step 3: Docker compose down
# ─────────────────────────────────────────────────────────
stop_docker() {
    log_step "Docker compose down"

    if [[ ! -d "$DOCKER_COMPOSE_DIR" ]]; then
        log_warn "$DOCKER_COMPOSE_DIR 없음, skip"
        return 0
    fi

    cd "$DOCKER_COMPOSE_DIR"

    for yaml in nr-ue.yaml nr-gnb.yaml sa-deploy.yaml; do
        if [[ -f "$yaml" ]]; then
            log_info "$yaml down..."
            docker compose -f "$yaml" down 2>/dev/null || true
            log_ok "$yaml 정리"
        fi
    done

    cd - >/dev/null
}

# ─────────────────────────────────────────────────────────
# Step 4: veth + iptables 제거
# ─────────────────────────────────────────────────────────
clean_net() {
    log_step "veth + iptables 정리"

    # veth 제거 (peer까지 자동 제거)
    if ip link show "$VETH_HOST" &>/dev/null; then
        sudo ip link delete "$VETH_HOST"
        log_ok "$VETH_HOST + $VETH_PEER 제거"
    else
        log_ok "$VETH_HOST 이미 없음"
    fi

    # iptables FORWARD 제거
    while sudo iptables -C FORWARD -s "$UE_SUBNET" -j ACCEPT 2>/dev/null; do
        sudo iptables -D FORWARD -s "$UE_SUBNET" -j ACCEPT
    done
    log_ok "FORWARD -s $UE_SUBNET 제거"

    while sudo iptables -C FORWARD -d "$UE_SUBNET" -j ACCEPT 2>/dev/null; do
        sudo iptables -D FORWARD -d "$UE_SUBNET" -j ACCEPT
    done
    log_ok "FORWARD -d $UE_SUBNET 제거"

    # NAT MASQUERADE 제거 (bridge 이름 변화 가능성 때문에 다 탐색)
    local nat_rules
    nat_rules=$(sudo iptables -t nat -L POSTROUTING --line-numbers -n \
        | awk -v subnet="$UE_SUBNET" '$0 ~ subnet {print $1}' | sort -rn)

    if [[ -n "$nat_rules" ]]; then
        for line in $nat_rules; do
            sudo iptables -t nat -D POSTROUTING "$line"
        done
        log_ok "NAT MASQUERADE rules 제거"
    else
        log_ok "NAT rule 없음"
    fi
}

# ─────────────────────────────────────────────────────────
# Main dispatch
# ─────────────────────────────────────────────────────────
main() {
    local cmd="${1:-all}"

    case "$cmd" in
        upf)
#            stop_upf
#            detach_xdp
            ;;
        xdp)
#            detach_xdp
            ;;
        docker)
            stop_docker
            ;;
        net)
            stop_upf
            detach_xdp
            clean_net
            ;;
        all|"")
            stop_upf
            detach_xdp
            stop_docker
            clean_net
            echo ""
            log_ok "전체 종료 완료"
            ;;
        help|-h|--help)
            sed -n '2,12p' "$0"
            ;;
        *)
            log_warn "알 수 없는 명령: $cmd"
            log_info "사용 가능: upf, xdp, docker, net, all, help"
            exit 1
            ;;
    esac
}

main "$@"
