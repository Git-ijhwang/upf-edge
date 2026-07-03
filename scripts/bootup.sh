#!/usr/bin/env bash
# bootup.sh — VM 재부팅 후 upf-edge 개발 환경 setup
#
# 사용법:
#   ./scripts/bootup.sh           # 전체 setup (veth + bridge + iptables + Docker 확인)
#   ./scripts/bootup.sh veth      # veth pair만
#   ./scripts/bootup.sh net       # veth + bridge + iptables (Docker 제외)
#   ./scripts/bootup.sh docker    # Docker compose만
#   ./scripts/bootup.sh status    # 현재 상태 확인
#
# 멱등 (idempotent): 이미 적용된 step은 skip.

set -euo pipefail

UE_SUBNET="192.168.100.0/24"
UE_IP="192.168.100.1/24"
VETH_HOST="upfedge0"
VETH_PEER="upfedge1"
DOCKER_BRIDGE_PATTERN="172.22.0."
DOCKER_BRIDGE_ALIAS_1="172.22.0.8/24"      #UPF
DOCKER_BRIDGE_ALIAS_2="172.22.0.50/24"     #SMF1
DOCKER_BRIDGE_ALIAS_3="172.22.0.51/24"     #SMF2
DOCKER_COMPOSE_DIR="$HOME/docker-open5gs"

color_ok="\033[32m"
color_warn="\033[33m"
color_err="\033[31m"
color_reset="\033[0m"

log_ok()   { echo -e "${color_ok}[ok]${color_reset}   $*"; }
log_warn() { echo -e "${color_warn}[warn]${color_reset} $*"; }
log_err()  { echo -e "${color_err}[err]${color_reset}  $*"; }
log_info() { echo -e "[info] $*"; }
log_step() { echo -e "\n=== $* ==="; }

require_sudo() {
    if ! sudo -n true 2>/dev/null; then
        log_warn "sudo 권한 필요. 비밀번호 입력하면 진행됨."
        sudo true
    fi
}

# ─────────────────────────────────────────────────────────
# Step 1: veth pair 생성
# ─────────────────────────────────────────────────────────
setup_veth() {
    log_step "veth pair ($VETH_HOST <-> $VETH_PEER)"

    if ip link show "$VETH_HOST" &>/dev/null; then
        log_ok "$VETH_HOST 이미 존재"
    else
        sudo ip link add "$VETH_HOST" type veth peer name "$VETH_PEER"
        log_ok "$VETH_HOST <-> $VETH_PEER 생성"
    fi

    if ip addr show "$VETH_HOST" | grep -q "$UE_IP"; then
        log_ok "$VETH_HOST 에 $UE_IP 이미 할당"
    else
        sudo ip addr add "$UE_IP" dev "$VETH_HOST"
        log_ok "$VETH_HOST 에 $UE_IP 할당"
    fi

    sudo ip link set "$VETH_HOST" up
    sudo ip link set "$VETH_PEER" up
    log_ok "$VETH_HOST, $VETH_PEER up"
}

# ─────────────────────────────────────────────────────────
# Step 2: Docker bridge 찾기 + alias IP 추가
# ─────────────────────────────────────────────────────────
setup_bridge() {
    log_step "Docker bridge alias IPs"

    # 172.22.0.x 대역을 가진 bridge 자동 검색
    local bridge
    bridge=$(ip -4 addr show | awk -v pat="$DOCKER_BRIDGE_PATTERN" \
        '/^[0-9]+:/{name=$2; sub(":","",name)} /inet/{if($2~pat) print name}' \
        | head -1)

    if [[ -z "$bridge" ]]; then
        log_warn "172.22.0.x bridge 못 찾음. Docker 컨테이너가 안 떠 있을 수도. 'docker' 단계를 먼저 실행하세요."
        return 0
    fi

    log_info "감지된 bridge: $bridge"

    for alias in "$DOCKER_BRIDGE_ALIAS_1" "$DOCKER_BRIDGE_ALIAS_2" "$DOCKER_BRIDGE_ALIAS_3"; do
        if ip addr show "$bridge" | grep -q "$alias"; then
            log_ok "$bridge 에 $alias 이미 할당"
        else
            sudo ip addr add "$alias" dev "$bridge"
            log_ok "$bridge 에 $alias 할당"
        fi
    done
}

# ─────────────────────────────────────────────────────────
# Step 3: iptables FORWARD + NAT
# ─────────────────────────────────────────────────────────
setup_iptables() {
    log_step "iptables FORWARD + NAT (UE subnet $UE_SUBNET)"

    # FORWARD ACCEPT (both directions)
    if sudo iptables -C FORWARD -s "$UE_SUBNET" -j ACCEPT 2>/dev/null; then
        log_ok "FORWARD -s $UE_SUBNET 이미 ACCEPT"
    else
        sudo iptables -I FORWARD -s "$UE_SUBNET" -j ACCEPT
        log_ok "FORWARD -s $UE_SUBNET ACCEPT 추가"
    fi

    if sudo iptables -C FORWARD -d "$UE_SUBNET" -j ACCEPT 2>/dev/null; then
        log_ok "FORWARD -d $UE_SUBNET 이미 ACCEPT"
    else
        sudo iptables -I FORWARD -d "$UE_SUBNET" -j ACCEPT
        log_ok "FORWARD -d $UE_SUBNET ACCEPT 추가"
    fi

    # NAT MASQUERADE — Docker bridge 통해 나가는 게 아닌 트래픽만
    local bridge
    bridge=$(ip -4 addr show | awk -v pat="$DOCKER_BRIDGE_PATTERN" \
        '/^[0-9]+:/{name=$2; sub(":","",name)} /inet/{if($2~pat) print name}' \
        | head -1)

    if [[ -z "$bridge" ]]; then
        log_warn "Bridge 못 찾음. NAT rule skip."
        return 0
    fi

    if sudo iptables -t nat -C POSTROUTING -s "$UE_SUBNET" ! -o "$bridge" -j MASQUERADE 2>/dev/null; then
        log_ok "NAT MASQUERADE 이미 적용"
    else
        sudo iptables -t nat -A POSTROUTING -s "$UE_SUBNET" ! -o "$bridge" -j MASQUERADE
        log_ok "NAT MASQUERADE 추가 (! -o $bridge)"
    fi

    # ip_forward 활성화
    if [[ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]]; then
        echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward >/dev/null
        log_ok "ip_forward 활성화"
    else
        log_ok "ip_forward 이미 활성화"
    fi

    # rp_filter 비활성화 (decapsulated 패킷 라우팅용)
    for iface in all "$VETH_HOST" "$VETH_PEER"; do
        local path="/proc/sys/net/ipv4/conf/$iface/rp_filter"
        if [[ -f "$path" ]]; then
            if [[ "$(cat "$path")" != "0" ]]; then
                echo 0 | sudo tee "$path" >/dev/null
                log_ok "rp_filter ($iface) 비활성화"
            else
                log_ok "rp_filter ($iface) 이미 비활성화"
            fi
        fi
    done
}

# ─────────────────────────────────────────────────────────
# Step 4: Docker compose (Open5GS + UERANSIM)
# ─────────────────────────────────────────────────────────
setup_docker() {
    log_step "Docker compose (Open5GS + UERANSIM)"

    if [[ ! -d "$DOCKER_COMPOSE_DIR" ]]; then
        log_err "$DOCKER_COMPOSE_DIR 디렉토리가 없음"
        return 1
    fi

    cd "$DOCKER_COMPOSE_DIR"

    # 이미 떠 있는지 확인
    if docker compose -f sa-deploy.yaml ps --services --filter "status=running" 2>/dev/null | grep -q .; then
        log_ok "Open5GS 컨테이너 이미 실행 중"
    else
        log_info "Open5GS 컨테이너 시작..."
        docker compose -f sa-deploy.yaml up -d
        log_ok "Open5GS 시작됨"
    fi

    if docker compose -f nr-gnb.yaml ps --services --filter "status=running" 2>/dev/null | grep -q .; then
        log_ok "gNB 컨테이너 이미 실행 중"
    else
        log_info "gNB 컨테이너 시작..."
        docker compose -f nr-gnb.yaml up -d
        log_ok "gNB 시작됨"
    fi

    if docker compose -f nr-ue.yaml ps --services --filter "status=running" 2>/dev/null | grep -q .; then
        log_ok "UE 컨테이너 이미 실행 중"
    else
        log_info "UE 컨테이너 시작..."
        docker compose -f nr-ue.yaml up -d
        log_ok "UE 시작됨"
    fi

    docker stop upf
    cd - >/dev/null
}

# ─────────────────────────────────────────────────────────
# Step 5: 환경 변수 reminders
# ─────────────────────────────────────────────────────────
print_env_reminders() {
    log_step "환경 변수 reminders"

    echo "다음 환경 변수를 shell에 export 했는지 확인:"
    echo "  export RUST_MIN_STACK=67108864"
    echo "  export RUST_LOG=info"
    echo ""
    echo "현재 RUST_MIN_STACK = ${RUST_MIN_STACK:-(unset)}"
    echo "현재 RUST_LOG       = ${RUST_LOG:-(unset)}"
}

# ─────────────────────────────────────────────────────────
# Status — 현재 상태 진단
# ─────────────────────────────────────────────────────────
show_status() {
    log_step "현재 상태"

    echo ""
    echo "─ veth ─"
    ip link show "$VETH_HOST" &>/dev/null && log_ok "$VETH_HOST 존재" || log_err "$VETH_HOST 없음"
    ip link show "$VETH_PEER" &>/dev/null && log_ok "$VETH_PEER 존재" || log_err "$VETH_PEER 없음"

    echo ""
    echo "─ Docker bridge ─"
    local bridge
    bridge=$(ip -4 addr show | awk -v pat="$DOCKER_BRIDGE_PATTERN" \
        '/^[0-9]+:/{name=$2; sub(":","",name)} /inet/{if($2~pat) print name}' \
        | head -1)
    if [[ -n "$bridge" ]]; then
        log_ok "bridge: $bridge"
        for alias in "$DOCKER_BRIDGE_ALIAS_1" "$DOCKER_BRIDGE_ALIAS_2"; do
            ip addr show "$bridge" | grep -q "$alias" \
                && log_ok "$bridge 에 $alias" \
                || log_warn "$bridge 에 $alias 없음"
        done
    else
        log_err "172.22.0.x bridge 못 찾음"
    fi

    echo ""
    echo "─ Docker 컨테이너 ─"
    docker ps --format "  {{.Names}} ({{.Status}})" | grep -E "open5gs|gnb|ue" || log_warn "관련 컨테이너 없음"

    echo ""
    echo "─ iptables FORWARD (UE subnet) ─"
    sudo iptables -L FORWARD -n | grep "$UE_SUBNET" || log_warn "FORWARD rule 없음"

    echo ""
    echo "─ iptables NAT POSTROUTING ─"
    sudo iptables -t nat -L POSTROUTING -n | grep "$UE_SUBNET" || log_warn "NAT MASQUERADE 없음"

    echo ""
    echo "─ ip_forward ─"
    echo "  /proc/sys/net/ipv4/ip_forward = $(cat /proc/sys/net/ipv4/ip_forward)"

    echo ""
}

# ─────────────────────────────────────────────────────────
# Main dispatch
# ─────────────────────────────────────────────────────────
main() {
    local cmd="${1:-all}"

    case "$cmd" in
        veth)
            require_sudo
            setup_veth
            ;;
        net)
            require_sudo
            setup_veth
            setup_bridge
            setup_iptables
            ;;
        docker)
            setup_docker
            ;;
        status)
            show_status
            ;;
        all|"")
            require_sudo
            setup_veth
            setup_docker
            setup_bridge
            setup_iptables
            print_env_reminders
            echo ""
            log_ok "전체 setup 완료"
            ;;
        help|-h|--help)
            sed -n '2,12p' "$0"
            ;;
        *)
            log_err "알 수 없는 명령: $cmd"
            log_info "사용 가능: veth, net, docker, status, all, help"
            exit 1
            ;;
    esac
}

main "$@"
