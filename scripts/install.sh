#!/usr/bin/env bash
# install.sh - Bootstrap security-monitor stack on Ubuntu 22.04/24.04
set -euo pipefail

COMPOSE_VERSION="2.27.0"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log()  { echo "[INFO]  $*"; }
warn() { echo "[WARN]  $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

require_root() {
    [[ $EUID -eq 0 ]] || die "Run as root: sudo bash $0"
}

install_docker() {
    if command -v docker &>/dev/null; then
        log "Docker already installed: $(docker --version)"
        return
    fi
    log "Installing Docker..."
    apt-get update -qq
    apt-get install -y -qq ca-certificates curl gnupg lsb-release

    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg

    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        > /etc/apt/sources.list.d/docker.list

    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin
    systemctl enable --now docker
    log "Docker installed."
}

install_compose() {
    if docker compose version &>/dev/null 2>&1; then
        log "Docker Compose plugin already installed."
        return
    fi
    log "Installing Docker Compose plugin v${COMPOSE_VERSION}..."
    mkdir -p /usr/local/lib/docker/cli-plugins
    curl -SL "https://github.com/docker/compose/releases/download/v${COMPOSE_VERSION}/docker-compose-linux-$(uname -m)" \
        -o /usr/local/lib/docker/cli-plugins/docker-compose
    chmod +x /usr/local/lib/docker/cli-plugins/docker-compose
    log "Docker Compose installed: $(docker compose version)"
}

setup_env() {
    log "Project directory: $PROJECT_DIR"
    if [[ ! -d "$PROJECT_DIR" ]]; then
        die "Project directory not found: $PROJECT_DIR — run this script from inside the cloned repo."
    fi
    if [[ -f "$PROJECT_DIR/.env" ]]; then
        log ".env already exists, skipping."
        return
    fi
    if [[ -f "$PROJECT_DIR/.env.example" ]]; then
        cp "$PROJECT_DIR/.env.example" "$PROJECT_DIR/.env"
    else
        # Write defaults inline if .env.example wasn't shipped
        cat > "$PROJECT_DIR/.env" <<'EOF'
TIKG_MODEL=secureBERT
LOG_LEVEL=INFO
NETDATA_CLAIM_TOKEN=
NETDATA_CLAIM_URL=https://app.netdata.cloud
NETDATA_CLAIM_ROOMS=
EOF
    fi
    log "Created .env — edit $PROJECT_DIR/.env before starting if needed."
}

open_firewall() {
    if command -v ufw &>/dev/null && ufw status | grep -q "Status: active"; then
        log "Configuring UFW..."
        ufw allow 19999/tcp comment "Netdata dashboard"
        ufw allow 5000/tcp  comment "TiKG API"
        log "UFW rules added."
    else
        warn "UFW not active — ensure ports 19999 (Netdata) and 5000 (TiKG) are open."
    fi
}

build_and_start() {
    log "Building and starting containers (first run pulls images + builds TiKG)..."
    cd "$PROJECT_DIR"
    docker compose pull netdata
    docker compose build tikg-api
    docker compose up -d
    log "Stack is up."
}

print_summary() {
    local ip
    ip=$(hostname -I | awk '{print $1}')
    echo
    echo "================================================="
    echo "  Security Monitor deployed successfully!"
    echo "================================================="
    echo "  Netdata dashboard : http://${ip}:19999"
    echo "  TiKG API          : http://${ip}:5000"
    echo "  TiKG health check : http://${ip}:5000/health"
    echo "  TiKG metrics      : http://${ip}:5000/metrics"
    echo
    echo "  Submit a threat report for analysis:"
    echo "    curl -X POST http://${ip}:5000/analyze \\"
    echo "      -H 'Content-Type: application/json' \\"
    echo "      -d '{\"text\": \"APT28 deployed Industroyer malware...\", \"source\": \"manual\"}'"
    echo
    echo "  Logs: docker compose logs -f"
    echo "================================================="
}

main() {
    require_root
    install_docker
    install_compose
    setup_env
    open_firewall
    build_and_start
    print_summary
}

main "$@"
