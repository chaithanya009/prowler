#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_name="${COMPOSE_PROJECT_NAME:-prowler-upstream}"
compose_file="${COMPOSE_FILE:-docker-compose.yml}"

compose() {
    COMPOSE_PROJECT_NAME="$project_name" docker compose -f "$compose_file" "$@"
}

read_env_value() {
    local key="$1"
    local fallback="$2"
    local value

    value="$(grep -E "^${key}=" "$repo_root/.env" 2>/dev/null | tail -n 1 | cut -d '=' -f 2- | tr -d '"')" || true

    if [[ -n "$value" ]]; then
        printf "%s" "$value"
        return
    fi

    printf "%s" "$fallback"
}

print_urls() {
    local ui_port
    local api_port
    local mcp_port

    ui_port="$(read_env_value UI_HOST_PORT 3000)"
    api_port="$(read_env_value DJANGO_HOST_PORT 8080)"
    mcp_port="$(read_env_value MCP_HOST_PORT 8000)"

    echo
    echo "Prowler is running:"
    echo "  UI:  http://localhost:${ui_port}"
    echo "  API: http://127.0.0.1:${api_port}/api/v1/"
    echo "  MCP: http://127.0.0.1:${mcp_port}/health"
    echo
}

require_docker() {
    if ! docker info >/dev/null 2>&1; then
        echo "Docker is not running. Start Docker Desktop and run this again."
        exit 1
    fi
}

start_services() {
    require_docker
    echo "Starting Prowler with ${compose_file}..."
    compose up -d --remove-orphans
    print_urls
}

start_dev_services() {
    compose_file="docker-compose-dev.yml"
    require_docker
    echo "Starting Prowler dev containers with ${compose_file}..."
    compose up -d --build --remove-orphans
    print_urls
}

stop_services() {
    require_docker
    echo "Stopping Prowler..."
    compose down --remove-orphans
}

restart_services() {
    stop_services
    start_services
}

reset_services() {
    require_docker
    echo "Resetting Prowler data and containers..."
    compose down --volumes --remove-orphans
    rm -rf "$repo_root/_data"
    start_services
}

show_status() {
    require_docker
    compose ps
}

show_logs() {
    require_docker
    compose logs -f "${@:2}"
}

usage() {
    echo "Usage: ./dev_setup.sh {start|dev|stop|restart|reset|status|logs}"
    echo
    echo "Defaults:"
    echo "  COMPOSE_PROJECT_NAME=${project_name}"
    echo "  COMPOSE_FILE=${compose_file}"
}

cd "$repo_root"

case "${1:-start}" in
    start)
        start_services
        ;;
    dev)
        start_dev_services
        ;;
    stop)
        stop_services
        ;;
    restart)
        restart_services
        ;;
    reset)
        reset_services
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs "$@"
        ;;
    *)
        usage
        exit 1
        ;;
esac
