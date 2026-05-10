#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
project_name="${COMPOSE_PROJECT_NAME:-prowler-upstream}"
tmux_session="${TMUX_SESSION:-prowler-upstream}"
prod_compose_file="docker-compose.yml"
dev_compose_file="docker-compose-dev.yml"

source "$repo_root/dev_scripts/local_env.sh"

prod_compose() {
  COMPOSE_PROJECT_NAME="$project_name" docker compose -f "$prod_compose_file" "$@"
}

dev_compose() {
  COMPOSE_PROJECT_NAME="$project_name" docker compose -f "$dev_compose_file" "$@"
}

ensure_docker() {
  if docker info >/dev/null 2>&1; then
    return
  fi

  if [[ "$(uname -s)" == "Darwin" && -d "/Applications/Docker.app" ]]; then
    echo "Docker is not running. Starting Docker Desktop..."
    open -a Docker

    for _ in $(seq 1 60); do
      if docker info >/dev/null 2>&1; then
        echo "Docker is ready."
        return
      fi
      sleep 2
    done
  fi

  echo "Docker is not running or is not reachable."
  echo "Start Docker Desktop and rerun: ./dev_setup.sh dev"
  exit 1
}

kill_port() {
  local port="$1"
  local pids

  pids="$(lsof -ti:"$port" 2>/dev/null || true)"
  if [[ -n "$pids" ]]; then
    kill -9 $pids 2>/dev/null || true
  fi
}

build_tmux_command() {
  local command="$1"
  local wrapped

  wrapped="$command; status=\$?; echo; echo \"[dev_setup] command exited with status \$status\"; exec \"\${SHELL:-/bin/zsh}\" -l"
  printf 'bash -lc %q' "$wrapped"
}

print_urls() {
  echo
  echo "Prowler is running:"
  echo "  UI:  http://localhost:$(read_env_value UI_HOST_PORT 13000)"
  echo "  API: http://127.0.0.1:$(read_env_value DJANGO_HOST_PORT 18080)/api/v1/"
  echo "  MCP: http://127.0.0.1:$(read_env_value MCP_HOST_PORT 18000)/health"
  echo
}

start_dev_services() {
  ensure_docker

  if ! command -v tmux >/dev/null 2>&1; then
    echo "tmux is not installed. Install it first: brew install tmux"
    exit 1
  fi

  echo "Stopping Docker dev app containers..."
  dev_compose stop api-dev ui-dev worker-dev worker-beat mcp-server >/dev/null 2>&1 || true

  echo "Starting Docker backing services..."
  "$repo_root/dev_scripts/services.sh"

  chmod +x "$repo_root"/dev_scripts/*.sh

  tmux kill-session -t "$tmux_session" 2>/dev/null || true
  kill_port "$(read_env_value UI_HOST_PORT 13000)"
  kill_port "$(read_env_value DJANGO_HOST_PORT 18080)"
  kill_port "$(read_env_value MCP_HOST_PORT 18000)"

  echo "Starting local dev processes in tmux session '${tmux_session}'..."
  tmux new-session -d -s "$tmux_session" -n api -c "$repo_root" "$(build_tmux_command './dev_scripts/api.sh')"
  tmux set -g mouse on
  tmux new-window -t "$tmux_session" -n ui -c "$repo_root" "$(build_tmux_command './dev_scripts/ui.sh')"
  tmux new-window -t "$tmux_session" -n mcp -c "$repo_root" "$(build_tmux_command './dev_scripts/mcp.sh')"
  tmux new-window -t "$tmux_session" -n worker -c "$repo_root" "$(build_tmux_command "./dev_scripts/wait_for_port.sh '$(read_env_value DJANGO_HOST_PORT 18080)' 'API' && ./dev_scripts/celery_worker.sh")"
  tmux new-window -t "$tmux_session" -n beat -c "$repo_root" "$(build_tmux_command "./dev_scripts/wait_for_port.sh '$(read_env_value DJANGO_HOST_PORT 18080)' 'API' && ./dev_scripts/celery_beat.sh")"

  print_urls
  echo "Attach with: tmux attach-session -t ${tmux_session}"
}

start_prod_services() {
  ensure_docker
  echo "Starting Prowler with prebuilt images from ${prod_compose_file}..."
  prod_compose up -d --remove-orphans
  print_urls
}

stop_services() {
  echo "Stopping local dev processes..."
  tmux kill-session -t "$tmux_session" 2>/dev/null || true
  kill_port "$(read_env_value UI_HOST_PORT 13000)"
  kill_port "$(read_env_value DJANGO_HOST_PORT 18080)"
  kill_port "$(read_env_value MCP_HOST_PORT 18000)"

  if docker info >/dev/null 2>&1; then
    echo "Stopping Docker services..."
    dev_compose down --remove-orphans
    prod_compose down --remove-orphans
  fi
}

reset_services() {
  ensure_docker
  stop_services
  dev_compose down --volumes --remove-orphans
  prod_compose down --volumes --remove-orphans
  rm -rf "$repo_root/_data"
  start_dev_services
}

show_status() {
  echo "tmux:"
  tmux list-windows -t "$tmux_session" 2>/dev/null || true
  echo

  if docker info >/dev/null 2>&1; then
    echo "docker:"
    dev_compose ps postgres valkey neo4j
  fi
}

show_logs() {
  if docker info >/dev/null 2>&1; then
    dev_compose logs -f "${@:2}"
  fi
}

usage() {
  echo "Usage: ./dev_setup.sh {dev|prod|stop|restart|reset|status|logs}"
  echo
  echo "Commands:"
  echo "  dev      Run API/UI/MCP/workers locally; Docker only for backing services"
  echo "  prod     Run prebuilt upstream Docker images"
}

cd "$repo_root"

case "${1:-}" in
  dev)
    start_dev_services
    ;;
  prod)
    start_prod_services
    ;;
  stop)
    stop_services
    ;;
  restart)
    stop_services
    start_dev_services
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
