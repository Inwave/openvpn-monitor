#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "Execute como root: sudo ./deploy/install.sh" >&2
    exit 1
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
install_dir=/opt/openvpn-monitor-fast
env_file=/etc/default/openvpn-monitor
service_file=/etc/systemd/system/openvpn-monitor.service

command -v python3 >/dev/null || {
    echo "python3 não está instalado" >&2
    exit 1
}
command -v systemctl >/dev/null || {
    echo "systemd não está disponível" >&2
    exit 1
}

install -d -m 0755 "${install_dir}"
install -m 0644 "${repo_dir}/openvpn_monitor_fast.py" "${install_dir}/openvpn_monitor_fast.py"
install -m 0644 "${repo_dir}/README.md" "${install_dir}/README.md"
install -m 0644 "${repo_dir}/COPYING" "${install_dir}/COPYING"
install -m 0644 "${repo_dir}/requirements.txt" "${install_dir}/requirements.txt"

if [[ ! -x "${install_dir}/.venv/bin/python" ]]; then
    python3 -m venv "${install_dir}/.venv"
fi
"${install_dir}/.venv/bin/python" -m pip install \
    --requirement "${install_dir}/requirements.txt"

if [[ ! -e "${env_file}" ]]; then
    install -m 0600 "${repo_dir}/deploy/openvpn-monitor.env.example" "${env_file}"
else
    echo "Mantendo configuração existente: ${env_file}"
fi

install -m 0644 "${repo_dir}/deploy/openvpn-monitor.service" "${service_file}"
systemctl daemon-reload
systemctl enable openvpn-monitor.service
systemctl restart openvpn-monitor.service
systemctl --no-pager --full status openvpn-monitor.service
