#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Fast, read-only OpenVPN status page.

The application reads OpenVPN's existing status file instead of querying the
management socket on every HTTP request. Parsed data is cached by file mtime;
an incomplete write never replaces the last known-good snapshot.
"""

import csv
import html
import io
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime
from urllib.parse import parse_qs, urlencode


STATUS_PATH = os.environ.get(
    "OPENVPN_STATUS_PATH", "/var/log/openvpn/openvpn-status.log"
)
SITE_NAME = os.environ.get("OPENVPN_MONITOR_SITE", "OpenVPN Monitor")
MAX_STATUS_BYTES = int(os.environ.get("OPENVPN_STATUS_MAX_BYTES", 8 * 1024 * 1024))
PAGE_SIZE = int(os.environ.get("OPENVPN_MONITOR_PAGE_SIZE", 200))
MAX_QUERY_LENGTH = 128
MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
MAC_COMPACT_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
SORT_COLUMNS = (
    ("identity", "Identidade"),
    ("vpn_ip", "IP VPN"),
    ("mac", "MAC"),
    ("remote", "Endereço real"),
    ("bytes_in", "Recebido"),
    ("bytes_out", "Enviado"),
    ("connected", "Conectado desde"),
    ("last_seen", "Última atividade"),
    ("online", "Tempo online"),
)
SORT_KEYS = frozenset(key for key, _label in SORT_COLUMNS)


def _field(record, name):
    value = record.get(name, "")
    return "" if value is None else str(value)


def _integer(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _normalise_mac(value):
    if MAC_COMPACT_RE.match(value or ""):
        compact = (value or "").upper()
        return ":".join(compact[index : index + 2] for index in range(0, 12, 2))
    if not MAC_RE.match(value or ""):
        return None
    return (value or "").replace("-", ":").upper()


def parse_status(data, source_mtime):
    """Parse OpenVPN status-version 2/CSV output into a bounded snapshot."""
    headers = {}
    clients = []
    routes = []
    status_time = None
    title = "OpenVPN"
    end_seen = False

    for row in csv.reader(io.StringIO(data)):
        if not row:
            continue
        record_type = row[0]
        if record_type == "TITLE" and len(row) > 1:
            title = row[1]
        elif record_type == "TIME" and len(row) > 2:
            status_time = _integer(row[2], None)
        elif record_type == "HEADER" and len(row) > 2:
            headers[row[1]] = row[2:]
        elif record_type in ("CLIENT_LIST", "ROUTING_TABLE"):
            header = headers.get(record_type)
            if not header:
                raise ValueError("registro antes do cabeçalho: {}".format(record_type))
            values = row[1:]
            record = {
                name: values[index] if index < len(values) else ""
                for index, name in enumerate(header)
            }
            if record_type == "CLIENT_LIST":
                clients.append(record)
            else:
                routes.append(record)
        elif record_type == "END":
            end_seen = True

    if not end_seen:
        raise ValueError("arquivo de status incompleto: marcador END ausente")
    if "CLIENT_LIST" not in headers or "ROUTING_TABLE" not in headers:
        raise ValueError("cabeçalhos obrigatórios ausentes")

    route_index = {}
    for route in routes:
        key = (_field(route, "Common Name"), _field(route, "Real Address"))
        route_index.setdefault(key, []).append(route)

    sessions = []
    for client in clients:
        common_name = _field(client, "Common Name")
        real_address = _field(client, "Real Address")
        matching_routes = route_index.get((common_name, real_address), [])
        route_macs = {
            mac
            for mac in (
                _normalise_mac(_field(route, "Virtual Address"))
                for route in matching_routes
            )
            if mac
        }
        identity_mac = _normalise_mac(common_name)
        if identity_mac:
            route_macs.add(identity_mac)
        macs = sorted(
            {
                mac
                for mac in route_macs
                if mac
            }
        )
        last_route = max(
            matching_routes,
            key=lambda route: _integer(_field(route, "Last Ref (time_t)")),
            default={},
        )
        username = _field(client, "Username")
        identity = username if username and username != "UNDEF" else common_name
        sessions.append(
            {
                "identity": identity,
                "common_name": common_name,
                "vpn_ip": _field(client, "Virtual Address")
                or _field(client, "Virtual IPv6 Address"),
                "remote": real_address,
                "macs": macs,
                "bytes_in": _integer(_field(client, "Bytes Received")),
                "bytes_out": _integer(_field(client, "Bytes Sent")),
                "connected_since": _field(client, "Connected Since"),
                "connected_epoch": _integer(
                    _field(client, "Connected Since (time_t)"), None
                ),
                "last_seen": _field(last_route, "Last Ref"),
                "last_seen_epoch": _integer(
                    _field(last_route, "Last Ref (time_t)"), None
                ),
            }
        )

    sessions.sort(key=lambda item: (item["identity"].casefold(), item["vpn_ip"]))
    return {
        "title": title,
        "source_mtime": source_mtime,
        "status_time": status_time or int(source_mtime),
        "sessions": sessions,
        "route_count": len(routes),
    }


class StatusCache:
    def __init__(self, path=STATUS_PATH, max_bytes=MAX_STATUS_BYTES):
        self.path = path
        self.max_bytes = max_bytes
        self._lock = threading.Lock()
        self._signature = None
        self._snapshot = None
        self._last_error = None

    def load(self):
        with self._lock:
            try:
                before = os.stat(self.path)
                signature = (before.st_mtime_ns, before.st_size)
                if self._snapshot is not None and signature == self._signature:
                    return self._snapshot, None
                if before.st_size <= 0 or before.st_size > self.max_bytes:
                    raise ValueError("tamanho do status fora do limite")

                last_exception = None
                for attempt in range(3):
                    try:
                        with open(self.path, "r", encoding="utf-8", errors="replace") as source:
                            data = source.read(self.max_bytes + 1)
                        if len(data.encode("utf-8")) > self.max_bytes:
                            raise ValueError("status excedeu o limite durante a leitura")
                        after = os.stat(self.path)
                        if (
                            before.st_mtime_ns != after.st_mtime_ns
                            or before.st_size != after.st_size
                        ):
                            before = after
                            if attempt < 2:
                                time.sleep(0.05)
                                continue
                            raise ValueError("status mudou durante a leitura")
                        snapshot = parse_status(data, after.st_mtime)
                        self._snapshot = snapshot
                        self._signature = (after.st_mtime_ns, after.st_size)
                        self._last_error = None
                        return snapshot, None
                    except (OSError, UnicodeError, ValueError) as exc:
                        last_exception = exc
                        if attempt < 2:
                            time.sleep(0.05)
                raise last_exception
            except (OSError, UnicodeError, ValueError) as exc:
                self._last_error = str(exc)
                if self._snapshot is not None:
                    return self._snapshot, self._last_error
                raise


STATUS_CACHE = StatusCache()


def _format_bytes(value):
    amount = float(max(0, value))
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if amount < 1024 or unit == "TiB":
            return "{:.0f} {}".format(amount, unit) if unit == "B" else "{:.1f} {}".format(amount, unit)
        amount /= 1024


def _format_duration(start_epoch):
    if not start_epoch:
        return "—"
    seconds = max(0, int(time.time()) - start_epoch)
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, _ = divmod(seconds, 60)
    if days:
        return "{}d {:02d}h".format(days, hours)
    if hours:
        return "{}h {:02d}m".format(hours, minutes)
    return "{}m".format(minutes)


def _safe(value):
    return html.escape(str(value or "—"), quote=True)


def _page_url(page, query, sort_key, sort_direction):
    params = {
        "page": page,
        "sort": sort_key,
        "dir": sort_direction,
    }
    if query:
        params["q"] = query
    return "/?{}".format(urlencode(params))


def _sort_value(session, sort_key):
    if sort_key == "vpn_ip":
        try:
            address = ipaddress.ip_address(session["vpn_ip"])
            return (0, address.version, int(address), "")
        except ValueError:
            return (1, 0, 0, session["vpn_ip"].casefold())
    if sort_key == "mac":
        return (0, " ".join(session["macs"]).casefold())
    if sort_key == "remote":
        return (0, session["remote"].casefold())
    if sort_key in ("bytes_in", "bytes_out"):
        return (0, session[sort_key])
    if sort_key == "connected":
        return (0, session["connected_epoch"] or 0)
    if sort_key == "last_seen":
        return (0, session["last_seen_epoch"] or 0)
    if sort_key == "online":
        connected_epoch = session["connected_epoch"]
        return (0, max(0, int(time.time()) - connected_epoch) if connected_epoch else 0)
    return (0, session["identity"].casefold())


def sort_sessions(sessions, sort_key="identity", sort_direction="asc"):
    """Return a sorted copy without changing the cached snapshot."""
    if sort_key not in SORT_KEYS:
        sort_key = "identity"
    if sort_direction not in ("asc", "desc"):
        sort_direction = "asc"
    return sorted(
        sessions,
        key=lambda session: (
            _sort_value(session, sort_key),
            session["identity"].casefold(),
            session["vpn_ip"],
        ),
        reverse=sort_direction == "desc",
    )


def _sort_headers(query, sort_key, sort_direction):
    headers = []
    for key, label in SORT_COLUMNS:
        active = key == sort_key
        next_direction = "desc" if active and sort_direction == "asc" else "asc"
        indicator = " &#9650;" if active and sort_direction == "asc" else " &#9660;" if active else ""
        url = _page_url(1, query, key, next_direction)
        aria_sort = (
            "ascending" if active and sort_direction == "asc" else
            "descending" if active else "none"
        )
        headers.append(
            "<th aria-sort='{}'><a href='{}'>{}{}</a></th>".format(
                aria_sort,
                _safe(url),
                _safe(label),
                indicator,
            )
        )
    return "".join(headers)


def render_page(
    snapshot,
    query="",
    page=1,
    warning=None,
    sort_key="identity",
    sort_direction="asc",
):
    if sort_key not in SORT_KEYS:
        sort_key = "identity"
    if sort_direction not in ("asc", "desc"):
        sort_direction = "asc"
    sessions = snapshot["sessions"]
    if query:
        needle = query.casefold()
        sessions = [
            session
            for session in sessions
            if needle
            in " ".join(
                [
                    session["identity"],
                    session["common_name"],
                    session["vpn_ip"],
                    session["remote"],
                    " ".join(session["macs"]),
                ]
            ).casefold()
        ]
    sessions = sort_sessions(sessions, sort_key, sort_direction)

    page_size = max(25, min(PAGE_SIZE, 500))
    total = len(sessions)
    page_count = max(1, (total + page_size - 1) // page_size)
    page = max(1, min(page, page_count))
    offset = (page - 1) * page_size
    visible = sessions[offset : offset + page_size]
    generated = datetime.fromtimestamp(snapshot["status_time"]).strftime("%d/%m/%Y %H:%M:%S")
    age = max(0, int(time.time() - snapshot["status_time"]))

    parts = [
        "<!doctype html><html lang='pt-BR'><head><meta charset='utf-8'>",
        "<meta name='viewport' content='width=device-width,initial-scale=1'>",
        "<meta http-equiv='refresh' content='60'>",
        "<title>{} - conexões OpenVPN</title>".format(_safe(SITE_NAME)),
        "<style>",
        "body{font:14px system-ui,-apple-system,sans-serif;margin:0;background:#f5f6f8;color:#20242a}",
        "header{background:#20252b;color:#fff;padding:16px 24px}h1{font-size:20px;margin:0}",
        "main{padding:18px 24px}.summary,.notice{background:#fff;border:1px solid #dfe3e8;border-radius:7px;padding:12px 14px;margin-bottom:14px}",
        ".notice{border-color:#e0aa28;background:#fff8e5}.muted{color:#66707a}.grid{display:flex;gap:24px;flex-wrap:wrap}",
        "form{display:flex;gap:8px;margin:12px 0}input{min-width:300px;max-width:520px;width:45%;padding:8px;border:1px solid #b8c0c8;border-radius:5px}",
        "button,.button{padding:8px 12px;border:0;border-radius:5px;background:#1769aa;color:#fff;text-decoration:none}",
        ".table-wrap{overflow:auto;background:#fff;border:1px solid #dfe3e8;border-radius:7px}",
        "table{border-collapse:collapse;width:100%;white-space:nowrap}th,td{padding:8px 10px;border-bottom:1px solid #e7eaee;text-align:left}",
        "th{position:sticky;top:0;background:#eceff2}th a{display:block;color:#20242a;text-decoration:none}th a:hover{text-decoration:underline}tbody tr:nth-child(even){background:#fafbfc}",
        ".pager{display:flex;justify-content:space-between;align-items:center;margin-top:14px}.disabled{opacity:.45;pointer-events:none}",
        "@media(max-width:700px){main{padding:12px}input{width:100%;min-width:0}}",
        "</style></head><body><header><h1>{} — conexões OpenVPN</h1></header><main>".format(_safe(SITE_NAME)),
    ]
    if warning:
        parts.append(
            "<div class='notice'><strong>Dados em cache.</strong> A última leitura completa foi mantida; uma nova tentativa ocorrerá automaticamente.</div>"
        )
    parts.extend(
        [
            "<div class='summary grid'><div><strong>{}</strong> conexões exibidas</div>".format(total),
            "<div><strong>{}</strong> conexões totais</div>".format(len(snapshot["sessions"])),
            "<div class='muted'>Atualizado em {} (há {}s)</div></div>".format(_safe(generated), age),
            "<form method='get' action='/'><input type='hidden' name='sort' value='{}'><input type='hidden' name='dir' value='{}'><input name='q' maxlength='{}' value='{}' placeholder='Buscar identidade, IP ou MAC'>".format(_safe(sort_key), _safe(sort_direction), MAX_QUERY_LENGTH, _safe(query)),
            "<button type='submit'>Buscar</button><a class='button' href='/'>Limpar</a></form>",
            "<div class='table-wrap'><table><thead><tr>{}</tr></thead><tbody>".format(_sort_headers(query, sort_key, sort_direction)),
        ]
    )
    for session in visible:
        parts.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _safe(session["identity"]),
                _safe(session["vpn_ip"]),
                _safe(", ".join(session["macs"])),
                _safe(session["remote"]),
                _safe(_format_bytes(session["bytes_in"])),
                _safe(_format_bytes(session["bytes_out"])),
                _safe(session["connected_since"]),
                _safe(session["last_seen"]),
                _safe(_format_duration(session["connected_epoch"])),
            )
        )
    previous_class = "button" if page > 1 else "button disabled"
    next_class = "button" if page < page_count else "button disabled"
    parts.extend(
        [
            "</tbody></table></div>",
            "<div class='pager'><a class='{}' href='{}'>Anterior</a><span>Página {} de {}</span><a class='{}' href='{}'>Próxima</a></div>".format(
                previous_class,
                _safe(_page_url(max(1, page - 1), query, sort_key, sort_direction)),
                page,
                page_count,
                next_class,
                _safe(_page_url(min(page_count, page + 1), query, sort_key, sort_direction)),
            ),
            "</main></body></html>",
        ]
    )
    return "".join(parts).encode("utf-8")


def render_legacy_json(snapshot):
    """Preserve the old ?get_json=1 identity-to-VPN-IP contract."""
    identities = {
        session["identity"]: session["vpn_ip"]
        for session in snapshot["sessions"]
        if session["identity"] and session["vpn_ip"]
    }
    return json.dumps(
        identities,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def application(environ, start_response):
    method = environ.get("REQUEST_METHOD", "GET").upper()
    if method not in ("GET", "HEAD"):
        body = b"Method Not Allowed\n"
        start_response("405 Method Not Allowed", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [body]

    try:
        snapshot, warning = STATUS_CACHE.load()
    except (OSError, UnicodeError, ValueError):
        body = b"Status OpenVPN temporariamente indisponivel. Tente novamente.\n"
        start_response("503 Service Unavailable", [("Content-Type", "text/plain; charset=utf-8"), ("Retry-After", "5"), ("Content-Length", str(len(body)))])
        return [b"" if method == "HEAD" else body]

    path = environ.get("PATH_INFO", "/")
    if path == "/healthz":
        payload = json.dumps(
            {
                "ok": True,
                "clients": len(snapshot["sessions"]),
                "status_age_seconds": max(0, int(time.time() - snapshot["status_time"])),
                "cached_after_error": bool(warning),
            },
            separators=(",", ":"),
        ).encode("utf-8")
        start_response("200 OK", [("Content-Type", "application/json"), ("Cache-Control", "no-store"), ("Content-Length", str(len(payload)))])
        return [b"" if method == "HEAD" else payload]
    if path != "/":
        body = b"Not Found\n"
        start_response("404 Not Found", [("Content-Type", "text/plain; charset=utf-8"), ("Content-Length", str(len(body)))])
        return [b"" if method == "HEAD" else body]

    params = parse_qs(environ.get("QUERY_STRING", ""), keep_blank_values=False)
    if params.get("get_json", [""])[0]:
        body = render_legacy_json(snapshot)
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Length", str(len(body))),
        ]
        start_response("200 OK", headers)
        return [b"" if method == "HEAD" else body]

    query = params.get("q", [""])[0][:MAX_QUERY_LENGTH].strip()
    sort_key = params.get("sort", ["identity"])[0]
    if sort_key not in SORT_KEYS:
        sort_key = "identity"
    sort_direction = params.get("dir", ["asc"])[0]
    if sort_direction not in ("asc", "desc"):
        sort_direction = "asc"
    try:
        page = int(params.get("page", ["1"])[0])
    except (TypeError, ValueError):
        page = 1
    body = render_page(
        snapshot,
        query=query,
        page=page,
        warning=warning,
        sort_key=sort_key,
        sort_direction=sort_direction,
    )
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Content-Length", str(len(body))),
    ]
    start_response("200 OK", headers)
    return [b"" if method == "HEAD" else body]


def run_server(argv=None):
    """Run a small local WSGI server for development and diagnostics."""
    global PAGE_SIZE, SITE_NAME, STATUS_CACHE

    import argparse
    import sys
    from wsgiref.simple_server import make_server

    parser = argparse.ArgumentParser(
        description="Run the read-only OpenVPN status monitor locally."
    )
    parser.add_argument(
        "--bind",
        default=os.environ.get("OPENVPN_MONITOR_BIND", "127.0.0.1"),
        help="Address to listen on (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        default=int(os.environ.get("OPENVPN_MONITOR_PORT", "8081")),
        type=int,
        help="TCP port to listen on (default: 8081)",
    )
    parser.add_argument(
        "--status-path",
        default=STATUS_PATH,
        help="OpenVPN status-version 2 CSV file",
    )
    parser.add_argument(
        "--site",
        default=SITE_NAME,
        help="Site name shown in the page header",
    )
    parser.add_argument(
        "--page-size",
        default=PAGE_SIZE,
        type=int,
        help="Rows per page, from 25 to 500 (default: 200)",
    )
    parser.add_argument(
        "--max-status-bytes",
        default=MAX_STATUS_BYTES,
        type=int,
        help="Maximum accepted status file size in bytes",
    )
    options = parser.parse_args(argv)

    if not 1 <= options.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not 25 <= options.page_size <= 500:
        parser.error("--page-size must be between 25 and 500")
    if options.max_status_bytes <= 0:
        parser.error("--max-status-bytes must be greater than zero")
    if not os.path.isfile(options.status_path):
        parser.error("status file does not exist: {}".format(options.status_path))
    if not os.access(options.status_path, os.R_OK):
        parser.error("status file is not readable: {}".format(options.status_path))

    PAGE_SIZE = options.page_size
    SITE_NAME = options.site
    STATUS_CACHE = StatusCache(options.status_path, options.max_status_bytes)

    server = make_server(options.bind, options.port, application)
    print(
        "OpenVPN Monitor Fast listening on http://{}:{}/".format(
            options.bind, options.port
        ),
        file=sys.stderr,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping OpenVPN Monitor Fast.", file=sys.stderr)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(run_server())
