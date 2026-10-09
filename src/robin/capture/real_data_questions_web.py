"""Localhost pages and exports for the explorer questions, layered on the existing server.

Every route outside ``/questions`` is served unchanged by the existing explorer handler.
Pages are rendered server-side from the same payloads as the CSV and JSON exports.
"""

from __future__ import annotations

import base64
import hashlib
import html
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import cast

from robin.capture.real_data_explorer import AtomicExplorerStore, BundleValidationError, _handler
from robin.capture.real_data_questions import (
    Q1_RULES,
    AcquisitionCatalog,
    CatalogView,
    QuestionError,
    answer_q1,
    answer_q3,
    list_selections,
    summarize_q1,
    to_csv_bytes,
    to_json_bytes,
)

_STYLE = (
    "body{font:15px/1.45 system-ui,sans-serif;margin:24px;color:#1b1f24;background:#fff}"
    "table{border-collapse:collapse;margin:12px 0}th,td{border:1px solid #c9d1d9;padding:4px 8px;"
    "text-align:left;vertical-align:top}th{background:#f3f5f7}.notice{background:#fff8e1;"
    "padding:8px 12px;border-left:4px solid #b7791f}.paris{color:#57606a}nav a{margin-right:16px}"
    "@media(prefers-color-scheme:dark){body{color:#e6edf3;background:#0d1117}th{background:#161b22}"
    "th,td{border-color:#30363d}.notice{background:#2d2200}.paris{color:#8b949e}a{color:#58a6ff}}"
)
_SCRIPT = (
    'const f=new Intl.DateTimeFormat("fr-FR",{timeZone:"Europe/Paris",dateStyle:"short",'
    'timeStyle:"medium"});for(const t of document.querySelectorAll("time[datetime]")){'
    'const d=new Date(t.dateTime);if(!isNaN(d)){const s=document.createElement("span");'
    's.className="paris";s.textContent=" · "+f.format(d)+" Paris";t.after(s);}}'
)


def _digest(text: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode()


CONTENT_SECURITY_POLICY = (
    f"default-src 'none'; style-src '{_digest(_STYLE)}'; script-src '{_digest(_SCRIPT)}'; "
    "form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
)
_Q1_STATUSES = ("INCLUDED", "EXCLUDED", "PENDING", "OUT_OF_STORE")
_OPTIONS = (
    "previous",
    "current",
    "event",
    "sport",
    "market",
    "outcome",
    "point",
    "period",
    "provider",
)
_LABELS = {
    "UP": "Hausse",
    "DOWN": "Baisse",
    "UNCHANGED": "Inchangée",
    "APPEARED": "Apparue dans l'acquisition récente (cause non attestée)",
    "NOT_OBSERVED": "Non observée dans l'acquisition récente (cause non attestée)",
    "EVENT_STARTED_BEFORE_CURRENT": "Match commencé avant l'acquisition récente",
    "EXCLUDED": "Exclu(e)",
    "COMPARED": "Comparée",
    "INCLUDED": "Inclus",
    "PENDING": "En attente : coup d'envoi après la dernière acquisition",
    "OUT_OF_STORE": "Hors stock : la référence précède le stock local",
    "J_MINUS_24H": "J−24 h (±60 min)",
    "NEAR": "Proche (±180 min)",
    "WITHIN_2H": "≤ 2 h avant",
    "WITHIN_6H": "≤ 6 h avant",
}
_ERRORS = {
    "ACQUISITION_UNKNOWN": "Acquisition absente du stock local vérifié.",
    "Q3_SAME_ACQUISITION": "Choisir deux acquisitions différentes.",
    "Q3_ORDER_INVALID": "L'acquisition de référence doit précéder l'acquisition comparée.",
    "SELECTION_NOT_FOUND": "Aucune offre ne correspond exactement à cette sélection.",
    "SELECTION_AMBIGUOUS": "Sélection ambiguë : préciser le fournisseur et la période.",
    "QUERY_INVALID": "Requête invalide.",
}


def _e(value: object) -> str:
    return html.escape("—" if value is None or value == "" else str(value), quote=True)


def _label(value: object) -> str:
    text = str(value) if value is not None else ""
    head, _, tail = text.partition(":")
    label = _LABELS.get(head, head)
    return _e(f"{label} ({tail})" if tail else label or None)


def _time(value: object) -> str:
    if not isinstance(value, str) or not value:
        return "—"
    return f'<time datetime="{_e(value)}">{_e(value)}</time>'


def _url(path: str, params: Mapping[str, object]) -> str:
    query = urllib.parse.urlencode(
        [(name, "" if value is None else str(value)) for name, value in params.items()]
    )
    return f"{path}?{query}" if query else path


def _link(path: str, params: Mapping[str, object], label: str) -> str:
    return f'<a href="{_e(_url(path, params))}">{_e(label)}</a>'


def _table(headers: Sequence[str], rows: Sequence[Sequence[str]]) -> str:
    head = "".join(f"<th>{_e(name)}</th>" for name in headers)
    body = "".join("<tr>" + "".join(f"<td>{cell}</td>" for cell in row) + "</tr>" for row in rows)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table>"


def _page(title: str, body: str) -> bytes:
    document = (
        '<!doctype html><html lang="fr"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body>"
        '<nav><a href="/robin-real-data.html">Explorateur</a><a href="/questions">Questions</a>'
        '<a href="/questions/q3">Q3 · deux acquisitions</a><a href="/questions/q1">Q1 · favori</a>'
        f"</nav><h1>{_e(title)}</h1>{body}<script>{_SCRIPT}</script></body></html>"
    )
    return document.encode("utf-8")


def _notice(text: str) -> str:
    return f'<p class="notice">{_e(text)}</p>'


def _acquisition_label(view: CatalogView, run_id: object) -> str:
    try:
        item = view.by_run(str(run_id))
    except QuestionError:
        return _e(run_id)
    view_link = _link(f"/history/{item.run_id}/robin-real-data.html", {}, "vue")
    return f"{_time(item.slot_start_utc)} · run {_e(item.run_id)} · {view_link}"


def _q1_overview(summary: Mapping[str, object]) -> list[list[str]]:
    rows = [
        [_label(name), _e(count)]
        for name, count in cast(dict[str, int], summary["status_counts"]).items()
    ]
    rows += [
        [_e(name), _e(count)]
        for name, count in cast(dict[str, int], summary["exclusion_reason_counts"]).items()
    ]

    def joined(name: str) -> str:
        return " / ".join(_e(value) for value in cast(dict[str, int], summary[name]).values())

    return rows + [
        ["Référence J−24 h / proche", joined("reference_class_counts")],
        ["Dernière observation ≤ 2 h / ≤ 6 h", joined("last_prematch_class_counts")],
        ["Inclus avec fenêtres strictes", _e(summary["included_strict_windows"])],
        [
            "Consensus du favori (baisse / hausse / inchangé)",
            joined("included_consensus_direction"),
        ],
        [
            "Médiane des écarts de médianes (inclus)",
            _e(summary["included_median_of_median_delta"]),
        ],
    ]


class QuestionPages:
    """Pure request → response mapping, so pages are testable without sockets."""

    def __init__(self, catalog: AcquisitionCatalog) -> None:
        self.catalog = catalog
        self._q1_cache: tuple[object, dict[str, object]] | None = None

    def respond(self, path: str, query: str) -> tuple[HTTPStatus, bytes, str, dict[str, str]]:
        try:
            values = urllib.parse.parse_qs(query, keep_blank_values=True, max_num_fields=16)
            options: dict[str, str] = {name: values[name][0] for name in _OPTIONS if name in values}
            filters: dict[str, str] = {
                name: values[name][0] for name in ("status", "strict") if name in values
            }
            if path in {"/questions", "/questions/"}:
                return self._html("Questions sur les acquisitions réelles", self._index())
            if path == "/questions/q3":
                return self._html("Q3 · comparer deux acquisitions", self._q3(options))
            if path == "/questions/q1":
                return self._html("Q1 · mouvement de la cote du favori", self._q1(filters))
            if path in {"/questions/q3.json", "/questions/q3.csv"}:
                payload = answer_q3(self.catalog, options)
                return self._export(payload, path, "robin-q3-selection")
            if path in {"/questions/q1.json", "/questions/q1.csv"}:
                payload = self._filtered_q1(filters)
                return self._export(payload, path, "robin-q1-favori")
            return HTTPStatus.NOT_FOUND, b"not found\n", "text/plain; charset=utf-8", {}
        except QuestionError as exc:
            code = str(exc)
            body = _notice(f"{_ERRORS.get(code, 'Refus')} Code : {code}")
            return self._html("Requête refusée", body, HTTPStatus.BAD_REQUEST)
        except (BundleValidationError, OSError):
            body = _notice("Stock local illisible. Code : LOCAL_STORE_UNAVAILABLE")
            return self._html("Stock indisponible", body, HTTPStatus.SERVICE_UNAVAILABLE)
        except ValueError:
            body = _notice(f"{_ERRORS['QUERY_INVALID']} Code : QUERY_INVALID")
            return self._html("Requête refusée", body, HTTPStatus.BAD_REQUEST)

    def _html(
        self, title: str, body: str, status: HTTPStatus = HTTPStatus.OK
    ) -> tuple[HTTPStatus, bytes, str, dict[str, str]]:
        headers = {"Content-Security-Policy": CONTENT_SECURITY_POLICY}
        return status, _page(title, body), "text/html; charset=utf-8", headers

    def _export(
        self, payload: Mapping[str, object], path: str, stem: str
    ) -> tuple[HTTPStatus, bytes, str, dict[str, str]]:
        suffix = path.rsplit(".", 1)[1]
        content = to_csv_bytes(payload) if suffix == "csv" else to_json_bytes(payload)
        kind = "text/csv" if suffix == "csv" else "application/json"
        disposition = {"Content-Disposition": f'attachment; filename="{stem}.{suffix}"'}
        return HTTPStatus.OK, content, f"{kind}; charset=utf-8", disposition

    def _index(self) -> str:
        view = self.catalog.view()
        rows = [
            [
                _time(item.slot_start_utc),
                _e(item.run_id),
                _e(item.collection_health),
                _e(item.row_count),
                _e(f"{sum(state.admissible for state in item.sports.values())}/{len(item.sports)}"),
                _link(f"/history/{item.run_id}/robin-real-data.html", {}, "vue"),
            ]
            for item in reversed(view.acquisitions)
        ]
        rejected = [[_e(name), _e(code)] for name, code in view.rejected]
        parts = [
            _notice(
                "Exploration descriptive : aucun edge validé, aucun conseil de pari, aucune "
                "causalité. Q2 (titulaire attendu absent) reste non observable avec les données "
                "actuelles."
            ),
            f"<p>{_e(len(view.acquisitions))} acquisitions vérifiées dans le stock local.</p>",
            "<p>" + _link("/questions/q3", {}, "Q3 · comparer deux acquisitions") + " · ",
            _link("/questions/q1", {}, "Q1 · mouvement de la cote du favori") + "</p>",
            _table(["Créneau", "Run", "Santé", "Lignes", "Sports admissibles", "Vue"], rows),
        ]
        if rejected:
            parts += ["<h2>Versions refusées</h2>", _table(["Version", "Code"], rejected)]
        return "".join(parts)

    def _q3(self, options: Mapping[str, str]) -> str:
        view = self.catalog.view()
        if len(view.acquisitions) < 2:
            return _notice("Au moins deux acquisitions vérifiées sont nécessaires.")
        previous_id = options.get("previous") or view.acquisitions[-2].run_id
        current_id = options.get("current") or view.acquisitions[-1].run_id
        choices = []
        for name, chosen in (("previous", previous_id), ("current", current_id)):
            entries = "".join(
                f'<option value="{_e(item.run_id)}"{" selected" if item.run_id == chosen else ""}>'
                f"{_e(item.slot_start_utc)} · run {_e(item.run_id)}</option>"
                for item in reversed(view.acquisitions)
            )
            title = "Référence (plus ancienne)" if name == "previous" else "Comparée (plus récente)"
            choices.append(f'<label>{title} <select name="{name}">{entries}</select></label> ')
        form = f'<form method="get" action="/questions/q3">{"".join(choices)}<button>Choisir</button></form>'
        previous, current = view.by_run(previous_id), view.by_run(current_id)
        if previous.run_id == current.run_id:
            raise QuestionError("Q3_SAME_ACQUISITION")
        if previous.slot_time >= current.slot_time:
            raise QuestionError("Q3_ORDER_INVALID")
        pair = {"previous": previous.run_id, "current": current.run_id}
        heading = (
            f"<p>Référence : {_acquisition_label(view, previous.run_id)}<br>"
            f"Comparée : {_acquisition_label(view, current.run_id)}</p>"
        )
        if "event" not in options:
            events = {**previous.events, **current.events}
            rows = [
                [
                    _time(state.kickoff.isoformat() if state.kickoff else None),
                    _e(key[2]),
                    f"<bdi>{_e(state.match)}</bdi>",
                    _link("/questions/q3", pair | {"event": key[3], "sport": key[2]}, "choisir"),
                ]
                for key, state in sorted(
                    events.items(), key=lambda pair_: (str(pair_[1].kickoff), pair_[1].match)
                )
            ]
            return (
                form
                + heading
                + "<h2>1. Match</h2>"
                + _table(["Coup d'envoi (UTC)", "Ligue", "Match", ""], rows)
            )
        previous_rows, current_rows = self.catalog.rows(previous), self.catalog.rows(current)
        if "market" not in options or "outcome" not in options:
            rows = [
                [
                    _e(item["sport_key"]),
                    _e(item["market_key"]),
                    f"<bdi>{_e(item['outcome'])}</bdi>",
                    _e(item["point"]),
                    _e(item["settlement_period_key"]),
                    _e(item["provider_key"]),
                    _e(item["previous_bookmakers"]),
                    _e(item["current_bookmakers"]),
                    _link(
                        "/questions/q3",
                        pair
                        | {
                            "event": options["event"],
                            "sport": item["sport_key"],
                            "market": item["market_key"],
                            "outcome": item["outcome"],
                            "point": item["point"],
                            "period": item["settlement_period_key"],
                            "provider": item["provider_key"],
                        },
                        "comparer",
                    ),
                ]
                for item in list_selections(previous_rows, current_rows, options["event"])
                if options.get("sport") in (None, item["sport_key"])
            ]
            headers = [
                "Ligue",
                "Marché",
                "Issue",
                "Seuil",
                "Période",
                "Fournisseur",
                "Bookmakers réf.",
                "Bookmakers comp.",
                "",
            ]
            return form + heading + "<h2>2. Sélection exacte</h2>" + _table(headers, rows)
        return form + self._q3_result(answer_q3(self.catalog, {**options, **pair}), view)

    def _q3_result(self, payload: Mapping[str, object], view: CatalogView) -> str:
        selection = cast(dict[str, object], payload["selection"])
        summary = cast(dict[str, object], payload["summary"])
        kickoff = cast(dict[str, object], payload["kickoff"])
        acquisitions = cast(dict[str, dict[str, object]], payload["acquisitions"])
        params = {
            "previous": acquisitions["previous"]["run_id"],
            "current": acquisitions["current"]["run_id"],
            "event": selection["event_id"],
            "sport": selection["sport_key"],
            "market": selection["market_key"],
            "outcome": selection["outcome"],
            "point": selection["point"],
            "period": selection["settlement_period_key"],
            "provider": selection["provider_key"],
        }
        period = selection["settlement_period_key"]
        if period == "PROVIDER_DEFAULT_UNSPECIFIED":
            period = "non attestée par le fournisseur (PROVIDER_DEFAULT_UNSPECIFIED)"
        facts = [
            ["Match", f"<bdi>{_e(selection['match'])}</bdi> ({_e(selection['sport_key'])})"],
            [
                "Sélection",
                f"{_e(selection['market_key'])} · <bdi>{_e(selection['outcome'])}</bdi> · seuil {_e(selection['point'])}",
            ],
            ["Période · fournisseur", f"{_e(period)} · {_e(selection['provider_key'])}"],
            ["Référence", _acquisition_label(view, acquisitions["previous"]["run_id"])],
            ["Comparée", _acquisition_label(view, acquisitions["current"]["run_id"])],
            [
                "Coup d'envoi (réf. → comp.)",
                " → ".join(
                    ", ".join(_e(value) for value in cast(list[str], kickoff[name])) or "—"
                    for name in ("previous_kickoff_utc", "current_kickoff_utc")
                )
                + (" · modifié" if kickoff["changed"] else ""),
            ],
            ["État", _label(payload["status"])],
        ]
        counts = cast(dict[str, int], summary["status_counts"])
        reasons = cast(dict[str, int], summary["exclusion_reason_counts"])
        tally = [[_label(name), _e(count)] for name, count in counts.items()]
        tally += [[_e(f"Exclue · {name}"), _e(count)] for name, count in reasons.items()]
        tally += [
            ["Médiane réf. (appariés)", _e(summary["previous_median_matched"])],
            ["Médiane comp. (appariés)", _e(summary["current_median_matched"])],
            ["Médiane des écarts (appariés)", _e(summary["median_delta"])],
        ]
        offers = [
            [
                f"<bdi>{_e(row.get('bookmaker'))}</bdi> ({_e(row.get('bookmaker_key'))})",
                _label(row.get("status")),
                _e(row.get("previous_price")),
                _time(row.get("previous_capture_time_utc")),
                _time(row.get("previous_source_timestamp_utc")),
                _e(row.get("current_price")),
                _time(row.get("current_capture_time_utc")),
                _time(row.get("current_source_timestamp_utc")),
                _e(row.get("delta")),
                _e(
                    " ".join(
                        str(point)
                        for point in cast(list[float], row.get("other_points_observed") or [])
                    )
                    or None
                ),
                _e(row.get("reason")),
            ]
            for row in cast(list[dict[str, object]], payload["rows"])
        ]
        headers = [
            "Bookmaker",
            "Statut",
            "Cote réf.",
            "Capture réf.",
            "Source réf.",
            "Cote comp.",
            "Capture comp.",
            "Source comp.",
            "Écart",
            "Autres seuils observés",
            "Motif",
        ]
        exports = (
            _link("/questions/q3.csv", params, "Exporter CSV")
            + " · "
            + _link("/questions/q3.json", params, "Exporter JSON")
        )
        return (
            "<h2>3. Mouvements par bookmaker</h2>"
            + _table(["Élément", "Valeur"], facts)
            + _table(["Synthèse de la sélection", "Nombre"], tally)
            + _table(headers, offers)
            + f"<p>{exports}</p>"
            + _notice(str(payload["notice"]))
        )

    def _filtered_q1(self, filters: Mapping[str, str]) -> dict[str, object]:
        """Unfiltered: the CLI bytes. Filtered: the kept rows with their own summary."""

        fingerprint = self.catalog.view().fingerprint()
        if self._q1_cache is None or self._q1_cache[0] != fingerprint:
            self._q1_cache = (fingerprint, answer_q1(self.catalog))
        payload = self._q1_cache[1]
        wanted = filters.get("status") or None
        strict = filters.get("strict") == "1"
        if wanted not in (None, *_Q1_STATUSES) or filters.get("strict") not in (None, "", "1"):
            raise QuestionError("QUERY_INVALID")
        if wanted is None and not strict:
            return payload
        kept = [
            row
            for row in cast(list[dict[str, object]], payload["rows"])
            if (wanted is None or row["status"] == wanted)
            and (not strict or row["strict_windows"] is True)
        ]
        return payload | {
            "filters": {"status": wanted, "strict_windows_only": strict},
            "filtered_summary": summarize_q1(kept),
            "rows": kept,
        }

    def _q1(self, filters: Mapping[str, str]) -> str:
        payload = self._filtered_q1(filters)
        store = cast(dict[str, object], payload["store"])
        rules = [[_e(name), _e(value)] for name, value in Q1_RULES.items()]
        coverage = _table(
            ["Couverture du stock (tous les matchs)", "Nombre"],
            _q1_overview(cast(dict[str, object], payload["summary"])),
        )
        if "filtered_summary" in payload:
            coverage += _table(
                ["Synthèse des matchs affichés", "Nombre"],
                _q1_overview(cast(dict[str, object], payload["filtered_summary"])),
            )
        options = "".join(
            f'<option value="{name}"{" selected" if filters.get("status") == name else ""}>{_label(name) if name else "Tous"}</option>'
            for name in ("", *_Q1_STATUSES)
        )
        checked = " checked" if filters.get("strict") == "1" else ""
        form = (
            f'<form method="get" action="/questions/q1"><label>Statut <select name="status">{options}</select></label> '
            f'<label><input type="checkbox" name="strict" value="1"{checked}> fenêtres strictes seulement</label> <button>Filtrer</button></form>'
        )
        rows = []
        for row in cast(list[dict[str, object]], payload["rows"]):
            evidence = "—"
            if row["reference_run_id"] and row["last_prematch_run_id"] and row["favourite_outcome"]:
                evidence = _link(
                    "/questions/q3",
                    {
                        "previous": row["reference_run_id"],
                        "current": row["last_prematch_run_id"],
                        "event": row["event_id"],
                        "sport": row["sport_key"],
                        "market": "h2h",
                        "outcome": row["favourite_outcome"],
                        "period": row["settlement_period_key"],
                        "provider": row["provider_key"],
                    },
                    "observations",
                )
            rows.append(
                [
                    _time(row["kickoff_utc"]),
                    f"<bdi>{_e(row['match'])}</bdi>",
                    _e(row["sport_key"]),
                    _label(row["status"]),
                    _label(row["reason"]),
                    f"{_time(row['reference_observed_at_utc'])}<br>{_e(row['reference_offset_minutes'])} min · {_label(row['reference_class'])}",
                    f"{_time(row['last_prematch_observed_at_utc'])}<br>{_e(row['last_prematch_minutes_before_kickoff'])} min avant · {_label(row['last_prematch_class'])}",
                    f"<bdi>{_e(row['favourite_outcome'])}</bdi> · n={_e(row['consensus_bookmakers_at_reference'])}",
                    f"{_e(row['paired_median_at_reference'])} → {_e(row['paired_median_last_prematch'])}",
                    _e(row["median_delta"]),
                    f"{_e(row['up_count'])} / {_e(row['down_count'])} / {_e(row['unchanged_count'])} (n={_e(row['paired_bookmakers'])})",
                    evidence,
                ]
            )
        params = {name: value for name, value in filters.items() if value}
        exports = (
            _link("/questions/q1.csv", params, "Exporter CSV")
            + " · "
            + _link("/questions/q1.json", params, "Exporter JSON")
        )
        headers = [
            "Coup d'envoi",
            "Match",
            "Ligue",
            "Statut",
            "Motif",
            "Référence observée",
            "Dernière cote observée avant le coup d'envoi",
            "Favori · consensus",
            "Médiane appariée réf. → dernière obs.",
            "Écart des médianes",
            "Hausse / baisse / inchangée",
            "Preuves",
        ]
        return (
            _notice(
                "La dernière cote observée avant le coup d'envoi n'est pas une cote de clôture. "
                "Exploration descriptive : aucun edge, aucun conseil de pari, aucune causalité."
            )
            + f"<p>Stock : {_e(store['acquisition_count'])} acquisitions, captures de {_time(store['first_acquired_at_utc'])} à {_time(store['last_acquired_at_utc'])} (bornes des statuts en attente et hors stock).</p>"
            + coverage
            + "<details><summary>Règles déclarées avant calcul</summary>"
            + _table(["Règle", "Valeur"], rules)
            + "</details>"
            + form
            + f"<p>{_e(len(rows))} matchs affichés · {exports}</p>"
            + _table(headers, rows)
        )


def make_server(store: AtomicExplorerStore, *, port: int = 4173) -> ThreadingHTTPServer:
    """The existing explorer server plus read-only ``/questions`` routes on 127.0.0.1.

    Every route refuses a foreign Host header (DNS rebinding); the existing handlers
    are otherwise reused unchanged.
    """

    base = _handler(store)
    base_get = cast(Callable[[BaseHTTPRequestHandler], None], getattr(base, "do_GET"))
    base_post = cast(Callable[[BaseHTTPRequestHandler], None], getattr(base, "do_POST"))
    pages = QuestionPages(AcquisitionCatalog(store))
    allowed_hosts: set[str] = set()

    def send(
        handler: BaseHTTPRequestHandler,
        status: HTTPStatus,
        payload: bytes,
        content_type: str,
        headers: Mapping[str, str],
    ) -> None:
        handler.send_response(status)
        for name, value in {
            "Content-Type": content_type,
            "Content-Length": str(len(payload)),
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
            **headers,
        }.items():
            handler.send_header(name, value)
        handler.end_headers()
        handler.wfile.write(payload)

    def trusted(handler: BaseHTTPRequestHandler) -> bool:
        if handler.headers.get("Host") in allowed_hosts:
            return True
        send(handler, HTTPStatus.FORBIDDEN, b"forbidden host\n", "text/plain", {})
        return False

    def do_get(handler: BaseHTTPRequestHandler) -> None:
        if not trusted(handler):
            return
        split = urllib.parse.urlsplit(handler.path)
        if split.path != "/questions" and not split.path.startswith("/questions/"):
            base_get(handler)
            return
        try:
            status, payload, content_type, headers = pages.respond(split.path, split.query)
        except Exception:  # fail closed without exposing internals
            status, payload = HTTPStatus.INTERNAL_SERVER_ERROR, b"QUESTION_UNEXPECTED_FAILURE\n"
            content_type, headers = "text/plain; charset=utf-8", {}
        send(handler, status, payload, content_type, headers)

    def do_post(handler: BaseHTTPRequestHandler) -> None:
        if trusted(handler):
            base_post(handler)

    handler_class = cast(
        type[BaseHTTPRequestHandler],
        type("RobinQuestionsHandler", (base,), {"do_GET": do_get, "do_POST": do_post}),
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), handler_class)
    bound_port = int(server.server_address[1])
    for host in ("127.0.0.1", "localhost"):
        allowed_hosts.add(f"{host}:{bound_port}")
        if bound_port == 80:
            allowed_hosts.add(host)
    return server


__all__ = ["CONTENT_SECURITY_POLICY", "QuestionPages", "make_server"]
