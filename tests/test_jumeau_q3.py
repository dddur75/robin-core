import runpy
from datetime import timedelta
from pathlib import Path

from robin.capture.real_data_questions import (
    AcquisitionCatalog,
    Selection,
    compare_selection,
    list_selections,
    to_json_bytes,
)
from tests.capture.test_real_data_questions import KICKOFF, _book, _offer, _store

ROOT = Path(__file__).resolve().parents[1]


def test_event_partition_preserves_every_selection_byte(tmp_path):
    ns = runpy.run_path(str(ROOT / 'scripts/jumeau.py'))
    before = _book('a', 2.0, 3.0, 4.0) + _book('b', 2.0, 3.0, 4.0, event='other')
    before += [_offer('a', 'Over', 1.8, market='totals', point=2.5)]
    after = _book('a', 2.2, 2.8, 4.1) + _book('b', 2.1, 2.9, 4.1, event='other')
    after += [_offer('a', 'Over', 1.9, market='totals', point=3.5)]
    store = _store(tmp_path, [(101, KICKOFF - timedelta(days=3), before),
                              (102, KICKOFF - timedelta(days=3, hours=-2), after)])
    catalog = AcquisitionCatalog(store)
    previous, current = catalog.view().acquisitions
    left, right = catalog.rows(previous), catalog.rows(current)
    partitions = list(ns['event_rows'](left, right))
    assert len(partitions) == 2
    for event, prior, later in partitions:
        assert list_selections(left, right, event) == list_selections(prior, later, event)
        for selection in list_selections(prior, later, event):
            choice = Selection(event, selection['market_key'], selection['outcome'], selection['point'],
                               selection['provider_key'], selection['settlement_period_key'],
                               selection['sport_key'])
            expected = compare_selection(previous, left, current, right, choice)
            actual = compare_selection(previous, prior, current, later, choice)
            assert to_json_bytes(actual) == to_json_bytes(expected)
