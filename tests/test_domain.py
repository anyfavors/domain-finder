import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import time
import asyncio
from unittest.mock import Mock

import domain


def test_is_pronounceable():
    assert domain.is_pronounceable("abc")
    assert domain.is_pronounceable("ae")
    assert not domain.is_pronounceable("bcdf")
    assert not domain.is_pronounceable("abccd")


def test_estimate_price():
    assert domain.estimate_price("com") == 12
    assert domain.estimate_price("io") == 35
    assert domain.estimate_price("xyz") == 15
    assert domain.estimate_price("abcdef") == 8


def test_generate_labels():
    labels = domain.generate_labels(5)
    assert labels == ["a", "e", "i", "o", "u"]
    assert len(set(labels)) == len(labels)
    for lbl in labels:
        assert domain.is_pronounceable(lbl)
        assert 1 <= len(lbl) <= domain.MAX_LABEL_LEN


def test_generate_labels_deterministic():
    assert domain.generate_labels(6) == domain.generate_labels(6)


def test_fetch_tlds_cached(tmp_path):
    cache = tmp_path / "tlds.json"
    df = domain.DomainFinder(top_tld_count=2, tld_cache_file=str(cache))
    fake_resp = Mock()
    fake_resp.text = "COM\nNET\n"
    fake_resp.raise_for_status = Mock()
    df.session.get = Mock(return_value=fake_resp)

    first = df.fetch_tlds()
    assert first == ["com", "net"]
    assert cache.exists()

    df.session.get = Mock(side_effect=Exception("no call"))
    second = df.fetch_tlds()
    assert second == first


def test_fetch_tlds_cache_expired(tmp_path):
    cache = tmp_path / "tlds.json"
    cache.write_text(json.dumps({'timestamp': time.time() - 100, 'tlds': ["com"]}))
    df = domain.DomainFinder(tld_cache_file=str(cache), tld_cache_age=1)
    fake_resp = Mock()
    fake_resp.text = "COM\n"
    fake_resp.raise_for_status = Mock()
    df.session.get = Mock(return_value=fake_resp)

    tlds = df.fetch_tlds()
    assert df.session.get.called
    assert tlds == ["com"]


def test_search_volume_cache(monkeypatch):
    async def fake_sv(label, session=None, retries=3):
        return 42

    monkeypatch.setattr(domain, "search_volume", fake_sv)
    cache = {}
    res = asyncio.run(domain.gather_search_volumes(["abc"], cache))
    assert res == {"abc": 42}
    assert cache["abc"]["volume"] == 42

    async def fail_sv(label, session=None, retries=3):
        raise AssertionError("called")

    monkeypatch.setattr(domain, "search_volume", fail_sv)
    res2 = asyncio.run(domain.gather_search_volumes(["abc"], cache))
    assert res2 == {"abc": 42}


def test_autocomplete_cache(monkeypatch):
    async def fake_ac(label, session=None, retries=3):
        return 7

    monkeypatch.setattr(domain, "autocomplete_count", fake_ac)
    cache = {}
    res = asyncio.run(domain.gather_autocomplete_counts(["abc"], cache))
    assert res == {"abc": 7}
    assert cache["abc"]["auto"] == 7

    async def fail_ac(label, session=None, retries=3):
        raise AssertionError("called")

    monkeypatch.setattr(domain, "autocomplete_count", fail_ac)
    res2 = asyncio.run(domain.gather_autocomplete_counts(["abc"], cache))
    assert res2 == {"abc": 7}

