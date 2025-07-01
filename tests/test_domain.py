import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import time
import asyncio
from unittest.mock import Mock

import domain_finder as domain


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
    labels = list(domain.generate_labels(5))
    assert len(labels) == 5
    assert all(lbl.isalpha() for lbl in labels)
    assert len(set(labels)) == len(labels)
    for lbl in labels:
        assert domain.is_pronounceable(lbl)
        assert 1 <= len(lbl) <= domain.Config().max_label_len


def test_generate_labels_deterministic():
    assert list(domain.generate_labels(6)) == list(domain.generate_labels(6))


def test_fetch_tlds_cached(tmp_path):
    cache = tmp_path / "tlds.json"
    cfg = domain.Config(top_tld_count=2, tld_cache_file=str(cache))
    df = domain.DomainFinder(cfg)

    class FakeResp:
        def __init__(self, text):
            self._text = text
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
        async def text(self):
            return self._text
        def raise_for_status(self):
            pass

    class FakeSession:
        def get(self, *args, **kwargs):
            return FakeResp("COM\nNET\n")

    session = FakeSession()
    first = asyncio.run(df.fetch_tlds(session))
    assert first == ["com", "net"]
    assert cache.exists()

    def fail_get(*args, **kwargs):
        raise AssertionError("no call")

    session.get = fail_get
    second = asyncio.run(df.fetch_tlds(session))
    assert second == first


def test_fetch_tlds_cache_expired(tmp_path):
    cache = tmp_path / "tlds.json"
    cache.write_text(json.dumps({'timestamp': time.time() - 100, 'tlds': ["com"]}))
    cfg = domain.Config(tld_cache_file=str(cache), tld_cache_age=1)
    df = domain.DomainFinder(cfg)

    class FakeResp:
        def __init__(self, text):
            self._text = text
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass
        async def text(self):
            return self._text
        def raise_for_status(self):
            pass

    class FakeSession:
        def __init__(self):
            self.called = False
        def get(self, *args, **kwargs):
            self.called = True
            return FakeResp("COM\n")

    session = FakeSession()
    tlds = asyncio.run(df.fetch_tlds(session))
    assert session.called
    assert tlds == ["com"]


def test_search_volume_cache(monkeypatch):
    async def fake_sv(label, session, retries=3):
        return 42

    monkeypatch.setattr(domain, "search_volume", fake_sv)
    cache = {}
    res = asyncio.run(domain.gather_search_volumes(["abc"], cache, session=object()))
    assert res == {"abc": 42}
    assert cache["abc"]["volume"] == 42

    async def fail_sv(label, session, retries=3):
        raise AssertionError("called")

    monkeypatch.setattr(domain, "search_volume", fail_sv)
    res2 = asyncio.run(domain.gather_search_volumes(["abc"], cache, session=object()))
    assert res2 == {"abc": 42}


def test_autocomplete_cache(monkeypatch):
    async def fake_ac(label, session, retries=3):
        return 7

    monkeypatch.setattr(domain, "autocomplete_count", fake_ac)
    cache = {}
    res = asyncio.run(domain.gather_autocomplete_counts(["abc"], cache, session=object()))
    assert res == {"abc": 7}
    assert cache["abc"]["auto"] == 7

    async def fail_ac(label, session, retries=3):
        raise AssertionError("called")

    monkeypatch.setattr(domain, "autocomplete_count", fail_ac)
    res2 = asyncio.run(domain.gather_autocomplete_counts(["abc"], cache, session=object()))
    assert res2 == {"abc": 7}


def test_autocomplete_concurrency(monkeypatch):
    calls = []

    async def fake_ac(label, session, retries=3):
        calls.append(label)
        await asyncio.sleep(0)
        return 1

    monkeypatch.setattr(domain, "autocomplete_count", fake_ac)
    cache = {}
    res = asyncio.run(
        domain.gather_autocomplete_counts(["a", "b"], cache, limit=1, session=object())
    )
    assert res == {"a": 1, "b": 1}
    assert calls == ["a", "b"]


def test_candidate_serialization_roundtrip():
    cand = domain.Candidate("foo", "com", 10, 1.0, 2, 3, 0.5, 0)
    cand.score = 4.2
    data = domain.candidate_to_dict(cand)
    new = domain.candidate_from_dict(data)
    assert new == cand
    assert hasattr(new, "score") and new.score == cand.score


def test_cli_invocation(monkeypatch):
    called = False

    async def fake_run(self):
        nonlocal called
        called = True

    monkeypatch.setattr(domain.DomainFinder, "run", fake_run)
    monkeypatch.setattr(sys, "argv", ["domain-finder", "--num-candidates", "1"])
    domain.main()
    assert called

