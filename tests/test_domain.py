import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import json
import time
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

