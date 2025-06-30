import random
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

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
    random.seed(0)
    labels = domain.generate_labels(5)
    assert len(labels) == 5
    assert len(set(labels)) == len(labels)
    for lbl in labels:
        assert domain.is_pronounceable(lbl)
        assert 1 <= len(lbl) <= domain.MAX_LABEL_LEN
