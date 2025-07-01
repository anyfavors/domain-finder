import numpy as np
import domain_finder as domain


def compute_scores(labels, tlds, stats, prices, cfg):
    ngram_scores = np.array([stats[l]["ngram"] for l in labels])
    volume_arr = np.array([stats[l]["volume"] for l in labels])
    auto_arr = np.array([stats[l]["auto"] for l in labels])
    length_scores = np.array([stats[l]["length_s"] for l in labels])
    price_arr = np.array([prices[t] for t in tlds])

    pn = (price_arr - price_arr.min()) / (price_arr.max() - price_arr.min() or 1)
    nn = (ngram_scores - ngram_scores.min()) / (
        ngram_scores.max() - ngram_scores.min() or 1
    )
    vn = (volume_arr - volume_arr.min()) / (volume_arr.max() - volume_arr.min() or 1)
    an = (auto_arr - auto_arr.min()) / (auto_arr.max() - auto_arr.min() or 1)

    scores = (
        cfg.weight_length * length_scores[:, None]
        + cfg.weight_price * pn[None, :]
        + cfg.weight_ngram * nn[:, None]
        + cfg.weight_volume * vn[:, None]
        + cfg.weight_auto * an[:, None]
    )
    return scores


def test_scoring_ranking():
    cfg = domain.Config()
    labels = ["aa", "bb"]
    tlds = ["com", "net"]
    stats = {
        "aa": {"ngram": 1, "volume": 10, "auto": 5, "length_s": 1.0},
        "bb": {"ngram": 0.5, "volume": 5, "auto": 2, "length_s": 0.5},
    }
    prices = {"com": 10, "net": 20}
    scores = compute_scores(labels, tlds, stats, prices, cfg)
    flat = scores.ravel()
    best = flat.argmax()
    li = best // len(tlds)
    ti = best % len(tlds)
    assert labels[li] == "aa"
    assert tlds[ti] == "net"
