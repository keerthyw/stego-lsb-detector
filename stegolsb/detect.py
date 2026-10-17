"""Steganalysis: decide whether an image probably contains LSB-hidden data.

Two classic statistical attacks are combined:

1. Chi-square attack (Westfeld & Pfitzmann, 1999)
   Writing random bits into LSBs makes each pair of values (2k, 2k+1), for example 100
   and 101, appear about equally often, because a 100 becomes 101 half the time and vice
   versa. Natural images don't have this property. A chi-square test measures how
   "equalised" the pairs are. Running it on growing portions of the image shows *where*
   the hidden data stops, which reveals sequential embedding very clearly.

2. Sample Pair Analysis (Dumitrescu, Wu & Wang, 2003)
   Looks at pairs of neighbouring pixel values and how LSB flipping moves them between
   groups. Solving a quadratic gives an estimate of the *embedding rate*: the share of
   colour values that carry hidden bits. It also works when bits are scattered randomly.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np

# --------------------------------------------------------------------------- chi-square


def _gammaincc(a: float, x: float) -> float:
    """Regularised upper incomplete gamma Q(a, x) (Numerical Recipes, 6.2)."""
    if x <= 0:
        return 1.0
    if x < a + 1:  # series representation of P(a, x)
        term = total = 1.0 / a
        n = a
        for _ in range(1000):
            n += 1
            term *= x / n
            total += term
            if abs(term) < abs(total) * 1e-12:
                break
        return 1.0 - total * math.exp(-x + a * math.log(x) - math.lgamma(a))
    # continued fraction for Q(a, x)
    b, c, d = x + 1 - a, 1e300, 1 / (x + 1 - a)
    h = d
    for i in range(1, 1000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-12:
            break
    return math.exp(-x + a * math.log(x) - math.lgamma(a)) * h


def chi_square_probability(values: np.ndarray) -> float:
    """Probability (0-1) that `values` have had their LSBs replaced with random bits."""
    hist = np.bincount(values, minlength=256).astype(float)
    even, odd = hist[0::2], hist[1::2]
    expected = (even + odd) / 2
    keep = expected > 4               # tiny categories make the test unreliable
    if keep.sum() < 2:
        return 0.0
    chi2 = float((((even - expected) ** 2)[keep] / expected[keep]).sum())
    dof = int(keep.sum()) - 1
    return _gammaincc(dof / 2, chi2 / 2)   # = 1 - CDF of the chi-square distribution


def chi_square_curve(flat: np.ndarray, steps: int = 100) -> np.ndarray:
    """Probability of embedding for the first 1%, 2%, ... 100% of the image (in pixel order)."""
    n = flat.size
    return np.array([chi_square_probability(flat[: max(64, n * i // steps)]) for i in range(1, steps + 1)])


# --------------------------------------------------------------------------- sample pair analysis


def spa_rate(channel: np.ndarray) -> float:
    """Estimate the embedding rate (0-1) of one colour channel with Sample Pair Analysis."""
    ch = channel.astype(np.int32)
    # Horizontally and vertically adjacent pixels form the sample pairs (r, s).
    r = np.concatenate([ch[:, :-1].ravel(), ch[:-1, :].ravel()])
    s = np.concatenate([ch[:, 1:].ravel(), ch[1:, :].ravel()])
    n = r.size

    s_even = (s % 2) == 0
    x = int(np.sum((s_even & (r < s)) | (~s_even & (r > s))))
    y = int(np.sum((s_even & (r > s)) | (~s_even & (r < s))))
    k = int(np.sum((r // 2) == (s // 2)))
    if k == 0:
        return 0.0

    a, b, c = 2 * k, 2 * (2 * x - n), y - x
    disc = b * b - 4 * a * c
    if disc < 0:
        return 0.0
    roots = [(-b + math.sqrt(disc)) / (2 * a), (-b - math.sqrt(disc)) / (2 * a)]
    beta = min(roots, key=abs)       # beta = estimated share of changed LSBs
    return float(min(1.0, max(0.0, 2 * beta)))  # changed LSBs are ~half the embedded bits


# --------------------------------------------------------------------------- verdict


def lsb_randomness(rgb: np.ndarray) -> float:
    """How far the LSB plane is from pure coin flips (0 = perfectly random).

    Compares each LSB with its right-hand neighbour, the one below, and the green LSB of
    the same pixel. Random bits agree exactly half the time. Natural images usually have
    some structure left in their LSBs, embedded data does not.
    """
    lsb = (rgb & 1).astype(np.int8)
    h = np.mean(lsb[:, 1:] == lsb[:, :-1])
    v = np.mean(lsb[1:] == lsb[:-1])
    c = np.mean(lsb[..., 0] == lsb[..., 1])
    return float(abs(h - 0.5) + abs(v - 0.5) + abs(c - 0.5))


@dataclass
class Analysis:
    verdict: str                        # CLEAN / SUSPICIOUS / LIKELY STEGO / CONFIRMED
    chi_curve: np.ndarray               # chi-square probability for the first 1%..100% of the image
    chi_overall: float
    spa_rates: dict[str, float]
    spa_mean: float
    randomness: float
    estimated_bytes: int
    reasons: list[str] = field(default_factory=list)
    payload: bytes | None = None        # set when an unprotected stegolsb payload was found


# Thresholds chosen by testing clean and stego versions of natural photos (see tests/ and README).
SPA_SUSPICIOUS = 0.04
SPA_LIKELY = 0.10
CHI_LIKELY = 0.95
RANDOM_LSB = 0.006


def analyze(arr: np.ndarray) -> Analysis:
    from .lsb import StegoError, reveal

    rgb = arr[..., :3]
    flat = rgb.reshape(-1)
    curve = chi_square_curve(flat)
    rates = {name: spa_rate(rgb[..., i]) for i, name in enumerate("RGB")}
    spa_mean = float(np.mean(list(rates.values())))
    randomness = lsb_randomness(rgb)
    full = curve[-1] > CHI_LIKELY and randomness < RANDOM_LSB
    est_bytes = int((1.0 if full else spa_mean) * flat.size / 8)

    a = Analysis("CLEAN", curve, float(curve[-1]), rates, spa_mean, randomness, est_bytes)

    # 1. Signature check: data hidden by this tool without a password can simply be read.
    try:
        a.payload = reveal(arr)
        a.verdict = "CONFIRMED"
        a.estimated_bytes = len(a.payload)
        a.reasons.append(f"Found an unprotected stegolsb header and recovered {len(a.payload)} bytes.")
        return a
    except StegoError:
        pass

    # 2. Statistical attacks.
    if spa_mean >= SPA_SUSPICIOUS:
        a.reasons.append(f"Sample Pair Analysis estimates {spa_mean:.1%} of colour values carry hidden bits "
                         f"(R {rates['R']:.1%}, G {rates['G']:.1%}, B {rates['B']:.1%}).")
    if full:
        a.reasons.append("The whole image has equalised value pairs (chi-square p = "
                         f"{curve[-1]:.2f}) and its LSB plane is indistinguishable from random bits: "
                         "the image looks filled to capacity.")
    if full or spa_mean >= SPA_LIKELY:
        a.verdict = "LIKELY STEGO"
    elif spa_mean >= SPA_SUSPICIOUS:
        a.verdict = "SUSPICIOUS"
    else:
        a.reasons.append("Neither attack found the statistical traces LSB embedding leaves. "
                         "Payloads smaller than about 2-3% of capacity are below what these tests can see.")
    return a


def lsb_plane(arr: np.ndarray, channel: int | None = None) -> np.ndarray:
    """Black/white image of the least significant bits (all channels combined, or one)."""
    rgb = arr[..., :3]
    bits = (rgb[..., channel] & 1) if channel is not None else ((rgb & 1).sum(axis=2) >= 2).astype(np.uint8)
    return (bits * 255).astype(np.uint8)
