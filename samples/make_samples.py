#!/usr/bin/env python3
"""Recreate the sample images and the figures in docs/.

The cover image is NASA's public-domain portrait of astronaut Eileen Collins, as shipped
with scikit-image (pip install scikit-image to run this script).

Run from the repo root:  python samples/make_samples.py
"""

import os
import random
import sys
import zlib

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from PIL import Image  # noqa: E402
from skimage import data  # noqa: E402

from stegolsb.detect import analyze  # noqa: E402
from stegolsb.lsb import hide, load_image, save_image  # noqa: E402
from stegolsb.visual import analysis_figure  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
S = lambda *p: os.path.join(ROOT, "samples", *p)  # noqa: E731
D = lambda *p: os.path.join(ROOT, "docs", *p)     # noqa: E731


def payload(size: int) -> bytes:
    """Compressed text: realistic hidden data (compressed files look random)."""
    random.seed(7)
    words = ("the analyst examined every header timestamp and checksum before writing "
             "the incident report for the evidence locker").split()
    text = " ".join(random.choice(words) for _ in range(60000)).encode()
    return zlib.compress(text, 9)[:size]


def main():
    os.makedirs(D(), exist_ok=True)
    Image.fromarray(data.astronaut()).save(S("cover.png"))
    cover = load_image(S("cover.png"))
    secret = payload(30000)

    save_image(hide(cover, b"Meet at the library, 6 pm. Bring the USB."), S("secret_message.png"))
    save_image(hide(cover, secret, password="srm2026"), S("protected.png"))
    sequential = hide(cover, secret)  # used only for the docs figure

    for name, arr in [("clean", cover), ("sequential", sequential), ("protected", load_image(S("protected.png")))]:
        analysis_figure(arr, analyze(arr), f"{name}.png", D(f"analysis_{name}.png"))
    print("samples/ and docs/ regenerated")


if __name__ == "__main__":
    main()
