"""Run with:  python -m unittest discover tests"""

import os
import sys
import tempfile
import unittest

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from stegolsb.detect import _gammaincc, analyze  # noqa: E402
from stegolsb.lsb import StegoError, capacity, hide, load_image, reveal, save_image  # noqa: E402

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def cover():
    return load_image(os.path.join(SAMPLES, "cover.png"))


class TestHideReveal(unittest.TestCase):
    def test_text_round_trip(self):
        self.assertEqual(reveal(hide(cover(), "héllo wörld".encode())), "héllo wörld".encode())

    def test_binary_round_trip_with_password(self):
        data = os.urandom(5000)
        stego = hide(cover(), data, password="s3cret")
        self.assertEqual(reveal(stego, password="s3cret"), data)

    def test_wrong_or_missing_password_fails(self):
        stego = hide(cover(), b"top secret", password="right")
        with self.assertRaises(StegoError):
            reveal(stego, password="wrong")
        with self.assertRaises(StegoError):
            reveal(stego)

    def test_clean_image_has_nothing(self):
        with self.assertRaises(StegoError):
            reveal(cover())

    def test_too_large_payload(self):
        img = cover()
        with self.assertRaises(StegoError):
            hide(img, b"x" * (capacity(img) + 1))

    def test_pixels_change_by_at_most_one(self):
        img = cover()
        stego = hide(img, os.urandom(capacity(img)))
        self.assertLessEqual(int(np.abs(stego.astype(int) - img.astype(int)).max()), 1)

    def test_alpha_channel_untouched(self):
        rgba = np.dstack([cover(), np.full(cover().shape[:2], 77, dtype=np.uint8)])
        stego = hide(rgba, b"keep alpha")
        self.assertTrue((stego[..., 3] == 77).all())
        self.assertEqual(reveal(stego), b"keep alpha")

    def test_png_save_and_jpeg_refused(self):
        stego = hide(cover(), b"survives png")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "out.png")
            save_image(stego, path)
            self.assertEqual(reveal(load_image(path)), b"survives png")
            with self.assertRaises(StegoError):
                save_image(stego, os.path.join(tmp, "out.jpg"))


class TestDetection(unittest.TestCase):
    def test_gamma_matches_reference_values(self):
        # Q(a, x) values computed with scipy.stats.chi2.sf(2x, 2a)
        for a, x, expected in [(1, 0.5, 0.60653066), (5, 3, 0.81526324), (50, 40, 0.92966493)]:
            self.assertAlmostEqual(_gammaincc(a, x), expected, places=6)

    def test_clean_cover(self):
        self.assertEqual(analyze(cover()).verdict, "CLEAN")

    def test_unprotected_payload_is_confirmed_and_read(self):
        a = analyze(load_image(os.path.join(SAMPLES, "secret_message.png")))
        self.assertEqual(a.verdict, "CONFIRMED")
        self.assertIn(b"library", a.payload)

    def test_password_protected_payload_is_detected_statistically(self):
        a = analyze(load_image(os.path.join(SAMPLES, "protected.png")))
        self.assertEqual(a.verdict, "LIKELY STEGO")
        self.assertIsNone(a.payload)
        self.assertAlmostEqual(a.estimated_bytes, 30000, delta=6000)  # SPA estimate is close to the truth

    def test_full_capacity_scattered(self):
        img = cover()
        a = analyze(hide(img, os.urandom(capacity(img)), password="x"))
        self.assertEqual(a.verdict, "LIKELY STEGO")

    def test_other_tools_sequential_embedding(self):
        """Random bits written from the top with no header (as another tool might) are still detected."""
        img = cover()
        flat = img.reshape(-1).copy()
        n = flat.size // 4
        flat[:n] = (flat[:n] & 0xFE) | np.random.default_rng(0).integers(0, 2, n, dtype=np.uint8)
        self.assertEqual(analyze(flat.reshape(img.shape)).verdict, "LIKELY STEGO")


if __name__ == "__main__":
    unittest.main()
