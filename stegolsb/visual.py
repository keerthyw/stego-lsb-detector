"""Forensic figures: the image, its LSB plane and the chi-square curve, side by side."""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")  # render to files, no window needed
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

from .detect import Analysis, lsb_plane  # noqa: E402

VERDICT_COLORS = {"CLEAN": "#2f855a", "SUSPICIOUS": "#b7791f", "LIKELY STEGO": "#c0392b", "CONFIRMED": "#c0392b"}


def analysis_figure(arr: np.ndarray, a: Analysis, title: str, out_path: str) -> None:
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), gridspec_kw={"width_ratios": [1, 1, 1.25]})

    axes[0].imshow(arr[..., :3])
    axes[0].set_title("Image")
    axes[1].imshow(lsb_plane(arr), cmap="gray", interpolation="nearest")
    axes[1].set_title("LSB plane (white = most channels' last bit is 1)")
    for ax in axes[:2]:
        ax.axis("off")

    x = np.arange(1, len(a.chi_curve) + 1)
    ax = axes[2]
    ax.plot(x, a.chi_curve, color="#1f3a5f", linewidth=2)
    ax.fill_between(x, a.chi_curve, color="#1f3a5f", alpha=0.12)
    ax.axhline(0.95, color="#c0392b", linestyle="--", linewidth=1)
    ax.text(2, 0.965, "p = 0.95", color="#c0392b", fontsize=9)
    ax.set_ylim(-0.02, 1.05)
    ax.set_xlim(1, len(a.chi_curve))
    ax.set_xlabel("Share of image examined, in pixel order (%)")
    ax.set_ylabel("Probability of embedding")
    ax.set_title("Chi-square attack")
    ax.spines[["top", "right"]].set_visible(False)

    color = VERDICT_COLORS.get(a.verdict, "#333")
    fig.suptitle(f"{title}   |   {a.verdict}   |   SPA estimate {a.spa_mean:.1%}", fontsize=13,
                 fontweight="bold", color=color)
    fig.tight_layout()
    fig.savefig(out_path, dpi=110)
    plt.close(fig)
