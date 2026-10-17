#!/usr/bin/env python3
"""LSB steganography toolkit: hide, reveal and detect data hidden in images.

Examples:
    python stego.py hide cover.png -m "meet at 6" -o secret.png
    python stego.py hide cover.png -f notes.pdf -o secret.png --password hunter2
    python stego.py reveal secret.png
    python stego.py reveal secret.png --password hunter2 -o notes.pdf
    python stego.py analyze suspect.png --plot report.png
    python stego.py capacity cover.png
"""

import argparse
import sys

from stegolsb.detect import analyze
from stegolsb.lsb import StegoError, capacity, hide, load_image, reveal, save_image


def cmd_hide(args) -> int:
    arr = load_image(args.cover)
    if args.message is not None:
        payload = args.message.encode("utf-8")
    else:
        with open(args.file, "rb") as fh:
            payload = fh.read()
    out = hide(arr, payload, args.password)
    save_image(out, args.output)
    print(f"Hid {len(payload):,} bytes in {args.output} "
          f"({len(payload) / capacity(arr):.1%} of the {capacity(arr):,}-byte capacity)"
          + (", scattered and XOR-masked with the password" if args.password else ""))
    return 0


def cmd_reveal(args) -> int:
    payload = reveal(load_image(args.image), args.password)
    if args.output:
        with open(args.output, "wb") as fh:
            fh.write(payload)
        print(f"Recovered {len(payload):,} bytes to {args.output}")
    else:
        try:
            print(payload.decode("utf-8"))
        except UnicodeDecodeError:
            print(f"Recovered {len(payload):,} bytes of binary data; use -o FILE to save them.")
    return 0


def cmd_analyze(args) -> int:
    worst = 0
    for path in args.images:
        arr = load_image(path)
        a = analyze(arr)
        print(f"=== {path} ===")
        print(f"Verdict:        {a.verdict}")
        print(f"SPA estimate:   {a.spa_mean:.1%} of colour values  (R {a.spa_rates['R']:.1%}, "
              f"G {a.spa_rates['G']:.1%}, B {a.spa_rates['B']:.1%})")
        print(f"Chi-square p:   {a.chi_overall:.3f} over the whole image")
        print(f"LSB randomness: {a.randomness:.4f}  (0 = indistinguishable from coin flips)")
        if a.verdict == "CONFIRMED":
            print(f"Payload size:   {a.estimated_bytes:,} bytes")
        elif a.verdict != "CLEAN":
            print(f"Estimated size: ~{a.estimated_bytes:,} bytes")
        for reason in a.reasons:
            print(f"  - {reason}")
        if a.payload is not None:
            try:
                print(f"  Payload: {a.payload[:200].decode('utf-8')!r}")
            except UnicodeDecodeError:
                print("  Payload is binary data; extract it with: stego.py reveal IMAGE -o FILE")
        if args.plot:
            from stegolsb.visual import analysis_figure
            out = args.plot if len(args.images) == 1 else f"{path.rsplit('.', 1)[0]}_analysis.png"
            analysis_figure(arr, a, path.rsplit("/", 1)[-1], out)
            print(f"  Figure saved to {out}")
        print()
        worst = max(worst, {"CLEAN": 0, "SUSPICIOUS": 1}.get(a.verdict, 2))
    return worst


def cmd_capacity(args) -> int:
    arr = load_image(args.image)
    print(f"{args.image}: {arr.shape[1]}x{arr.shape[0]} pixels, can hide {capacity(arr):,} bytes")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Hide, reveal and detect LSB steganography in images.")
    sub = p.add_subparsers(dest="command", required=True)

    h = sub.add_parser("hide", help="hide a message or file in an image")
    h.add_argument("cover", help="cover image (PNG, BMP, or JPEG input)")
    src = h.add_mutually_exclusive_group(required=True)
    src.add_argument("-m", "--message", help="text to hide")
    src.add_argument("-f", "--file", help="file to hide")
    h.add_argument("-o", "--output", required=True, help="output image (must be PNG/BMP/TIFF)")
    h.add_argument("-p", "--password", help="scatter and mask the data with this password")
    h.set_defaults(func=cmd_hide)

    r = sub.add_parser("reveal", help="extract hidden data")
    r.add_argument("image")
    r.add_argument("-p", "--password")
    r.add_argument("-o", "--output", help="save the payload to a file instead of printing it")
    r.set_defaults(func=cmd_reveal)

    a = sub.add_parser("analyze", help="detect hidden data (steganalysis)")
    a.add_argument("images", nargs="+")
    a.add_argument("--plot", metavar="PNG", help="save a figure with the LSB plane and chi-square curve")
    a.set_defaults(func=cmd_analyze)

    c = sub.add_parser("capacity", help="how many bytes an image can hold")
    c.add_argument("image")
    c.set_defaults(func=cmd_capacity)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (StegoError, FileNotFoundError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
