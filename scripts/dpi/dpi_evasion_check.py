#!/usr/bin/env python3
"""Gate for the albus DPI evasion lab (stdlib only).

Parses the captured output of `scripts/dpi_sim.py run` (JSON log lines plus
one final {"results": [...]} block) and asserts the expected verdict for one
phase. Used by CI (.github/workflows/ci.yml, job `dpi-evasion`) and by local
root-lab runs, so both enforce the exact same bar.

Usage:
    dpi_evasion_check.py {off|on} <sim-log-file>

    off  albus is DOWN: every target must show sim_decision == "rst" and
         bypassed == false. This proves the simulator itself is live — a
         phase that passes without any RST proves nothing (false negative),
         so it fails the gate.
    on   albus is UP: every target must show bypassed == true. Any RST here
         is a real evasion regression.

Exit code is 0 on pass, 1 on any failure (including unparsable logs).
"""

from __future__ import annotations

import json
import sys


def load_results(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        text = f.read()
    # dpi_sim.py prints one JSON object per line, then a final pretty-printed
    # {"results": [...]} block at the end of stdout.
    key = text.rfind('"results"')
    if key == -1:
        raise ValueError("no final {\"results\": [...]} block found in sim log")
    start = text.rfind("{", 0, key)
    if start == -1:
        raise ValueError("no final {\"results\": [...]} block found in sim log")
    payload = json.loads(text[start:])
    results = payload.get("results")
    if not isinstance(results, list) or not results:
        raise ValueError("results block is empty or malformed")
    return results


def check_off(results: list[dict]) -> list[str]:
    errors = []
    for r in results:
        target = r.get("target", "?")
        decision = r.get("sim_decision")
        bypassed = r.get("bypassed")
        print(f"[off] target={target} sim_decision={decision} bypassed={bypassed}")
        if decision != "rst" or bypassed is not False:
            errors.append(
                f"{target}: expected sim_decision=rst + bypassed=false, "
                f"got sim_decision={decision} + bypassed={bypassed} "
                "(simulator did not RST — test itself is invalid)"
            )
    return errors


def check_on(results: list[dict]) -> list[str]:
    errors = []
    for r in results:
        target = r.get("target", "?")
        decision = r.get("sim_decision")
        bypassed = r.get("bypassed")
        handshake = (r.get("detail") or {}).get("handshake_ok")
        print(
            f"[on] target={target} sim_decision={decision} "
            f"bypassed={bypassed} handshake_ok={handshake}"
        )
        if bypassed is not True:
            errors.append(
                f"{target}: expected bypassed=true, got bypassed={bypassed} "
                f"(sim_decision={decision} — evasion regression)"
            )
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[1] not in ("off", "on"):
        print(__doc__, file=sys.stderr)
        return 2
    phase, path = argv[1], argv[2]
    try:
        results = load_results(path)
    except (OSError, ValueError, json.JSONDecodeError) as e:
        print(f"GATE FAIL: cannot parse sim log {path}: {e}")
        return 1
    errors = check_off(results) if phase == "off" else check_on(results)
    if errors:
        for e in errors:
            print(f"GATE FAIL: {e}")
        return 1
    if phase == "off":
        print("DPI simulator: WITHOUT albus -> connection RST'd (expected).")
    else:
        print("DPI simulator: WITH albus -> connection established (evasion successful).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
