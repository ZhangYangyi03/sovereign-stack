"""Turn bench/results.json into the table that lives in README.md.

    python bench/table.py            # print the markdown
    python bench/table.py --write    # replace the block between the markers

The README's table is generated, not typed: a number that cannot be regenerated
is a number nobody should believe.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
START = "<!-- bench:start -->"
END = "<!-- bench:end -->"


def rows(data: dict) -> list:
    out = []
    env = data.get("environment", {})
    out.append("| what | number |")
    out.append("| --- | --- |")
    if env:
        out.append("| host | %s, %s, %d cores, python %s, modexp via %s |"
                   % (env.get("machine"), env.get("platform", "").split("-SP")[0],
                      env.get("cpu_count", 0), env.get("python"), env.get("pow_backend")))
    for row in data.get("crypto", []):
        out.append("| %s | %.1f ms |" % (row["name"], row["ms_median"]))
    for row in data.get("zk", []):
        if "verify" in row:
            out.append("| %s: prove / verify | %.0f ms / %.0f ms, %d bytes |"
                       % (row["name"], row["prove"]["ms_median"], row["verify"]["ms_median"],
                          row.get("bytes", 0)))
    for row in data.get("exchange", []):
        out.append("| %s | %.0f ms, proof %d bytes |"
                   % (row["name"], row["ms_median"], row.get("bytes", 0)))
    for row in data.get("compliance", []):
        if "controls" in row and "counts" not in row:
            out.append("| %s (%d controls) | %.1f ms |"
                       % (row["name"], row["controls"], row["ms_median"]))
    for row in data.get("ops", []):
        out.append("| %s | %.0f ms, %d ops, lost %d, converged %s |"
                   % (row["name"], row["ms_median"], row["operations"], row["lost"],
                      row["converged"]))
    for row in data.get("transport", []):
        out.append("| %s | %.2f ms |" % (row["name"], row["ms_median"]))
    return out


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    with open(os.path.join(HERE, "results.json"), encoding="utf-8") as fh:
        data = json.load(fh)
    table = "\n".join(rows(data))
    if "--write" not in argv:
        print(table)
        return 0
    readme = os.path.join(os.path.dirname(HERE), "README.md")
    with open(readme, encoding="utf-8") as fh:
        text = fh.read()
    if START not in text or END not in text:
        raise SystemExit("README has no %s / %s block" % (START, END))
    head, rest = text.split(START, 1)
    _, tail = rest.split(END, 1)
    with open(readme, "w", encoding="utf-8") as fh:
        fh.write(head + START + "\n" + table + "\n" + END + tail)
    print("README table updated from %d sections" % len(data))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
