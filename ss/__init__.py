"""sovereign-stack.

One gateway that joins the three things a public-sector IT office is asked to do
separately:

  exchange    move a statistic across a jurisdiction boundary without moving the
              records it was computed from
  compliance  decide a control status against a catalogue, and be able to say
              "the evidence does not settle this" without guessing
  ops         keep the whole thing running where the link is intermittent and the
              power is not guaranteed

Submodules are imported lazily: `from ss import exchange` works, and a machine
without one optional dependency can still use the rest.
"""
from __future__ import annotations

import importlib

__all__ = ["crypto", "identity", "zk", "exchange", "compliance", "ops", "net"]
__version__ = "0.1.0"


def __getattr__(name):
    if name in __all__:
        module = importlib.import_module("." + name, __name__)
        globals()[name] = module
        return module
    raise AttributeError(name)
