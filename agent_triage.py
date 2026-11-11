#!/usr/bin/env python3
"""Retired legacy cloud triage agent.

The original implementation used shell=True and passed untrusted data to a
remote LLM. It is disabled on the defensive branch. Use q_safe.analyzer.
"""
import sys
if __name__ == "__main__":
    print("Q-SAFE: legacy agent_triage.py is disabled; use python -m q_safe.cli.", file=sys.stderr)
    raise SystemExit(2)
