#!/usr/bin/env python3
import re
import sys

def parse_ftrace(path):
    values = []
    pattern = re.compile(r'took (\d+) ns')
    with open(path) as f:
        for line in f:
            m = pattern.search(line)
            if m:
                values.append(int(m.group(1)))
    return values

def percentile(sorted_vals, p):
    idx = int(len(sorted_vals) * p / 100)
    idx = min(idx, len(sorted_vals) - 1)
    return sorted_vals[idx]

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "upstream"
    values = parse_ftrace(path)
    if not values:
        print("No data found")
        return

    values.sort()
    avg = sum(values) / len(values)

    print(f"samples: {len(values)}")
    print(f"avg:     {avg:.0f} ns")
    print(f"p50:     {percentile(values, 50)} ns")
    print(f"p99:     {percentile(values, 99)} ns")
    print(f"min:     {values[0]} ns")
    print(f"max:     {values[-1]} ns")

if __name__ == "__main__":
    main()
