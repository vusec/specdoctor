import subprocess

import subprocess
# shlex takes care of splitting a string representing a command in words for subprocess
import shlex
import os
import time
import sys
from datetime import datetime, timedelta
import argparse
import statistics

command = "python3 run.py -t Boom -atk U2S -com ATTACKER -o out-phase2 -nt1 20 -nt3 20 -nt4 0 -k"
vulns = [
        "meltdown",
        "spectre_v1",
        # "spectre_v2",
        # "spectre_rsb",
        # "other"
        ]

def found(vuln: str, bin_path: str, start_ts: float, ttes):
    if vuln not in ttes.keys() or ttes[vuln] == None:
        print(f"Found {vuln}")
        ts = os.stat(bin_path).st_mtime
        ttes[vuln] = ts

        print(datetime.fromtimestamp(ts))
        diff = int(ts-start_ts)
        print(f"{int(diff / 3600)}:{int(diff / 60) % 60}:{diff % 60}")

def found_all(ttes):
    for t in ttes.keys():
        if t in vulns and ttes[t] == None:
            return False

    return True

def init_ttes():
    ttes = {}
    for v in vulns:
        ttes[v] = None
    return ttes

def get_ts_diff(diff: float):
    return f"{int(diff / 3600)}:{int(diff / 60) % 60}:{int(diff % 60)}"


def collect_runs(path):
    stats = []
    subfolders = [ f.path for f in os.scandir(path) if f.is_dir() ]
    for s in subfolders:
        try:
            f = open(s + "/ttes.txt")
            entry = {}
            for l in f:
                fields = l.replace('\n','').split(':')
                if fields[1] != 'None':
                    entry[fields[0]] = float(fields[1])
            for k in entry.keys():
                if k != 'start':
                    entry[k] -= entry['start']
            stats.append(entry)
            f.close()
        except:
            print("Skipping...")
            continue
    return stats

def print_stats(path):
    stats = collect_runs(path)
    bugs = set([ k for k in stats[0].keys() if k != 'start'])
    for b in bugs:
        ttes = [stats[i][b] for i in range(len(stats))]
        print(f"============ Vuln: {b}")
        print(f"Mean: {get_ts_diff(statistics.mean(ttes))}")
        print(f"Geomean: {get_ts_diff(statistics.geometric_mean(ttes))}")
        print(f"Std: {get_ts_diff(statistics.stdev(ttes))}")
        print(f"Min: {get_ts_diff(min(ttes))}")
        print(f"Max {get_ts_diff(max(ttes))}")
        print("")


parser = argparse.ArgumentParser(prog='Specdoctor-no-sidechannel evaluation')
parser.add_argument('-n', '--runs', type=int, default=5, help="Number of runs")
parser.add_argument('-o', '--results-dir', default="results", help="Path of the output folder")
parser.add_argument('--dry-run', action='store_true', help="Test command without running the fuzzer")
parser.add_argument('--stats-only', action='store_true', help="Only print stats of an existing run")
parser.add_argument('--no-l1', action='store_true', help="Remove bias that loads the secret in L1 before the speculative window")
args = parser.parse_args()

if args.stats_only:
    print_stats(args.results_dir)
    sys.exit(0)

if args.no_l1:
    command += " -l1 0.0"

# Create results folder
subprocess.call(shlex.split(f"mkdir -p {args.results_dir}"))
print(f"Results folder {args.results_dir}")

for i in range(args.runs):
    # Create start file
    subprocess.call(shlex.split("touch start"))
    start_ts = os.stat("start").st_mtime

    # Start SpecDoctor
    if not args.dry_run:
        _process = subprocess.Popen(shlex.split(command), env=os.environ.copy())

    time.sleep(2)
    out_dir = "out-phase2/"
    # Read the PID
    pid_f = out_dir + "pid"
    f = open(pid_f)
    pid = f.readline().replace('\n','').strip()
    print(f"Started fuzzer with PID {pid}")
    print(datetime.fromtimestamp(start_ts))
    f.close()


    # time.sleep(10)
    # subprocess.call(shlex.split(f"kill -15 {pid}"))
    # sys.exit(0)

    bin_dir = out_dir + "diff/input/"
    ttes = init_ttes()

    while not found_all(ttes):
        bins = os.listdir(bin_dir)
        for b in bins:
            if b.endswith(".elf"):
                cause = b.split("_")[5]
                inst = b.split("_")[6]
                if cause == "BR":
                    if inst.startswith("b"):
                        found("spectre_v1", bin_dir + b, start_ts, ttes)
                    elif inst.startswith("j"):
                        found("spectre_v2", bin_dir + b, start_ts, ttes)
                    elif inst.startswith("r"):
                        found("spectre_rsb", bin_dir + b, start_ts, ttes)
                    else:
                        found(f"other_{inst}", bin_dir + b, start_ts, ttes)

                elif cause == "XCPT":
                    found("Meltdown", bin_dir + b, start_ts, ttes)

        time.sleep(1)

    f = open(f'{out_dir}/ttes.txt', 'w')
    f.write(f"start:{start_ts}\n")
    for t in ttes.keys():
        f.write(f"{t}:{ttes[t]}")
    f.close()

    subprocess.call(shlex.split(f"mv start {out_dir}"))
    subprocess.call(shlex.split(f"kill -15 {pid}"))
    # Wait for the fuzzer to die.
    time.sleep(180)

    subprocess.call(shlex.split(f"mv {out_dir} {args.results_dir}/{i}"))
    print(f"Ended run {i}")

print_stats(args.results_dir)
