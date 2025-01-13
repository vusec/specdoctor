#!/bin/bash

date +%s > start
python3 run.py -t Boom -atk U2S -com ATTACKER -o out-phase2 -nt1 20 -nt3 20 -nt4 0 -k
