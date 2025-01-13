import time
import os
import datetime

os.system("date +%s > now")

now = 0
start = 0

with open("start", "r") as f:
    start = int(f.readline().replace(" ", "").replace("\n", ""))

with open("now", "r") as f:
    now = int(f.readline().replace(" ", "").replace("\n", ""))

print(datetime.timedelta(seconds=now-start))
