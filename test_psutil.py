import psutil
import numpy as np
import pandas as pd
print("psutil installed successfully.")

print("CPU usage:", psutil.cpu_percent(interval=1), "%")

print("Memory usage:", psutil.virtual_memory().percent, "%")

print("Number of running processes:", len(psutil.pids()))

