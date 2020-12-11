import numpy as np
import pandas as pd
import rrcf
import matplotlib.pyplot as plt
import time

# RRCF sensitive to dimension with largest min-max difference
# Need to address min/max normalization in a streaming context
# Drop cols 21, 24 due to high mag
# Greater range of codisp values seen when two columns are dropped
# https://arxiv.org/ftp/arxiv/papers/1910/1910.07696.pdf

# Load the data
# df = pd.read_csv('test.csv', header=None, skiprows=1)
df = pd.read_csv('test.csv')
df = df.drop(['seq_raw', 'ack_raw'], axis=1)
df = df.fillna(0)
print(df.head())
X = df.to_numpy()
print(X.shape)

print(df.describe().T)


#
# fig, ax1 = plt.subplots(figsize=(10, 5))
#
# # color = 'tab:red'
# # ax1.set_ylabel('Data', color=color, size=14)
# # ax1.plot(sin, color=color)
# # ax1.tick_params(axis='y', labelcolor=color, labelsize=12)
# # ax1.set_ylim(0,160)
# # ax2 = ax1.twinx()
# color = 'tab:blue'
# ax1.set_ylabel('CoDisp', color=color, size=14)
# ax1.plot(pd.Series(avg_codisp).sort_index(), color=color)
# ax1.tick_params(axis='y', labelcolor=color, labelsize=12)
# ax1.grid('off')
# ax1.set_ylim(0, 160)
# plt.title('Network traffic nomaly score (blue)', size=14)
# plt.show()
