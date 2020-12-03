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

# Set tree parameters
num_trees = 40
shingle_size = 4
tree_size = 256

# Create a forest of empty trees
forest = []
for _ in range(num_trees):
    tree = rrcf.RCTree()
    forest.append(tree)

# Use the "shingle" generator to create rolling window
points = rrcf.shingle(X, size=shingle_size)

# Create a dict to store anomaly score of each point
avg_codisp = {}

# For each shingle...
for index, point in enumerate(points):
    print(index)
    # Point shape is shingle_size x dimensions
    # For each tree in the forest...
    for tree in forest:
        # If tree is above permitted size...
        if len(tree.leaves) > tree_size:
            # Drop the oldest point (FIFO)
            tree.forget_point(index - tree_size)
        #
        #
        #
        #
        # Do min-max norm here here
        # https://stats.stackexchange.com/questions/441342/same-value-of-min-and-max-in-min-max-normalisation
        if index == 0:
            window_max = point.max(axis=0).reshape(1, -1)
            window_min = point.min(axis=0).reshape(1, -1)
        else:
            window_max = np.r_[point, window_max].max(axis=0).reshape(1, -1)
            window_min = np.r_[point, window_min].min(axis=0).reshape(1, -1)
        # print(window_min)
        # print(window_max)
        difference = window_max - window_min
        difference[difference==0] = 1
        point = (point - window_min) / difference
        # print(point)
        #
        #
        #
        #
        # Insert the new point into the tree
        tree.insert_point(point, index=index)
        # Compute codisp on the new point...
        new_codisp = tree.codisp(index)
        # And take the average over all trees
        if not index in avg_codisp:
            avg_codisp[index] = 0
        avg_codisp[index] += new_codisp / num_trees

fig, ax1 = plt.subplots(figsize=(10, 5))

# color = 'tab:red'
# ax1.set_ylabel('Data', color=color, size=14)
# ax1.plot(sin, color=color)
# ax1.tick_params(axis='y', labelcolor=color, labelsize=12)
# ax1.set_ylim(0,160)
# ax2 = ax1.twinx()
color = 'tab:blue'
ax1.set_ylabel('CoDisp', color=color, size=14)
ax1.plot(pd.Series(avg_codisp).sort_index(), color=color)
ax1.tick_params(axis='y', labelcolor=color, labelsize=12)
ax1.grid('off')
ax1.set_ylim(0, 160)
plt.title('Network traffic nomaly score (blue)', size=14)
plt.show()
