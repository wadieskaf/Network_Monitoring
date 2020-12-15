import numpy as np
import pandas as pd
import rrcf
import matplotlib.pyplot as plt
import time
import pyshark

# RRCF sensitive to dimension with largest min-max difference
# Need to address min/max normalization in a streaming context
# Drop cols 21, 24 due to high mag
# Greater range of codisp values seen when two columns are dropped
# https://arxiv.org/ftp/arxiv/papers/1910/1910.07696.pdf

# Load the data
capture = pyshark.FileCapture('./2019 Singapore ICS data/Dec2019_00000_20191206100500.pcap')
packet_list = []
# for i, packet in enumerate(capture):
#     if i == 10000:
#         break
#     packet_list.append(packet)

# Relevant features
# layers_dict = {'ETH': [{'dst_lg': []}, {'lg': []}, {'dst_ig': []}, {'ig': []}, {'src_lg': []}, {'src_ig': []}],
#                'VLAN': [{'priority': []}, {'dei': []}, {'id': []}],
#                'IP': [{'hdr_len': []}, {'len': []}, {'flags_rb': []}, {'flags_df': []}, {'flags_mf': []}, {'frag_offset': []}, {'ttl': []}, {'proto': []}, {'checksum_status': []}],
#                'TCP': [{'stream':[]}, {'len':[]}, {'seq':[]}, {'nxtseq':[]}, {'ack':[]},
#                 {'hdr_len':[]}, {'flags_res':[]}, {'flags_ns':[]}, {'flags_cwr':[]}, {'flags_ecn':[]}, {'flags_urg':[]}, {'flags_ack':[]},
#                 {'flags_push':[]}, {'flags_reset':[]}, {'flags_syn':[]}, {'flags_fin':[]}, {'checksum_status':[]}, {'urgent_pointer':[]}],
#                'UDP':[{'length':[]}, {'checksum_status':[]}, {'stream':[]}, {'time_relative':[]}, {'time_delta':[]}]}

layers_dict = {'ETH': [{'dst_lg': []}, {'lg': []}, {'dst_ig': []}, {'ig': []}, {'src_lg': []}, {'src_ig': []}],
               'VLAN': [{'priority': []}, {'dei': []}],
               'IP': [{'hdr_len': []}, {'len': []},
                      {'ttl': []}, {'proto': []}, {'checksum_status': []}],
               'TCP': [{'stream': []}, {'len': []}, {'seq': []}, {'nxtseq': []},
                       {'hdr_len': []},
                       {'checksum_status': []}, {'urgent_pointer': []}],
               'UDP': [{'length': []}, {'checksum_status': []}, {'stream': []}]}

# Set tree parameters
num_trees = 40
shingle_size = 2
tree_size = 128
num_feats = 23

# Create a forest of empty trees
forest = []
for _ in range(num_trees):
    tree = rrcf.RCTree()
    forest.append(tree)

# Use the "shingle" generator to create rolling window
# points = rrcf.shingle(X, size=shingle_size)

# Create a dict to store anomaly score of each point
avg_codisp = {}

# For each shingle...
# Need to account for NA values
# for index in range(len(packet_list) - shingle_size):
for index in range(1000):
    print(index)
    # window = []
    # for i in range(shingle_size):
    #     window.append(capture[index + i])
    # window = capture[index:index + shingle_size]
    updated_window = np.empty((shingle_size, num_feats))

    for j in range(shingle_size):
        row = []
        for layer_key in layers_dict.keys():
            layer_attributes = layers_dict[layer_key]
            for k, attribute in enumerate(layer_attributes):
                try:
                    attribute_name = list(attribute.keys())[0]
                    # layers_dict[layer_key][k][attribute_name].append(getattr(packet_list[j][layer_key], list(attribute.keys())[0]))
                    # row.append(getattr(window[j][layer_key], list(attribute.keys())[0]))
                    row.append(getattr(capture[index + j][layer_key], list(attribute.keys())[0]))
                    # column_names[attribute].append(val)
                except:
                    attribute_name = list(attribute.keys())[0]
                    # layers_dict[layer_key][k][attribute_name].append(np.nan)
                    row.append(np.nan)

        updated_window[j, :] = row

    point = np.nan_to_num(updated_window)

    # Do min-max norm here here
    # https://stats.stackexchange.com/questions/441342/same-value-of-min-and-max-in-min-max-normalisation
    if index == 0:
        window_max = point.max(axis=0).reshape(1, -1)
        window_min = point.min(axis=0).reshape(1, -1)
    else:
        window_max = np.r_[point, window_max].max(axis=0).reshape(1, -1)
        window_min = np.r_[point, window_min].min(axis=0).reshape(1, -1)

    difference = window_max - window_min
    difference[difference == 0] = 1
    point = (point - window_min) / difference

    # print(point)
    # Point shape is shingle_size x dimensions
    # For each tree in the forest...
    for tree in forest:
        # If tree is above permitted size...
        if len(tree.leaves) > tree_size:
            # Drop the oldest point (FIFO)
            tree.forget_point(index - tree_size)


        # Insert the new point into the tree
        tree.insert_point(point, index=index)
        # Compute codisp on the new point...
        new_codisp = tree.codisp(index)
        # And take the average over all trees
        if not index in avg_codisp:
            avg_codisp[index] = 0
        avg_codisp[index] += new_codisp / num_trees
    # print(avg_codisp[index])

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
