import pyshark
import pandas as pd


def network_conversation(packet):
    try:
        protocol = packet.transport_layer
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        return f'{protocol} {source_address}:{source_port} --> {destination_address}:{destination_port}'
    except AttributeError as e:
        pass


capture = pyshark.FileCapture('./2019 Singapore ICS data/Dec2019_00000_20191206100500.pcap')
# capture.set_debug()

# CHANGE THE LOOP INDEX TO EXPAND SAMPLES USED
packet_list = []
for i, packet in enumerate(capture):
    if i == 10000:
        break
    packet_list.append(packet)

# for packet in packet_list:
#     try:
#         print(packet['UDP'].field_names)
#     except:
#         pass

# capture.close()


total_layers = ['ETH', 'VLAN', 'IP', 'TCP', 'UDP', 'ENIP', 'CIP', 'CIPCLS', 'CIPCM', 'CIPCLS', 'CIPIO', 'TLS']

layers_attributes = {'ETH': ['dst', 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr', 'addr_resolved', 'addr_oui', 'addr_oui_resolved', 'dst_lg', 'lg', 'dst_ig', 'ig', 'src', 'src_resolved', 'src_oui', 'src_oui_resolved', 'src_lg', 'src_ig', 'type'],
              'VLAN': ['priority', 'dei', 'id', 'etype'],
              'IP': ['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host'],
              'TCP': ['srcport', 'dstport', 'port', 'stream', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ns', 'flags_cwr', 'flags_ecn', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'window_size_scalefactor', 'checksum', 'checksum_status', 'urgent_pointer', 'analysis', 'analysis_bytes_in_flight', 'analysis_push_bytes_sent', '', 'time_relative', 'time_delta', 'payload', 'pdu_size'],
              'UDP':['srcport', 'dstport', 'port', 'length', 'checksum', 'checksum_status', 'stream', '', 'time_relative', 'time_delta', 'payload'],
              'ENIP': ['', 'command', 'length', 'session', 'status', 'context', 'options', 'sud_iface', 'timeout', 'cpf_itemcount', 'cpf_typeid', 'cpf_length', 'cpf_cai_connid', 'cip_seq'],
              'CIP': ['service', 'rr', 'sc', 'request_path_size', '', 'epath', 'path_segment', 'path_segment_type', 'data_segment_type', 'data_segment_size', 'symbol'],
              'CIPCLS': ['', 'cip_data']}

# CIP and CIPCLS, CIPCM, CIPCLS, CIPIO, TLS, and ENIP are very sparse so most of the values in those columns will be None
# type variables are in hexadecimal but categorical so division based off magnitude won't work
# address variables make no sense to include
# all len values, checksum_type, time values will be important
# 'flag' values are hex while 'flag_' values are not, both categorical
# checksum is not categorical, probably able to be removed

layers_dict = {'ETH': [{'dst_lg': []}, {'lg': []}, {'dst_ig': []}, {'ig': []}, {'src_lg': []}, {'src_ig': []}],
               'VLAN': [{'priority': []}, {'dei': []}, {'id': []}],
               'IP': [{'hdr_len': []}, {'len': []}, {'flags_rb': []}, {'flags_df': []}, {'flags_mf': []}, {'frag_offset': []}, {'ttl': []}, {'proto': []}, {'checksum_status': []}],
               'TCP': [{'stream':[]}, {'len':[]}, {'seq':[]}, {'seq_raw':[]}, {'nxtseq':[]}, {'ack':[]}, {'ack_raw':[]},
                {'hdr_len':[]}, {'flags_res':[]}, {'flags_ns':[]}, {'flags_cwr':[]}, {'flags_ecn':[]}, {'flags_urg':[]}, {'flags_ack':[]},
                {'flags_push':[]}, {'flags_reset':[]}, {'flags_syn':[]}, {'flags_fin':[]}, {'checksum_status':[]}, {'urgent_pointer':[]}],
               'UDP':[{'length':[]}, {'checksum_status':[]}, {'stream':[]}, {'time_relative':[]}, {'time_delta':[]}]}

for i in range(len(packet_list)):
    for layer_key in layers_dict.keys():
        layer_attributes = layers_dict[layer_key]
        for j, attribute in enumerate(layer_attributes):
            try:
                attribute_name = list(attribute.keys())[0]
                layers_dict[layer_key][j][attribute_name].append(getattr(packet_list[i][layer_key], list(attribute.keys())[0]))
                # column_names[attribute].append(val)
            except:
                attribute_name = list(attribute.keys())[0]
                layers_dict[layer_key][j][attribute_name].append(None)


feature_list = []
feature_names = []
for layer_key in layers_dict.keys():
    layer_attributes = layers_dict[layer_key]
    for j, attribute in enumerate(layer_attributes):
        attribute_name = list(attribute.keys())[0]
        feature_names.append(attribute_name)
        feature_list.append(layers_dict[layer_key][j][attribute_name])

output_df = pd.DataFrame(list(zip(*feature_list)), columns=feature_names)
output_df.to_csv(index=False, path_or_buf='test.csv')