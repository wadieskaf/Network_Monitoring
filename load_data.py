import pyshark


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
conversations = []
for i, packet in enumerate(capture):
    if i == 20:
        break
    results = network_conversation(packet)
    if results != None:
        conversations.append(results)

# this sorts the conversations by protocol
# TCP and UDP
for item in sorted(conversations):
    print(item)

print(capture[0])

for packet in capture:
    print(packet.layers)
    break

layers = ['ETH', 'VLAN', 'IP', 'TCP', 'ENIP', 'CIP', 'CIPCLS']
layers_dict = {'ETH': ['dst', 'dst_resolved', 'dst_oui', 'dst_oui_resolved', 'addr', 'addr_resolved', 'addr_oui', 'addr_oui_resolved', 'dst_lg', 'lg', 'dst_ig', 'ig', 'src', 'src_resolved', 'src_oui', 'src_oui_resolved', 'src_lg', 'src_ig', 'type'],
              'VLAN': ['priority', 'dei', 'id', 'etype'],
              'IP': ['version', 'hdr_len', 'dsfield', 'dsfield_dscp', 'dsfield_ecn', 'len', 'id', 'flags', 'flags_rb', 'flags_df', 'flags_mf', 'frag_offset', 'ttl', 'proto', 'checksum', 'checksum_status', 'src', 'addr', 'src_host', 'host', 'dst', 'dst_host'],
              'TCP': ['srcport', 'dstport', 'port', 'stream', 'len', 'seq', 'seq_raw', 'nxtseq', 'ack', 'ack_raw', 'hdr_len', 'flags', 'flags_res', 'flags_ns', 'flags_cwr', 'flags_ecn', 'flags_urg', 'flags_ack', 'flags_push', 'flags_reset', 'flags_syn', 'flags_fin', 'flags_str', 'window_size_value', 'window_size', 'window_size_scalefactor', 'checksum', 'checksum_status', 'urgent_pointer', 'analysis', 'analysis_bytes_in_flight', 'analysis_push_bytes_sent', '', 'time_relative', 'time_delta', 'payload', 'pdu_size'],
              'ENIP': ['', 'command', 'length', 'session', 'status', 'context', 'options', 'sud_iface', 'timeout', 'cpf_itemcount', 'cpf_typeid', 'cpf_length', 'cpf_cai_connid', 'cip_seq'],
              'CIP': ['service', 'rr', 'sc', 'request_path_size', '', 'epath', 'path_segment', 'path_segment_type', 'data_segment_type', 'data_segment_size', 'symbol'],
              'CIPCLS': ['', 'cip_data']}

for i in range(len(capture)):
    for layer_key in layers_dict:
        layer_attributes = layers_dict[layer_key]
        for attribute in layer_attributes:
            try:
                val = getattr(capture[i][layer_key], attribute)
                # column_names[attribute].append(val)
            except:
                continue