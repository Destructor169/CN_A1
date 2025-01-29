from scapy.all import rdpcap, IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import defaultdict
import csv

# Load the PCAP file
pcap_file = "3.pcap"  # Make sure this file is in the same directory
packets = rdpcap(pcap_file)

# 1. Total Data Transferred (Bytes)
total_data = sum(len(pkt) for pkt in packets)
print(f"Total Data Transferred: {total_data} bytes")

# 2. Total Number of Packets
total_packets = len(packets)
print(f"Total Packets: {total_packets}")

# 3. Packet Size Statistics
packet_sizes = [len(pkt) for pkt in packets]
min_size = min(packet_sizes)
max_size = max(packet_sizes)
avg_size = sum(packet_sizes) / total_packets

print(f"Min Packet Size: {min_size} bytes")
print(f"Max Packet Size: {max_size} bytes")
print(f"Average Packet Size: {avg_size:.2f} bytes")

# 4. Histogram of Packet Sizes
plt.hist(packet_sizes, bins=20, edgecolor='black')
plt.xlabel("Packet Size (Bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution")
plt.show()

# 5. Unique Source-Destination Pairs
unique_pairs = set()
for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        if TCP in pkt or UDP in pkt:
            sport = pkt.sport
            dport = pkt.dport
            unique_pairs.add((src, sport, dst, dport))

print(f"Unique Source-Destination Pairs: {len(unique_pairs)}")
with open('unique_pairs.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Source IP', 'Source Port', 'Destination IP', 'Destination Port'])
    for pair in unique_pairs:
        writer.writerow([pair[0], pair[1], pair[2], pair[3]])

# 6. Total Flows per IP Address
src_flows = defaultdict(int)
dst_flows = defaultdict(int)
data_transferred = defaultdict(int)

for pkt in packets:
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        length = len(pkt)
        src_flows[src] += 1
        dst_flows[dst] += 1
        data_transferred[(src, dst)] += length

print("Source IP Flows:")
with open('src_flows.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Source IP', 'Flow Count'])
    for ip, count in src_flows.items():
        writer.writerow([ip, count])

print("Destination IP Flows:")
with open('dst_flows.csv', 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Destination IP', 'Flow Count'])
    for ip, count in dst_flows.items():
        writer.writerow([ip, count])

# 7. Source-Destination Pair with Most Data Transferred
max_data_pair = max(data_transferred, key=data_transferred.get)
max_data = data_transferred[max_data_pair]
print(f"Source-Destination Pair with Most Data: {max_data_pair[0]} -> {max_data_pair[1]}: {max_data} bytes")