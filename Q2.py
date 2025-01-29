from scapy.all import rdpcap, IP, TCP, Raw

# Load the PCAP file
pcap_file = "3.pcap"  # Ensure this file is in the same directory
packets = rdpcap(pcap_file)

# Variables to track login attempts and successful login
login_attempts = 0
successful_credentials = None
successful_source_port = None
total_content_length = 0

# Target IP
target_ip = "192.168.10.50"

for pkt in packets:
    if IP in pkt and TCP in pkt and Raw in pkt:
        if pkt[IP].dst == target_ip or pkt[IP].src == target_ip:
            payload = pkt[Raw].load.decode(errors="ignore")  # Decode payload safely

            # Check if it's an HTTP POST request (Login Attempt)
            if "POST" in payload and "password" in payload:
                login_attempts += 1

                # Extract credentials from payload
                lines = payload.split("\r\n")
                credentials = {}
                for line in lines:
                    if "=" in line:  # Simple key-value extraction
                        key, value = line.split("=", 1)
                        credentials[key.strip()] = value.strip()

                # Check for successful login attempt
                if "password" in credentials and credentials["password"] == "secure password":
                    successful_credentials = credentials
                    successful_source_port = pkt[TCP].sport  # Get client's source port

                # Extract Content-Length (if available)
                for line in lines:
                    if "Content-Length:" in line:
                        try:
                            content_length = int(line.split(":")[1].strip())
                            total_content_length += content_length
                        except ValueError:
                            pass  # Ignore parsing errors

# Display results
print(f"Q1. Number of Login Attempts: {login_attempts}")
if successful_credentials:
    print(f"Q2. Successful Credentials: {successful_credentials}")
    print(f"Q3. Client's Source Port for Successful Login: {successful_source_port}")
else:
    print("Q2. No successful login found.")
print(f"Q4. Total Content Length of All Login Attempt Payloads: {total_content_length} bytes")