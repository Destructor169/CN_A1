# README - PCAP Analysis

## Group Number: 30

### **PCAP File Selection Criteria**
The PCAP file is chosen based on the formula:
**X = (Team ID) % 9**
where Team ID is obtained from the Google Sheets. The corresponding PCAP file from the provided dataset is selected accordingly.

---

## **Team Members**
- **Aditya Kumar**  
- **Mrugank Patil**

---

## **Assignment Description**

### **Part 1: Metrics and Plots (40 points)**
From the selected **X.pcap** file, we extract and generate the following network traffic metrics by replaying the PCAP file using tools like `tcpreplay`:

1. **Total Data Statistics:**
   - Compute the total amount of data transferred (in bytes), the total number of packets, and the minimum, maximum, and average packet sizes.
   - Visualize the distribution of packet sizes by plotting a histogram.

2. **Unique Source-Destination Pairs:**
   - Identify unique pairs of source and destination IP addresses along with their respective ports.

3. **Flow Analysis:**
   - Display a dictionary where the key is the IP address and the value is the total flows for that IP address as the source.
   - Similarly, display a dictionary where the key is the IP address and the value is the total flows for that IP address as the destination.
   - Identify the source-destination pair (IP:port to IP:port) that transferred the most data.

4. **Performance Metrics:**
   - Measure the maximum packet processing speed in terms of packets per second (`pps`) and megabits per second (`mbps`).
   - Test the program under different conditions:
     - Running `tcpreplay` and the analysis program on the same machine (VM).
     - Running on different machines, where one machine replays the traffic and another captures it.

---

### **Part 2: Catch Me If You Can (40 points)**
For the designated **X.pcap** file, the program is extended to analyze and answer specific questions:

- **Q1:** How many login attempts were made?  
  _(Hint: Filter packets with IP `192.168.10.50`)_

- **Q2:** What are the credentials used in the successful login attempt?  
  _(Hint: The password is "secure password")_

- **Q3:** What is the client's source port number during the successful login attempt?

- **Q4:** What is the total content length of all login attempt payloads?

---

### **Part 3: Capture the Packets (20 points)**
Wireshark is used to capture real-time network traffic while performing regular internet activities. The analysis includes:

#### **(1) Identifying New Application Layer Protocols**
- List at least **5 different application layer protocols** not covered in class.
- Describe their operation, layer of usage, and provide their associated RFC number.

#### **(2) Website Traffic Analysis**
Analyzing network traffic while visiting:
- [Canara Bank](https://canarabank.in)
- [GitHub](https://github.com)
- [Netflix](https://netflix.com)

##### **Extract the following details:**
- **Request Line:** Identify the request line with the version of the application layer protocol and the corresponding IP address.
- **Connection Persistence:** Determine if the connection is persistent or not.
- **HTTP Header Fields:** Extract three request and response header fields and their values.
- **HTTP Error Codes:** List any three error codes encountered while loading the pages, along with brief descriptions.
- **Performance Metrics:** Capture browser-reported performance metrics when loading a webpage.
- **Cookies and Flags:** Identify the cookies used and their corresponding flags in request and response headers.
- **Browser Name & Screenshot:** Provide a screenshot of the performance metrics recorded in the browser's developer tools.

---

## **CSV Files Overview**
The CSV files generated in **Part 1 - Section 3** contain:
- A dictionary where the **key** is the **IP address**, and the **value** is the total flows for that IP as a source.
- A dictionary where the **key** is the **IP address**, and the **value** is the total flows for that IP as a destination.
- A record of the **source-destination pair (IP:port to IP:port) that transferred the most data.**

These files store all relevant data required to answer the questions in this section.

---
