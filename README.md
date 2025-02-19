# WireFish - Packet Sniffer

WireFish is a lightweight, efficient, and scalable packet sniffer built using **libpcap** in **C** while applying **Object-Oriented Programming (OOP) principles**. It provides real-time packet capture, protocol analysis, and filtering capabilities similar to **Wireshark** or **Tcpdump**.

## Features
- **Written in C** with **OOP design** for maintainability and scalability.
- **Captures and analyzes IP packets**, displaying key header fields.
- **Supports Layer 4 protocols:**
  - TCP
  - UDP
  - ICMP
- **Supports Layer 7 protocols:**
  - HTTP
  - DNS
  - FTP
- **Multiple levels of inheritance** for efficient protocol handling.
- **Filtering by IP address and port** via command-line arguments.
- **Bonus Feature:** Option to **save captured packets** in **PCAP format** for analysis in Wireshark.

## Installation
### Prerequisites
Ensure you have **libpcap** installed on your system:
```sh
sudo apt-get install libpcap-dev  # Ubuntu/Debian
sudo yum install libpcap-devel    # CentOS/RHEL
brew install libpcap              # macOS
```

### Compilation
Compile the WireFish program using **GCC**:
```sh
gcc -o wirefish wirefish.c -lpcap
```

## Usage
### Basic Command
```sh
sudo ./wirefish -i <interface> [-f "filter expression"] [-o output.pcap]
```

### Examples
#### Capture all packets on interface `eth0`:
```sh
sudo ./wirefish -i eth0
```

#### Capture only TCP traffic from a specific IP:
```sh
sudo ./wirefish -i eth0 -f "tcp and src host 192.168.1.1"
```

#### Capture and save packets to `capture.pcap`:
```sh
sudo ./wirefish -i eth0 -o capture.pcap
```

## OOP Design in C
WireFish follows an **OOP-like structure** using **structs and function pointers**:
- **Base Packet Class:** Generic packet structure.
- **Derived Protocol Classes:** Specific handlers for **TCP, UDP, ICMP, HTTP, DNS, and FTP**.
- **Encapsulation:** Packet structures are abstracted, ensuring maintainability.
- **Polymorphism:** Function pointers allow different protocol handlers to be called dynamically.
- **Modularity:** New protocols can be added with minimal changes.

## Scalability & Maintainability
- **Modular Design:** Each protocol is independent, making it easy to extend.
- **Efficient Filtering:** Uses `pcap_compile` for optimized packet selection.
- **Memory Safety:** Proper handling of pointers and memory allocation prevents leaks.
- **Error Handling:** Graceful handling of invalid inputs and runtime errors.

## Future Enhancements
- Support for **IPv6 packets**.
- Integration with a **GUI** for real-time visualization.
- More advanced **packet inspection and analysis**.

## Video
[expalin the project](https://drive.google.com/file/d/1oLluowNProAqQiHsMeSOInqNsICbIb0W/view?usp=sharing)



