# Network Configuration Generator 💻

A Python-based script designed to automate the initial configuration setup for network devices (routers and switches). This tool promotes **Infrastructure as Code (IaC)** principles by generating standardized, error-free Cisco-like configuration files from simple, user-provided inputs.

---

## ✨ Features

The generator streamlines network deployment by providing these core functionalities:

* **Subnet Calculation:** Uses the `ipaddress` module to accurately calculate critical network metrics from a single **CIDR** input (e.g., `192.168.1.0/24`), including: Network Address, Broadcast Address, Subnet Mask, and Usable Host Range.
* **Router Configuration:**
    * Sets up two interfaces: a **WAN** interface (configured as DHCP client) and a **LAN** interface (configured with the first usable static IP).
    * Configures **NAT Overload** (PAT) and a standard access-list for Internet access.
* **Switch Configuration:**
    * Configures the **Management Interface (VLAN 1)** with the second usable static IP in the network.
    * Sets the necessary **Default Gateway** for remote management access.
* **DHCP Services:** Generates a complete **DHCP Pool** configuration for the LAN and automatically **excludes** the first 10 usable IP addresses for static assignments (router, switch, servers).
* **Basic Security Hardening:** Implements essential security commands, including disabling HTTP servers and setting a warning **MOTD Banner**.
* **Input Validation:** Ensures the stability of the script by validating the CIDR format, prefix length, and device naming conventions.

---

## 🚀 Getting Started

### Prerequisites

You need **Python 3** installed on your system.

### Installation

1.  **Clone the repository:**
    ```bash
    git clone git@github.com:Deception94/Network-Config-Generator.git
    cd Network-Config-Generator
    ```
2.  **No dependencies are required** as the script uses only the built-in `ipaddress` module.

### Usage

1.  **Run the script from your terminal:**
    ```bash
    python automate_config.py
    ```

2.  **Follow the interactive prompts:**
    | Prompt | Example Input | Purpose |
    | :--- | :--- | :--- |
    | `Enter network IP in CIDR notation:` | `192.168.10.0/24` | Defines the subnet for the LAN. |
    | `Enter device type (router/switch):` | `router` | Determines which configuration template to use. |
    | `Enter device hostname:` | `HQ-RTR-01` | Sets the device hostname and the output file name. |

3.  **Review the Output:** The full configuration will be printed to the console and automatically saved to a text file in the same directory (e.g., `HQ-RTR-01_router.txt`).

---

## 🛠️ Technology

* **Language:** Python 3
* **Library:** `ipaddress` (Python Standard Library)
* **Target Syntax:** Cisco IOS-like commands

---

## 🔗 References

This project is built upon core Computer Networking and Python principles.

1.  **Cisco, *Cisco IOS and Network Fundamentals*.**
    * *Reference for standard network device configuration syntax (DHCP, NAT, Interface setup).*
2.  **Python Software Foundation. *The Python Standard Library (ipaddress — IPv4/IPv6 manipulation)*.**
    * *Reference for the accurate, programmatic calculation of IP addresses and subnet details.*
