#!/usr/bin/env python3
"""
Network Configuration Generator
Automates the creation of network device configurations
"""

import ipaddress
import re


def display_welcome_banner():
    """Display welcome banner"""
    print("=" * 50)
    print("      NETWORK CONFIGURATION GENERATOR")
    print("=" * 50)
    print("Automates router/switch configuration generation")
    print("Features: IP calculation, DHCP, Security, NAT")
    print("=" * 50)
    print()


def validate_input(network_cidr, device_type, device_name):
    """
    Validate all user inputs and return error messages if any
    
    Args:
        network_cidr (str): CIDR notation (e.g., 192.168.1.0/24)
        device_type (str): 'router' or 'switch'
        device_name (str): Device hostname
    
    Returns:
        list: List of error messages, empty if valid
    """
    errors = []

    # Validate CIDR notation
    try:
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        if network.prefixlen < 8 or network.prefixlen > 30:
            errors.append("Prefix length should be between /8 and /30")
        if network.is_private is False:
            errors.append("Warning: Using public IP range for internal network")
    except ValueError as e:
        errors.append(f"Invalid CIDR notation: {e}. Use format: 192.168.1.0/24")

    # Validate device type
    if device_type not in ['router', 'switch']:
        errors.append("Device type must be either 'router' or 'switch'")

    # Validate hostname
    if not device_name.strip():
        errors.append("Device hostname cannot be empty")
    elif len(device_name) > 63:
        errors.append("Hostname too long (max 63 characters)")
    elif ' ' in device_name:
        errors.append("Hostname cannot contain spaces")
    elif not re.match(r'^[a-zA-Z0-9\-_]+$', device_name):
        errors.append("Hostname can only contain letters, numbers, hyphens, and underscores")

    return errors


def calculate_subnet_info(network_cidr):
    """
    Calculate subnet information from CIDR notation.
    
    Args:
        network_cidr (str): CIDR notation
    
    Returns:
        dict: Dictionary with network details or None if error
    """
    try:
        # Parse the CIDR notation using ipaddress module
        network = ipaddress.IPv4Network(network_cidr, strict=False)
        
        # Get list of usable hosts
        hosts = list(network.hosts())
        
        # Calculate all the subnet information
        subnet_info = {
            'network_address': str(network.network_address),
            'broadcast_address': str(network.broadcast_address),
            'subnet_mask': str(network.netmask),
            'wildcard_mask': str(network.hostmask),
            'prefix_length': network.prefixlen,
            'total_hosts': network.num_addresses,
            'usable_hosts': network.num_addresses - 2,  # Subtract network and broadcast
            'first_usable_host': str(hosts[0]) if hosts else "N/A",
            'last_usable_host': str(hosts[-1]) if hosts else "N/A",
            'ip_network': network  # Keep the network object for further calculations
        }
        return subnet_info
    except ValueError as e:
        print(f"Error: Invalid CIDR notation - {e}")
        return None


def generate_router_config(device_name, subnet_info):
    """
    Generate router configuration with multiple interfaces
    
    Args:
        device_name (str): Router hostname
        subnet_info (dict): Subnet information
    
    Returns:
        str: Router configuration
    """
    config = []
    
    config.append(f"! Router Configuration for {device_name}")
    config.append(f"hostname {device_name}")
    config.append("!")
    
    # Basic Security
    config.append("! Basic Security Configuration")
    config.append("no ip http-server")
    config.append("no ip http secure-server")
    config.append("service password-encryption")
    config.append("banner motd # Unauthorized Access is Prohibited #")
    config.append("!")
    
    # WAN Interface (simulated with DHCP from ISP)
    config.append("! WAN Interface - Connected to Internet")
    config.append("interface GigabitEthernet0/0")
    config.append(" description WAN Link to ISP")
    config.append(" ip address dhcp")
    config.append(" negotiation auto")
    config.append(" no shutdown")
    config.append("!")
    
    # LAN Interface - Connected to internal network
    config.append("! LAN Interface - Connected to Internal Network")
    config.append("interface GigabitEthernet0/1")
    config.append(" description LAN Link to Internal Network")
    config.append(f" ip address {subnet_info['first_usable_host']} {subnet_info['subnet_mask']}")
    config.append(" duplex auto")
    config.append(" speed auto")
    config.append(" no shutdown")
    config.append("!")
    
    # DHCP Configuration for LAN
    if subnet_info['usable_hosts'] > 10:
        config.append("! DHCP Configuration for LAN")
        dhcp_pool_name = "LAN_POOL"
        config.append(f"ip dhcp pool {dhcp_pool_name}")
        config.append(f" network {subnet_info['network_address']} {subnet_info['subnet_mask']}")
        config.append(f" default-router {subnet_info['first_usable_host']}")
        config.append(" dns-server 8.8.8.8 8.8.4.4")
        config.append(" domain-name local")
        config.append(" lease 7")
        config.append("!")
        
        # Exclude first 10 IPs for static devices
        network = subnet_info['ip_network']
        hosts = list(network.hosts())
        if len(hosts) > 10:
            exclude_start = hosts[0]  # First usable (router)
            exclude_end = hosts[9]    # Tenth usable
            config.append(f"ip dhcp excluded-address {exclude_start} {exclude_end}")
            config.append("!")
    
    # Basic NAT for internet access
    config.append("! NAT Configuration for Internet Access")
    config.append("ip nat inside source list NAT interface GigabitEthernet0/0 overload")
    config.append("access-list 1 permit 192.168.0.0 0.0.255.255")  # Standard private ranges
    config.append("access-list 1 permit 10.0.0.0 0.255.255.255")
    config.append("access-list 1 permit 172.16.0.0 0.15.255.255")
    config.append("!")
    config.append("interface GigabitEthernet0/1")
    config.append(" ip nat inside")
    config.append("!")
    config.append("interface GigabitEthernet0/0")
    config.append(" ip nat outside")
    config.append("!")
    
    # Basic routing (if needed)
    config.append("! Default route to ISP")
    config.append("ip route 0.0.0.0 0.0.0.0 GigabitEthernet0/0")
    config.append("!")
    
    # Save configuration
    config.append("! Save configuration")
    config.append("end")
    config.append("write memory")
    
    return "\n".join(config)


def generate_switch_config(device_name, subnet_info):
    """
    Generate switch configuration
    
    Args:
        device_name (str): Switch hostname
        subnet_info (dict): Subnet information
    
    Returns:
        str: Switch configuration
    """
    config = []
    
    config.append(f"! Switch Configuration for {device_name}")
    config.append(f"hostname {device_name}")
    config.append("!")
    
    # Basic Security
    config.append("! Basic Security Configuration")
    config.append("no ip http-server")
    config.append("no ip http secure-server")
    config.append("service password-encryption")
    config.append("banner motd # Unauthorized Access is Prohibited #")
    config.append("!")
    
    # Management interface - switch gets the second usable IP
    network = subnet_info['ip_network']
    hosts = list(network.hosts())
    switch_ip = str(hosts[1]) if len(hosts) > 1 else str(hosts[0])  # Second IP after router
    
    config.append("! Management Interface Configuration")
    config.append("interface Vlan1")
    config.append(" description Management Interface")
    config.append(f" ip address {switch_ip} {subnet_info['subnet_mask']}")
    config.append(" no shutdown")
    config.append("!")
    
    # Default gateway (usually the router)
    config.append(f"ip default-gateway {subnet_info['first_usable_host']}")
    config.append("!")
    
    # Basic switch port configuration
    config.append("! Switch Port Configuration")
    config.append("interface range FastEthernet0/1-24")
    config.append(" switchport mode access")
    config.append(" switchport access vlan 1")
    config.append(" spanning-tree portfast")
    config.append(" no shutdown")
    config.append("!")
    
    # Save configuration
    config.append("! Save configuration")
    config.append("end")
    config.append("write memory")
    
    return "\n".join(config)


def display_configuration_summary(device_type, device_name, subnet_info):
    """Display a summary of the generated configuration"""
    print("\n" + "=" * 60)
    print("CONFIGURATION SUMMARY")
    print("=" * 60)
    print(f"Device Type: {device_type.upper()}")
    print(f"Device Name: {device_name}")
    print(f"Network: {subnet_info['network_address']}/{subnet_info['prefix_length']}")
    print(f"Subnet Mask: {subnet_info['subnet_mask']}")
    print(f"Usable IP Range: {subnet_info['first_usable_host']} - {subnet_info['last_usable_host']}")
    
    if device_type == "router":
        print(f"Router IP: {subnet_info['first_usable_host']}")
        print(f"Switch/DHCP Range: {subnet_info['first_usable_host']} + 1 onwards")
    elif device_type == "switch":
        network = subnet_info['ip_network']
        hosts = list(network.hosts())
        switch_ip = str(hosts[1]) if len(hosts) > 1 else str(hosts[0])
        print(f"Switch IP: {switch_ip}")
        print(f"Default Gateway: {subnet_info['first_usable_host']}")
    print("=" * 60)


def main():
    """Main function to run the network configuration generator"""
    display_welcome_banner()
    
    # Get user input
    print("Please provide the following information:")
    network_cidr = input("Enter network IP in CIDR notation (e.g., 192.168.1.0/24): ").strip()
    device_type = input("Enter device type (router/switch): ").lower().strip()
    device_name = input("Enter device hostname: ").strip()
    
    # Validate inputs
    validation_errors = validate_input(network_cidr, device_type, device_name)
    
    if validation_errors:
        print("\n❌ Input Errors:")
        for error in validation_errors:
            print(f"   - {error}")
        print("\nPlease correct the errors and try again.")
        return
    
    print(f"\n✅ Generating configuration for {device_name} ({device_type})...")
    
    # Calculate subnet information
    subnet_info = calculate_subnet_info(network_cidr)
    
    if not subnet_info:
        print("❌ Failed to calculate subnet information.")
        return
    
    # Display network information
    print("\n📊 NETWORK DESIGN")
    print("-" * 40)
    print(f"Network Address:    {subnet_info['network_address']}")
    print(f"CIDR Notation:      /{subnet_info['prefix_length']}")
    print(f"Subnet Mask:        {subnet_info['subnet_mask']}")
    print(f"Wildcard Mask:      {subnet_info['wildcard_mask']}")
    print(f"Broadcast Address:  {subnet_info['broadcast_address']}")
    print(f"Total IPs:          {subnet_info['total_hosts']}")
    print(f"Usable Hosts:       {subnet_info['usable_hosts']}")
    print(f"First Usable IP:    {subnet_info['first_usable_host']}")
    print(f"Last Usable IP:     {subnet_info['last_usable_host']}")
    
    # Generate device configuration based on type
    if device_type == "router":
        config = generate_router_config(device_name, subnet_info)
        filename = f"{device_name}_router_config.txt"
    elif device_type == "switch":
        config = generate_switch_config(device_name, subnet_info)
        filename = f"{device_name}_switch_config.txt"
    else:
        print("❌ Error: Unknown device type")
        return
    
    # Save configuration to file
    try:
        with open(filename, 'w') as f:
            f.write(config)
        
        # Display summary and results
        display_configuration_summary(device_type, device_name, subnet_info)
        
        print(f"\n✅ Configuration generated successfully!")
        print(f"📁 Configuration saved to: {filename}")
        
        # Option to display configuration
        show_config = input("\nWould you like to view the configuration? (y/n): ").lower()
        if show_config in ['y', 'yes']:
            print("\n" + "=" * 60)
            print("GENERATED CONFIGURATION")
            print("=" * 60)
            print(config)
            
    except IOError as e:
        print(f"❌ Error saving configuration file: {e}")


if __name__ == "__main__":
    main()