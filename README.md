# DHCP Statistics Analyzer

**Author:** Zdebska Kateryna (Login: xzdebs00)  
**Date of Creation:** 20.11.2023

## Description:

The DHCP Statistics Analyzer is a program designed to analyze DHCP traffic and provide statistics on IP address allocations within specified IP prefixes. It captures DHCP ACK packets, tracks allocated IPs, and calculates utilization percentages for defined IP prefixes.

### Features:
- Supports both offline analysis of pcap files and live capture from a network interface.
- Monitors and logs utilization exceeding 50% for each specified IP prefix.
- Utilizes ncurses for live display of IP prefix statistics.

### Extensions/Restrictions:
- It requires the installation of the `libpcap` library for pcap file processing.
- Live capture utilizes the `ncurses` library for interactive display.

## Example of Execution:

1. Analyzing a pcap file:
   ```bash
   ./dhcp-stats -r sample.pcap 192.168.1.0/24 10.0.0.0/16

2. Live capture from a network interface:
   ```bash
   ./dhcp-stats -i eth0 192.168.1.0/24 10.0.0.0/16

## Submitted Files:
- dhcp-stats.c: Main source code file containing the DHCP Statistics Analyzer implementation.
- README.md: This readme file providing information about the program.
- Makefile: Makefile for compiling the program.
- manual.pdf: PDF document containing the program manual.
- dhcp-stats.1: Man page for the DHCP Statistics Analyzer.
