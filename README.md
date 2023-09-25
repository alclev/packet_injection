# Custom TCP Packet Generator with Comprehensive Field Modification Library

## Overview

This project provides a C program that generates customized TCP packets using raw socket programming. The program allows you to modify each field of the packet comprehensively, including the Ethernet frame. This project is intended for educational purposes only and emphasizes the importance of using technology responsibly.

## Packet Injection and Raw Socket Programming

### Packet Injection

Packet injection is a technique used to create and send custom network packets directly onto a network interface. This project leverages raw socket programming to achieve packet injection, allowing you to craft and send TCP packets tailored to your specific needs.

### Raw Socket Programming

Raw socket programming provides low-level access to network communication, enabling the creation of custom packets and manipulation of packet headers. In this project, raw sockets are used to construct and send TCP packets with complete control over every field in the packet, including Ethernet frame details.

## Usage

To use this program, follow these steps:

1. Clone the repository to your local machine:

   ```shell
   git clone https://github.com/yourusername/custom-tcp-packet-generator.git

2. Compile the C program:

    ```shell
    make 

3. Run the program with appropriate permissions (usually requires root/superuser privileges):
    ```shell
    ./inject -i <interface> -d <ip> -p <port>

## Ethics and Responsible Use

### Educational Purposes
This project is intended solely for educational purposes to help individuals learn about network communication, raw socket programming, and packet manipulation. It should not be used for malicious activities or unauthorized network intrusion.

### Responsible Use of Technology
Responsible use of technology is of utmost importance. It is crucial to adhere to legal and ethical guidelines when using tools like this packet generator. Misuse of such technology can lead to serious legal consequences and harm to network infrastructure and security.

### Disclaimer
This project and its authors are not responsible for any misuse or illegal activities conducted with this tool. Use it responsibly, respect the privacy and security of others, and comply with all applicable laws and regulations.

### Contributing
Contributions to this project are welcome. If you have suggestions, improvements, or bug fixes, please submit a pull request.


