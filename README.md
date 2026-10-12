# DNS Spoofer

A Python-based DNS response manipulation tool built with Scapy and NetfilterQueue for authorized cybersecurity testing in isolated lab environments.

## Features

- Intercepts queued network packets using NetfilterQueue.
- Inspects DNS packets using Scapy.
- Supports configurable target domains and redirect IP addresses.
- Allows selection of an NFQUEUE number.
- Provides command-line arguments using `argparse`.
- Handles keyboard interruption and queue errors.

## Requirements

- Linux operating system
- Python 3
- Scapy
- NetfilterQueue and its required system dependencies
- `iptables` and NFQUEUE kernel support

Install the Python dependencies:

```bash
pip install -r requirements.txt
```

## Usage

Display the available command-line options:

```bash
python3 dns_spoofer.py --help
```

Configure the target domain and IP address in an authorized, isolated lab:

```bash
sudo python3 dns_spoofer.py \
  --domain example.test \
  --spoof-ip 192.168.1.130 \
  --queue-number 0
```

The example IP address must be replaced with an appropriate address for your test environment.

## How It Works

1. Receives packets delivered to the configured NFQUEUE.
2. Parses packets using Scapy.
3. Checks DNS-related packet information against the configured target domain.
4. Modifies a matching DNS response with the configured IP address.
5. Returns the processed packet to the network stack.

## Limitations

- Designed for Linux environments with compatible NFQUEUE support.
- Requires suitable packet-filtering rules and permissions.
- DNS over HTTPS (DoH) and DNS over TLS (DoT) are not handled by this implementation.
- Complex DNS responses and additional resource records may require further handling.
- Successful packet modification does not guarantee that the client will accept the response.

## Responsible Use

This project is intended for educational purposes and authorized security testing in controlled environments.

Only test networks and devices that you own or have explicit permission to assess. Do not use this tool to redirect other users' traffic or interfere with systems without authorization.

## Disclaimer

The author assumes no responsibility for misuse or damage resulting from this software. Use it responsibly and in accordance with applicable laws.

## Author

**SENSI0X**
