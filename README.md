# Port Scanner

*Created by [Soumit Santra] - Advanced Security Tools*  
*© 2025 [Soumit Santra]. All rights reserved.*

A feature-rich network port scanner written in Python that supports multiple scanning modes and protocols.

## ⚠️ Warning

This port scanner is for educational and authorized testing purposes only:

- **Legal Compliance**: Unauthorized port scanning may be illegal in some jurisdictions
- **Permission Required**: Always obtain explicit permission before scanning any network or system
- **Professional Use**: For professional security testing, ensure you have proper authorization
- **Ethical Usage**: Do not use this tool for malicious purposes or unauthorized access
- **Liability**: The authors are not responsible for any misuse or damage caused by this tool

Recommended safety measures:
- Only scan systems you own or have permission to test
- Check local laws and regulations regarding port scanning
- Consider using in a controlled testing environment first
- Document all authorized testing activities
- Be prepared to stop scanning if requested by system owners


## Features

- Multiple scanning modes:
  - Quick scan (common ports)
  - Regular scan (ports 1-1000)
  - Intense TCP scan (all ports)
  - UDP scan
  - Combined TCP/UDP scan
  - No-ping scan
  - Custom scan with configurable parameters

- Additional capabilities:
  - OS detection
  - Service identification
  - Banner grabbing
  - Port status (open/closed/filtered)
  - Ping scanning
  - Traceroute
  - Multi-threading support
  - Progress visualization
  - Results export

## Requirements

- Python 3.6+
- Required packages (auto-installed):
  - colorama
  - tqdm
  - scapy

## Installation

1. Clone or download the repository
2. Navigate to the project directory
3. Run the script:
```bash
python port_scanner.py
```
The script will automatically install required dependencies if missing.

## Usage

1. Run the script and choose from the following scan types:
   1. Quick scan
   2. Regular scan
   3. Intense scan all TCP
   4. Intense scan with UDP
   5. Intense TCP + UDP scan
   6. Intense scan no ping
   7. Ping scan
   8. Quick trace route
   9. Slow comprehensive scan
   10. OS scan
   11. Customize scan
   12. Exit

2. Enter the target IP address or hostname when prompted

3. View results and optionally save them to a file

## Customization

The custom scan option (#11) allows you to configure:
- Port range
- Scan speed
- Protocol (TCP/UDP/both)
- Additional features (traceroute, OS detection)

## Output

Results include:
- Open ports with service names and banners
- Filtered and closed ports statistics
- OS detection results (when available)
- Scan duration and statistics

## Notes

- Some features require root/administrator privileges
- UDP scanning requires Scapy library
- Scanning without permission may be illegal
- Use responsibly and only on authorized systems

## License

This project is open source and available under the MIT License.
