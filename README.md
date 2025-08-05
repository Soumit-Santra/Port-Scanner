# 🚀 Port Scanner 

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-green)
![Security](https://img.shields.io/badge/Security-Authorized%20Testing%20Only-red)

**Created by [Soumit Santra] — Advanced Security Tools**  
© 2025 Soumit Santra. All rights reserved.

---

A powerful, multi-threaded Python port scanner with advanced scanning modes, colored output, OS detection, and more.

---

## ⚠️ Legal & Ethical Notice

> **This tool is for educational and authorized testing only!**
>
> - **Obtain explicit permission** before scanning any network or system.
> - **Unauthorized port scanning may be illegal** in your jurisdiction.
> - **The author is not responsible** for misuse or damages.

**Best Practices:**
- Only scan systems you own or have written permission to test.
- Check local laws and regulations.
- Use in a controlled environment when possible.
- Document all authorized testing.
- Stop scanning immediately if requested by system owners.

---

## ✨ Features

- **Multiple Scan Modes:**
  - Quick scan (common ports)
  - Regular scan (ports 1–1000)
  - Intense TCP scan (all ports 1–65535)
  - UDP scan (common UDP ports)
  - Combined TCP/UDP scan
  - No-ping scan
  - Custom scan (choose ports, speed, protocol, and extras)

- **Advanced Capabilities:**
  - OS detection (TCP/IP fingerprinting & TTL analysis)
  - Service identification & banner grabbing
  - Port status: open, closed, filtered
  - Ping scanning
  - Traceroute
  - Multi-threaded for speed
  - Colored output & progress bars (`colorama`, `tqdm`)
  - Export results to file
  - **Auto-installs dependencies**

---

## 🛠️ Requirements

- Python **3.6+**
- The script will auto-install if missing:
  - `colorama`
  - `tqdm`
  - `scapy`

---

## 💻 Installation

### 🪟 Windows

1. Clone or download the repository.
2. Open a terminal and navigate to the project directory.
3. Run:
   ```bash
   python port_scanner.py
   ```
   > The script will install any missing dependencies automatically.

### 🐧 Linux

1. Clone or download the repository.
2. Open a terminal and navigate to the project directory.
3. Ensure Python 3.6+ is installed:
   ```bash
   python3 --version
   ```
4. Run:
   ```bash
   python3 port_scanner.py
   ```
   > The script will install any missing dependencies automatically.

**For best results (especially UDP/OS detection), run as root:**
```bash
sudo python3 port_scanner.py
```

---

## 🚦 Usage

1. **Run the script** and select a scan type:
    ```
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
    ```

2. **Enter the target IP address or hostname** when prompted.

3. **View results** in the terminal and optionally **save them to a file**.

---

## 🛠️ Custom Scan

The **custom scan** option lets you choose:
- Port range
- Scan speed (affects timeout)
- Protocol (TCP/UDP/both)
- Extras: traceroute, OS detection

---

## 📋 Output

- **Open ports** with service names & banners
- **Filtered/closed ports** statistics
- **OS detection** results (when available)
- **Scan duration** and statistics

---

## 📝 Notes

- Some features (UDP scan, OS detection) require **root/administrator privileges**.
- UDP scanning uses Scapy if available, otherwise falls back to basic UDP socket checks.
- The script warns if not run with elevated privileges.
- **Use responsibly and only on authorized systems.**

---

## 📄 License

This project is open-source software licensed under the **MIT license**.

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

---

## 📧 Contact

**Soumit Santra**  
For questions, suggestions, or collaboration opportunities.

---

*Remember: With great power comes great responsibility. Use this tool ethically and legally.*
