# Net-Ceptor Toolkit 🛡️

Advanced Network Reconnaissance & Security Analysis Tool

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.8%2B-green)
![License](https://img.shields.io/badge/license-MIT-orange)

## 🔒 Overview

Net-Ceptor Toolkit is a powerful network analysis and security assessment tool designed for ethical network reconnaissance and monitoring. It provides advanced capabilities for network device discovery, traffic analysis, and security testing.

### ⚡ Key Features

- **Network Discovery**: Scan and identify all devices on your network
- **Traffic Monitoring**: Real-time analysis of network traffic with GUI interface
- **Device Interaction**: Interact with network devices using various protocols
- **Location Analysis**: Geolocation tracking and mapping of network devices
- **Security Testing**: Basic security assessment and vulnerability scanning
- **Cross-Platform**: Supports both Linux and Windows environments

## 🛡️ Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Administrator/root privileges for network operations

### Linux Installation

1. **Install system dependencies**:
   ```bash
   # Ubuntu/Debian
   sudo apt-get update
   sudo apt-get install python3-dev python3-pip python3-tk libpcap-dev nmap
   
   # Fedora
   sudo dnf install python3-devel python3-pip python3-tkinter libpcap-devel nmap
   
   # Arch Linux
   sudo pacman -S python-pip python-tkinter libpcap nmap
   ```

2. **Clone the repository**:
   ```bash
   git clone https://github.com/iksoft/net-ceptor.git
   cd net-ceptor
   ```

3. **Create virtual environment (recommended)**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Windows Installation

1. **Install Python**:
   - Download Python 3.8+ from [python.org](https://www.python.org/downloads/)
   - During installation, check "Add Python to PATH"
   - Check "Install pip" during installation

2. **Install Npcap**:
   - Download and install [Npcap](https://npcap.com/#download)
   - During installation, check "Install Npcap in WinPcap API-compatible Mode"

3. **Install Nmap**:
   - Download and install [Nmap](https://nmap.org/download.html)
   - Add Nmap to system PATH

4. **Clone or download the repository**:
   - Download ZIP from GitHub or use Git:
     ```cmd
     git clone https://github.com/iksoft/net-ceptor.git
     cd net-ceptor
     ```

5. **Create virtual environment (recommended)**:
   ```cmd
   python -m venv venv
   venv\Scripts\activate
   ```

6. **Install Python dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```
```cmd
   pip install scapy>=2.5.0 python-nmap>=0.7.1 netifaces>=0.11.0 requests>=2.28.2 paramiko>=3.3.1 dnspython>=2.4.2 getmac>=0.9.4 rich>=13.6.0 pillow>=10.0.0 python-dotenv>=1.0.0 cryptography>=41.0.0 pyOpenSSL>=23.2.0 psutil>=5.9.5 ipaddress>=1.0.23 wakeonlan==3.0.0
```

## 🚀 Usage

### Running the Tool

1. **Linux**:
   ```bash
   sudo python3 network_scanner.py
   ```

2. **Windows** (Run Command Prompt as Administrator):
   ```cmd
   python network_scanner.py
   ```

### Basic Operations

1. **Network Scanning**:
   - Select option 1 from main menu
   - Wait for the scan to complete
   - View list of discovered devices

2. **Device Analysis**:
   - Select a device from the list
   - Choose from available options:
     - View detailed information
     - Monitor device traffic
     - Run connection test
     - Interact with device
     - View location information

3. **Traffic Monitoring**:
   - Select "Monitor device traffic"
   - Use the GUI interface to view:
     - DNS queries
     - Network connections
     - Protocol information
     - Traffic statistics

## 🔧 Configuration

### Custom Settings

- Edit `config.py` to modify:
  - Default scan ranges
  - Timeout values
  - API endpoints
  - GUI preferences

### API Keys

Some features require API keys:
1. Geolocation services
2. MAC vendor lookup
3. Security scanning

Configure API keys in `config.py` or use environment variables.

## 🛠️ Troubleshooting

### Common Issues

1. **Permission Denied**:
   - Ensure running with admin/root privileges
   - Check firewall settings
   - Verify Npcap/WinPcap installation

2. **No Devices Found**:
   - Check network connection
   - Verify interface settings
   - Disable firewall temporarily

3. **GUI Issues**:
   - Install/update Tkinter
   - Check Python version compatibility
   - Verify display server (Linux)

### Debug Mode

Enable debug logging:
```bash
export DEBUG=1  # Linux
set DEBUG=1     # Windows
```

## 📚 Documentation

Detailed documentation available in `/docs`:
- [Installation Guide](docs/installation.md)
- [User Manual](docs/user-manual.md)
- [API Reference](docs/api-reference.md)
- [Security Guidelines](docs/security.md)

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Create Pull Request

## ⚠️ Disclaimer

This tool is for ethical network analysis and security assessment only. Users are responsible for complying with applicable laws and regulations.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🌟 Acknowledgments

- Scapy Project
- Nmap Security Scanner
- Rich Terminal Interface
- Python Community

---
Developed with ❤️ by [Iksoft Original](https://github.com/iksoft)
