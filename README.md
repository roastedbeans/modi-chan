# Quectel RM520N-GL Network Data Extractor

A Python-based network data extraction tool for Quectel RM520N-GL 5G module, designed for ML-based Intrusion Detection Systems (IDS). Collects comprehensive network metrics including RRC states, NAS layer data, signal metrics, and diagnostic information via AT commands.

## Features

- Real-time monitoring of cellular network parameters
- Comprehensive data collection via AT commands:
  - RRC (Radio Resource Control) states
  - NAS (Non-Access Stratum) registration status
  - Signal metrics (RSRP, RSRQ, SINR, etc.)
  - Cell information (serving and neighbor cells)
  - Authentication and security states
  - Diagnostic metrics (temperature, power status)
- Multi-RAT support (5G NR SA/NSA, LTE, WCDMA)
- CSV logging with timestamps
- Configurable monitoring intervals
- Detailed console output
- Single port operation for simplicity

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
cd modi-extractor
```

2. Create and activate virtual environment:
```bash
# Windows
python -m venv venv
venv\Scripts\activate

# Linux/MacOS
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Finding Your COM Port

### Windows
1. Open Device Manager (Win + X → Device Manager)
2. Look under "Ports (COM & LPT)"
3. Find "Quectel USB AT Port (COMx)" - note the COM number

### Linux
```bash
# List all serial ports
ls /dev/tty*

# Find Quectel ports specifically
ls -l /dev/tty* | grep -i "Quectel"

# Detailed USB device info
lsusb | grep -i "Quectel"
dmesg | grep -i "Quectel"

# Monitor device connections
sudo dmesg -w
```

### macOS
```bash
# List all serial ports
ls /dev/cu.* | grep -i "Quectel"
ls /dev/tty.* | grep -i "Quectel"
```

Note: The Quectel RM520N-GL module typically appears as "Quectel USB AT Port". This single port provides access to all network and diagnostic information via AT commands.

## Usage

### Basic Usage
```bash
python modi.py COM3  # Windows

python modi.py /dev/ttyUSB0  # Linux ($ls /dev/ttyUSB* - AT Port usually at ttyUSB0 or ttyUSB1)
```

### Advanced Options
```bash
# Custom baud rate
python modi.py COM3 -b 115200

# Custom update interval (seconds)
python modi.py COM3 -i 10

# Custom output directory
python modi.py COM3 -o /path/to/output

# Enable verbose logging
python modi.py COM3 -v
```

## Data Collection

### Network Parameters
- RRC state and connection type
- Cell identity (MCC, MNC, Cell ID, PCI)
- Radio parameters (EARFCN/ARFCN, Band, Bandwidth)
- Signal metrics (RSRP, RSRQ, RSSI, SINR, CQI)
- NAS registration states (CS, PS, EPS, 5G)
- Authentication/Security info
- Neighbor cell information

### Diagnostic Parameters
- Temperature sensors (modem, PA, SIM, board, RF)
- Power management status
- Battery voltage information
- Signal quality metrics

### Output Format
- CSV files with timestamps
- Real-time console display
- Comprehensive logging

## Hardware Setup

1. Connect RM520N-GL module via USB
2. Install appropriate USB-to-Serial drivers
3. Identify the AT port in device manager
4. Ensure proper SIM card installation and network coverage

## Troubleshooting

### Common Issues
- **Port Access Error**: Verify port name and permissions
- **No Response**: Check physical connections and drivers
- **Data Errors**: Verify SIM card and network coverage
- **CSV Write Error**: Check output directory permissions

### Port Names
- Windows: `COM1`, `COM2`, etc.
- Linux: `/dev/ttyUSB0`, `/dev/ttyACM0`, etc.
- MacOS: `/dev/cu.usbserial-*`

## Signal Quality Reference

- RSRP (Reference Signal Received Power)
  - Excellent: > -80 dBm
  - Good: -80 to -90 dBm
  - Fair: -90 to -100 dBm
  - Poor: < -100 dBm

- SINR (Signal to Interference plus Noise Ratio)
  - Excellent: > 20 dB
  - Good: 13 to 20 dB
  - Fair: 0 to 13 dB
  - Poor: < 0 dB

## AT Commands Used

The tool uses standard AT commands for comprehensive data collection:
- `AT+QENG="servingcell"` - Network and signal information
- `AT+QENG="neighbourcell"` - Neighbor cell data  
- `AT+QTEMP` - Temperature monitoring
- `AT+CREG?`, `AT+CEREG?`, `AT+C5GREG?` - Registration states
- `AT+CPIN?`, `AT+COPS?` - Authentication info
- `AT+CSQ`, `AT+QCAINFO` - Signal quality and carrier aggregation

## License

This project is provided as-is for educational and development purposes.