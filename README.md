# Quectel RM520N-GL Network Monitor

A Python application for monitoring RRC, NAS, and signal strength information from the Quectel RM520N-GL 5G module.

## Features

- **Real-time monitoring** of network parameters
- **RRC (Radio Resource Control)** information from serving and neighbor cells
- **NAS (Non-Access Stratum)** registration status for CS, EPS, and 5GS
- **Signal strength metrics** including RSRP, RSRQ, SINR, and CSQ
- **Multi-technology support** for 5G NR (SA/NSA), LTE, and WCDMA
- **Tabular display** with automatic screen refresh
- **Flexible update intervals**

## Installation

1. Install Python 3.6 or higher
2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage
```bash
python rm520n_monitor.py COM3
```

### Advanced Options
```bash
# Specify baud rate
python rm520n_monitor.py /dev/ttyUSB0 -b 115200

# Set update interval to 10 seconds
python rm520n_monitor.py COM3 -i 10

# Run once and exit (no continuous monitoring)
python rm520n_monitor.py COM3 --once
```

### Command Line Arguments

- `port`: Serial port (e.g., `COM3` on Windows, `/dev/ttyUSB0` on Linux)
- `-b, --baudrate`: Baud rate (default: 115200)
- `-i, --interval`: Update interval in seconds (default: 5)
- `-o, --once`: Run once and exit

## Supported AT Commands

The application uses the following AT commands:

### Network Information
- `AT+QENG="servingcell"` - Primary serving cell information
- `AT+QENG="neighbourcell"` - Neighbor cell information

### Signal Measurements  
- `AT+QRSRP` - Reference Signal Received Power
- `AT+QRSRQ` - Reference Signal Received Quality
- `AT+QSINR` - Signal to Interference plus Noise Ratio
- `AT+CSQ` - Signal quality report

### NAS Registration Status
- `AT+CREG?` - Circuit Switched registration
- `AT+CEREG?` - EPS network registration  
- `AT+C5GREG?` - 5GS network registration

## Data Display

### NAS Information
- CS Registration status
- EPS Registration status  
- 5GS Registration status
- Last update timestamp

### Serving Cells
- Technology (5G NR SA/NSA, LTE, WCDMA)
- Connection state
- Network identifier (MCC-MNC)
- Cell ID and Physical Cell ID
- Frequency information (EARFCN/ARFCN)
- Band information
- Signal measurements (RSRP, RSRQ, RSSI, SINR)

### Neighbor Cells
- Available neighbor cells
- Signal strength comparison
- Cell reselection parameters

### Signal Metrics
- Detailed signal measurements
- Multi-path signal information
- Channel quality indicators

## Hardware Setup

1. Connect the RM520N-GL module via USB
2. Install appropriate drivers for your operating system
3. Identify the AT command port (usually appears as a serial port)
4. Ensure the module has a valid SIM card and network coverage

## Troubleshooting

### Connection Issues
- Verify the correct serial port name
- Check that no other applications are using the port
- Ensure proper drivers are installed
- Try different baud rates if communication fails

### No Data Display
- Check SIM card installation
- Verify network coverage in your area
- Ensure the module is properly powered
- Try different network preferences (2G/3G/4G/5G)

### Common Port Names
- **Windows**: `COM1`, `COM3`, `COM4`, etc.
- **Linux**: `/dev/ttyUSB0`, `/dev/ttyACM0`, etc.
- **macOS**: `/dev/cu.usbserial-*` or `/dev/tty.usbserial-*`

## Technical Notes

### Supported Technologies
- **5G NR Standalone (SA)**: Full 5G network
- **5G NR Non-Standalone (NSA)**: 5G with LTE anchor
- **LTE**: 4G networks including LTE-A
- **WCDMA**: 3G networks

### Signal Measurement Ranges
- **RSRP**: -140 to -44 dBm (higher is better)
- **RSRQ**: -20 to -3 dB (higher is better)  
- **SINR**: -20 to 30 dB (higher is better)
- **CSQ**: 0-31 scale (higher is better)

## License

This project is provided as-is for educational and development purposes.