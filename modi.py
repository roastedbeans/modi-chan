#!/usr/bin/env python3
"""
Quectel RM520N-GL Network Data Extractor for ML-based IDS
Extracts RRC states, NAS layer data, and signal metrics for security analysis
"""

import serial
import time
import re
import csv
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
import argparse
import os
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@dataclass
class NetworkData:
    """Comprehensive network data structure for ML IDS"""
    # Timestamp
    timestamp: str = ""
    
    # RRC Layer Data
    rrc_state: str = ""  # IDLE, CONNECTED, INACTIVE
    cell_type: str = ""  # serving/neighbor
    technology: str = ""  # LTE, NR5G-SA, NR5G-NSA, WCDMA
    
    # Cell Identity
    mcc: str = ""
    mnc: str = ""
    cell_id: str = ""
    pci: str = ""
    tac_lac: str = ""
    
    # Radio Parameters
    earfcn_arfcn: str = ""
    band: str = ""
    bandwidth: str = ""
    scs: str = ""  # Sub-Carrier Spacing (5G parameter)
    
    # Signal Metrics
    rsrp: str = ""
    rsrq: str = ""
    rssi: str = ""
    sinr: str = ""
    cqi: str = ""
    tx_power: str = ""
    
    # NAS Layer Data
    cs_state: str = ""  # Circuit Switched registration
    cs_lac: str = ""
    cs_ci: str = ""
    ps_state: str = ""  # Packet Switched registration  
    ps_lac: str = ""
    ps_ci: str = ""
    eps_state: str = ""  # EPS registration
    eps_tac: str = ""
    eps_ci: str = ""
    nr5g_state: str = ""  # 5G registration
    nr5g_tac: str = ""
    nr5g_ci: str = ""
    
    # Authentication/Security
    sim_state: str = ""  # READY, SIM PIN, etc
    operator: str = ""
    operator_mcc_mnc: str = ""
    attach_state: str = ""
    
    # Neighbor Cell Info
    neighbor_count: int = 0
    best_neighbor_rsrp: str = ""
    neighbor_cells_json: str = ""  # JSON string of neighbor cells
    
    # Additional Metrics
    csq_rssi: str = ""
    csq_ber: str = ""
    serving_cell_count: int = 0
    ca_info: str = ""  # Carrier aggregation info

class ATCommandInterface:
    """Handles AT command communication with the modem"""
    
    def __init__(self, port: str, baudrate: int = 115200, timeout: int = 5):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.serial_conn = None
        
    def connect(self) -> bool:
        """Establish serial connection"""
        try:
            self.serial_conn = serial.Serial(
                port=self.port,
                baudrate=self.baudrate,
                timeout=self.timeout,
                parity=serial.PARITY_NONE,
                stopbits=serial.STOPBITS_ONE,
                bytesize=serial.EIGHTBITS
            )
            logger.info(f"Connected to {self.port} at {self.baudrate} baud")
            
            # Test connection
            response = self.send_command("AT")
            if self._check_ok(response):
                logger.info("Modem communication verified")
                return True
            else:
                logger.error("Modem not responding to AT commands")
                return False
                
        except Exception as e:
            logger.error(f"Failed to connect: {e}")
            return False
    
    def disconnect(self):
        """Close serial connection"""
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()
            logger.info("Disconnected from modem")
    
    def send_command(self, command: str, timeout: Optional[int] = None) -> List[str]:
        """Send AT command and return response lines"""
        if not self.serial_conn or not self.serial_conn.is_open:
            logger.error("Serial connection not established")
            return []
        
        timeout = timeout or self.timeout
        
        try:
            # Clear buffers
            self.serial_conn.reset_input_buffer()
            self.serial_conn.reset_output_buffer()
            
            # Send command
            cmd = f"{command}\r\n"
            self.serial_conn.write(cmd.encode())
            logger.debug(f"Sent: {command}")
            
            # Read response
            response_lines = []
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                if self.serial_conn.in_waiting > 0:
                    line = self.serial_conn.readline().decode('utf-8', errors='ignore').strip()
                    if line:
                        response_lines.append(line)
                        if line in ['OK', 'ERROR'] or line.startswith('+CME ERROR'):
                            break
                time.sleep(0.05)
            
            logger.debug(f"Response: {response_lines}")
            return response_lines
            
        except Exception as e:
            logger.error(f"Error sending command {command}: {e}")
            return []
    
    def _check_ok(self, response: List[str]) -> bool:
        """Check if response contains OK"""
        return any('OK' in line for line in response)

class NetworkDataExtractor:
    """Extracts network data from AT command responses"""
    
    def __init__(self, at_interface: ATCommandInterface):
        self.at = at_interface
        
    def extract_all_data(self) -> NetworkData:
        """Extract comprehensive network data"""
        data = NetworkData()
        data.timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        
        # Extract serving cell info (includes RRC state)
        self._extract_serving_cell(data)
        
        # Extract NAS registration states
        self._extract_nas_states(data)
        
        # Extract authentication/security info
        self._extract_auth_info(data)
        
        # Extract neighbor cells
        self._extract_neighbor_cells(data)
        
        # Extract additional signal metrics
        self._extract_signal_metrics(data)
        
        return data
    
    def _extract_serving_cell(self, data: NetworkData):
        """Extract serving cell and RRC information"""
        lines = self.at.send_command('AT+QENG="servingcell"')
        
        for line in lines:
            if line.startswith('+QENG: "servingcell"'):
                parts = line.split(',')
                if len(parts) >= 3:
                    # Common fields
                    data.rrc_state = parts[1].strip('"')
                    data.technology = parts[2].strip('"')
                    data.cell_type = "serving"
                    
                    # Technology-specific parsing
                    if "LTE" in data.technology:
                        self._parse_lte_serving(parts, data)
                    elif "NR5G-SA" in data.technology:
                        self._parse_nr5g_sa_serving(parts, data)
                    elif "NR5G-NSA" in data.technology:
                        self._parse_nr5g_nsa_serving(parts, data)
                    elif "WCDMA" in data.technology:
                        self._parse_wcdma_serving(parts, data)
                        
            elif line.startswith('+QENG: "LTE"') or line.startswith('+QENG: "NR5G-NSA"'):
                # EN-DC mode additional cells
                data.serving_cell_count += 1
                
    def _parse_lte_serving(self, parts: List[str], data: NetworkData):
        """Parse LTE serving cell data"""
        try:
            if len(parts) >= 18:
                idx_offset = 1 if parts[0].startswith('+QENG: "LTE"') else 0
                data.mcc = parts[3 + idx_offset].strip('"')
                data.mnc = parts[4 + idx_offset].strip('"')
                data.cell_id = parts[5 + idx_offset].strip('"')
                data.pci = parts[6 + idx_offset].strip('"')
                data.earfcn_arfcn = parts[7 + idx_offset].strip('"')
                data.band = parts[8 + idx_offset].strip('"')
                data.bandwidth = parts[9 + idx_offset].strip('"') if len(parts) > 9 + idx_offset else ""
                data.tac_lac = parts[11 + idx_offset].strip('"')
                data.rsrp = parts[12 + idx_offset].strip('"')
                data.rsrq = parts[13 + idx_offset].strip('"')
                data.rssi = parts[14 + idx_offset].strip('"')
                data.sinr = parts[15 + idx_offset].strip('"')
                data.cqi = parts[16 + idx_offset].strip('"') if len(parts) > 16 + idx_offset else ""
                data.tx_power = parts[17 + idx_offset].strip('"') if len(parts) > 17 + idx_offset else ""
        except (IndexError, ValueError) as e:
            logger.warning(f"Error parsing LTE serving cell: {e}")
    
    def _parse_nr5g_sa_serving(self, parts: List[str], data: NetworkData):
        """Parse NR5G-SA serving cell data"""
        try:
            if len(parts) >= 17:
                data.mcc = parts[4].strip('"')
                data.mnc = parts[5].strip('"')
                data.cell_id = parts[6].strip('"')
                data.pci = parts[7].strip('"')
                data.tac_lac = parts[8].strip('"')
                data.earfcn_arfcn = parts[9].strip('"')
                data.band = parts[10].strip('"')
                data.bandwidth = parts[11].strip('"') if len(parts) > 11 else ""
                data.rsrp = parts[12].strip('"')
                data.rsrq = parts[13].strip('"')
                data.sinr = parts[14].strip('"')
                data.rssi = parts[15].strip('"') if len(parts) > 15 else ""
                data.tx_power = parts[16].strip('"') if len(parts) > 16 else ""
        except (IndexError, ValueError) as e:
            logger.warning(f"Error parsing NR5G-SA serving cell: {e}")
    
    def _parse_nr5g_nsa_serving(self, parts: List[str], data: NetworkData):
        """Parse NR5G-NSA serving cell data"""
        try:
            if len(parts) >= 11:
                data.mcc = parts[1].strip('"')
                data.mnc = parts[2].strip('"')
                data.pci = parts[3].strip('"')
                data.rsrp = parts[4].strip('"')
                data.sinr = parts[5].strip('"')
                data.rsrq = parts[6].strip('"')
                data.earfcn_arfcn = parts[7].strip('"')
                data.band = parts[8].strip('"')
                data.bandwidth = parts[9].strip('"') if len(parts) > 9 else ""
                data.scs = parts[10].strip('"') if len(parts) > 10 else ""
        except (IndexError, ValueError) as e:
            logger.warning(f"Error parsing NR5G-NSA serving cell: {e}")
    
    def _parse_wcdma_serving(self, parts: List[str], data: NetworkData):
        """Parse WCDMA serving cell data"""
        try:
            if len(parts) >= 17:
                data.mcc = parts[4].strip('"')
                data.mnc = parts[5].strip('"')
                data.tac_lac = parts[6].strip('"')
                data.cell_id = parts[7].strip('"')
                data.earfcn_arfcn = parts[8].strip('"')
                data.pci = parts[9].strip('"')  # PSC for WCDMA
                data.rsrp = parts[11].strip('"')  # RSCP for WCDMA
                data.rsrq = parts[12].strip('"')  # ECIO for WCDMA
        except (IndexError, ValueError) as e:
            logger.warning(f"Error parsing WCDMA serving cell: {e}")
    
    def _extract_nas_states(self, data: NetworkData):
        """Extract NAS registration states"""
        # Circuit Switched registration
        lines = self.at.send_command("AT+CREG?")
        for line in lines:
            if line.startswith('+CREG:'):
                parts = line.split(',')
                if len(parts) >= 2:
                    data.cs_state = self._decode_reg_state(parts[1].strip())
                    if len(parts) >= 4:
                        data.cs_lac = parts[2].strip('"')
                        data.cs_ci = parts[3].strip('"')
        
        # Packet Switched registration (GPRS)
        lines = self.at.send_command("AT+CGREG?")
        for line in lines:
            if line.startswith('+CGREG:'):
                parts = line.split(',')
                if len(parts) >= 2:
                    data.ps_state = self._decode_reg_state(parts[1].strip())
                    if len(parts) >= 4:
                        data.ps_lac = parts[2].strip('"')
                        data.ps_ci = parts[3].strip('"')
        
        # EPS registration (LTE)
        lines = self.at.send_command("AT+CEREG?")
        for line in lines:
            if line.startswith('+CEREG:'):
                parts = line.split(',')
                if len(parts) >= 2:
                    data.eps_state = self._decode_reg_state(parts[1].strip())
                    if len(parts) >= 4:
                        data.eps_tac = parts[2].strip('"')
                        data.eps_ci = parts[3].strip('"')
        
        # 5G registration
        lines = self.at.send_command("AT+C5GREG?")
        for line in lines:
            if line.startswith('+C5GREG:'):
                parts = line.split(',')
                if len(parts) >= 2:
                    data.nr5g_state = self._decode_reg_state(parts[1].strip())
                    if len(parts) >= 4:
                        data.nr5g_tac = parts[2].strip('"')
                        data.nr5g_ci = parts[3].strip('"')
    
    def _decode_reg_state(self, state: str) -> str:
        """Decode registration state"""
        states = {
            '0': 'NOT_REGISTERED',
            '1': 'REGISTERED_HOME',
            '2': 'SEARCHING',
            '3': 'DENIED',
            '4': 'UNKNOWN',
            '5': 'REGISTERED_ROAMING',
            '6': 'REGISTERED_SMS_ONLY_HOME',
            '7': 'REGISTERED_SMS_ONLY_ROAMING',
            '8': 'EMERGENCY_ONLY',
            '9': 'REGISTERED_CSFB_NOT_PREFERRED_HOME',
            '10': 'REGISTERED_CSFB_NOT_PREFERRED_ROAMING'
        }
        return states.get(state, f'UNKNOWN_{state}')
    
    def _extract_auth_info(self, data: NetworkData):
        """Extract authentication and security information"""
        # SIM state
        lines = self.at.send_command("AT+CPIN?")
        for line in lines:
            if line.startswith('+CPIN:'):
                data.sim_state = line.split(':', 1)[1].strip()
        
        # Operator info
        lines = self.at.send_command("AT+COPS?")
        for line in lines:
            if line.startswith('+COPS:'):
                parts = line.split(',')
                if len(parts) >= 3:
                    data.operator = parts[2].strip('"')
                    if len(parts) >= 4:
                        data.operator_mcc_mnc = parts[3].strip('"')
        
        # Attach state
        lines = self.at.send_command("AT+CGATT?")
        for line in lines:
            if line.startswith('+CGATT:'):
                state = line.split(':', 1)[1].strip()
                data.attach_state = "ATTACHED" if state == '1' else "DETACHED"
    
    def _extract_neighbor_cells(self, data: NetworkData):
        """Extract neighbor cell information"""
        lines = self.at.send_command('AT+QENG="neighbourcell"')
        neighbor_cells = []
        
        for line in lines:
            if '+QENG: "neighbourcell' in line:
                parts = line.split(',')
                cell_info = {}
                
                if 'LTE' in line:
                    try:
                        cell_info = {
                            'tech': 'LTE',
                            'earfcn': parts[2].strip('"'),
                            'pci': parts[3].strip('"'),
                            'rsrq': parts[4].strip('"'),
                            'rsrp': parts[5].strip('"'),
                            'rssi': parts[6].strip('"'),
                            'sinr': parts[7].strip('"'),
                            'srxlev': parts[8].strip('"') if len(parts) > 8 else ""
                        }
                    except (IndexError, ValueError):
                        pass
                elif 'WCDMA' in line:
                    try:
                        cell_info = {
                            'tech': 'WCDMA',
                            'uarfcn': parts[2].strip('"'),
                            'psc': parts[5].strip('"'),
                            'rscp': parts[6].strip('"'),
                            'ecio': parts[7].strip('"'),
                            'srxlev': parts[8].strip('"') if len(parts) > 8 else ""
                        }
                    except (IndexError, ValueError):
                        pass
                elif '5G' in line:
                    try:
                        cell_info = {
                            'tech': '5G',
                            'arfcn': parts[2].strip('"'),
                            'pci': parts[3].strip('"'),
                            'rsrp': parts[4].strip('"'),
                            'rsrq': parts[5].strip('"'),
                            'sinr': parts[6].strip('"') if len(parts) > 6 else ""
                        }
                    except (IndexError, ValueError):
                        pass
                
                if cell_info:
                    neighbor_cells.append(cell_info)
        
        data.neighbor_count = len(neighbor_cells)
        
        # Find best neighbor RSRP
        if neighbor_cells:
            rsrp_values = []
            for cell in neighbor_cells:
                rsrp = cell.get('rsrp', cell.get('rscp', ''))
                if rsrp and rsrp != 'N/A':
                    try:
                        rsrp_values.append(int(rsrp))
                    except ValueError:
                        pass
            
            if rsrp_values:
                data.best_neighbor_rsrp = str(max(rsrp_values))
        
        # Store neighbor cells as JSON
        data.neighbor_cells_json = json.dumps(neighbor_cells) if neighbor_cells else ""
    
    def _extract_signal_metrics(self, data: NetworkData):
        """Extract additional signal metrics"""
        # CSQ
        lines = self.at.send_command("AT+CSQ")
        for line in lines:
            if line.startswith('+CSQ:'):
                parts = line.split(':', 1)[1].strip().split(',')
                if len(parts) >= 2:
                    data.csq_rssi = parts[0].strip()
                    data.csq_ber = parts[1].strip()
        
        # Carrier aggregation info
        lines = self.at.send_command("AT+QCAINFO")
        ca_info = []
        for line in lines:
            if line.startswith('+QCAINFO:'):
                ca_info.append(line.split(':', 1)[1].strip())
        data.ca_info = '; '.join(ca_info) if ca_info else ""

class DataLogger:
    """Handles CSV logging of network data"""
    
    def __init__(self, output_dir: str = "network_data"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Create filename with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.filename = self.output_dir / f"rm520n_network_data_{timestamp}.csv"
        
        self.csv_file = None
        self.csv_writer = None
        self.is_initialized = False
        
    def initialize(self):
        """Initialize CSV file with headers"""
        try:
            self.csv_file = open(self.filename, 'w', newline='', encoding='utf-8')
            
            # Get field names from NetworkData
            fieldnames = [field.name for field in NetworkData.__dataclass_fields__.values()]
            
            self.csv_writer = csv.DictWriter(self.csv_file, fieldnames=fieldnames)
            self.csv_writer.writeheader()
            self.csv_file.flush()
            
            self.is_initialized = True
            logger.info(f"Logging to: {self.filename}")
            
        except Exception as e:
            logger.error(f"Failed to initialize CSV logger: {e}")
            self.is_initialized = False
    
    def log_data(self, data: NetworkData):
        """Log network data to CSV"""
        if not self.is_initialized:
            self.initialize()
        
        if self.is_initialized and self.csv_writer and self.csv_file:
            try:
                # Convert dataclass to dict
                data_dict = asdict(data)
                
                # Write row
                self.csv_writer.writerow(data_dict)
                self.csv_file.flush()
                
                logger.debug("Data logged to CSV")
                
            except Exception as e:
                logger.error(f"Failed to log data: {e}")
    
    def close(self):
        """Close CSV file"""
        if self.csv_file:
            self.csv_file.close()
            logger.info("CSV logger closed")

class NetworkMonitor:
    """Main monitoring application"""
    
    def __init__(self, port: str, output_dir: str = "network_data", 
                 interval: int = 5, baudrate: int = 115200):
        self.port = port
        self.interval = interval
        self.baudrate = baudrate
        
        # Initialize components
        self.at_interface = ATCommandInterface(port, baudrate)
        self.extractor = NetworkDataExtractor(self.at_interface)
        self.logger = DataLogger(output_dir)
        
        self.running = False
        
    def start(self):
        """Start monitoring"""
        # Connect to modem
        if not self.at_interface.connect():
            logger.error("Failed to connect to modem")
            return False
        
        # Initialize logger
        self.logger.initialize()
        
        # Enable URCs for real-time updates (optional)
        self._configure_modem()
        
        self.running = True
        logger.info(f"Starting network monitoring (interval: {self.interval}s)")
        
        try:
            while self.running:
                # Extract data
                data = self.extractor.extract_all_data()
                
                # Log to CSV
                self.logger.log_data(data)
                
                # Display summary
                self._display_summary(data)
                
                # Wait for next interval
                time.sleep(self.interval)
                
        except KeyboardInterrupt:
            logger.info("Monitoring stopped by user")
        except Exception as e:
            logger.error(f"Monitoring error: {e}")
        finally:
            self.stop()
        
        return True
    
    def stop(self):
        """Stop monitoring"""
        self.running = False
        self.logger.close()
        self.at_interface.disconnect()
        logger.info("Network monitoring stopped")
    
    def _configure_modem(self):
        """Configure modem for optimal monitoring"""
        # Enable network registration URCs
        self.at_interface.send_command("AT+CREG=2")
        self.at_interface.send_command("AT+CGREG=2")
        self.at_interface.send_command("AT+CEREG=2")
        self.at_interface.send_command("AT+C5GREG=2")
        
        # Set network info format
        self.at_interface.send_command('AT+QENG="servingcell",1')
        
        logger.info("Modem configured for monitoring")
    
    def _display_summary(self, data: NetworkData):
        """Display summary of current network state"""
        print("\n" + "="*80)
        print(f"Network Status - {data.timestamp}")
        print("="*80)
        
        # RRC/Cell Info
        print(f"\nRRC State: {data.rrc_state} | Technology: {data.technology}")
        print(f"Cell ID: {data.cell_id} | PCI: {data.pci} | Band: {data.band}")
        print(f"MCC-MNC: {data.mcc}-{data.mnc} | TAC/LAC: {data.tac_lac}")
        
        # Signal Quality
        print(f"\nSignal Quality:")
        print(f"  RSRP: {data.rsrp} dBm | RSRQ: {data.rsrq} dB | SINR: {data.sinr} dB")
        print(f"  RSSI: {data.rssi} dBm | CQI: {data.cqi}")
        
        # NAS States
        print(f"\nNAS Registration States:")
        print(f"  CS: {data.cs_state} | PS: {data.ps_state}")
        print(f"  EPS: {data.eps_state} | 5G: {data.nr5g_state}")
        
        # Security
        print(f"\nSecurity:")
        print(f"  SIM: {data.sim_state} | Attach: {data.attach_state}")
        print(f"  Operator: {data.operator} ({data.operator_mcc_mnc})")
        
        # Neighbors
        print(f"\nNeighbor Cells: {data.neighbor_count} | Best RSRP: {data.best_neighbor_rsrp}")
        
        print("="*80)

def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Quectel RM520N-GL Network Data Extractor for ML-based IDS"
    )
    parser.add_argument(
        "port", 
        help="Serial port (e.g., COM3, /dev/ttyUSB2)"
    )
    parser.add_argument(
        "-b", "--baudrate", 
        type=int, 
        default=115200,
        help="Baud rate (default: 115200)"
    )
    parser.add_argument(
        "-i", "--interval", 
        type=int, 
        default=5,
        help="Data collection interval in seconds (default: 5)"
    )
    parser.add_argument(
        "-o", "--output", 
        default="network_data",
        help="Output directory for CSV files (default: network_data)"
    )
    parser.add_argument(
        "-v", "--verbose", 
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and start monitor
    monitor = NetworkMonitor(
        port=args.port,
        output_dir=args.output,
        interval=args.interval,
        baudrate=args.baudrate
    )
    
    # Start monitoring
    success = monitor.start()
    
    return 0 if success else 1

if __name__ == "__main__":
    exit(main())