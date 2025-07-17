#!/usr/bin/env python3
"""
Test script to identify the AT command port for Quectel RM520N-GL
"""

import serial
import time
import glob

def test_at_port(port, timeout=3):
    """Test if a port responds to AT commands"""
    try:
        # Open serial connection
        ser = serial.Serial(
            port=port,
            baudrate=115200,
            timeout=timeout,
            parity=serial.PARITY_NONE,
            stopbits=serial.STOPBITS_ONE,
            bytesize=serial.EIGHTBITS
        )
        
        # Clear buffers
        ser.reset_input_buffer()
        ser.reset_output_buffer()
        
        # Send AT command
        ser.write(b'AT\r\n')
        time.sleep(0.5)
        
        # Read response
        response_bytes = ser.read_all()
        response = response_bytes.decode('utf-8', errors='ignore') if response_bytes else ""
        
        # Clean up
        ser.close()
        
        # Check if we got OK response
        if 'OK' in response:
            return True, response.strip()
        else:
            return False, response.strip()
            
    except Exception as e:
        return False, str(e)

def main():
    """Test all available ttyUSB ports"""
    # Find all ttyUSB ports
    ports = glob.glob('/dev/ttyUSB*')
    
    if not ports:
        print("No ttyUSB ports found!")
        return
    
    print("Testing AT command response on available ports:")
    print("=" * 60)
    
    at_ports = []
    
    for port in sorted(ports):
        print(f"\nTesting {port}...")
        
        success, response = test_at_port(port)
        
        if success:
            print(f"✓ {port}: AT command SUCCESSFUL")
            print(f"  Response: {response}")
            at_ports.append(port)
        else:
            print(f"✗ {port}: Failed - {response}")
    
    print("\n" + "=" * 60)
    
    if at_ports:
        print(f"AT command ports found: {at_ports}")
        if len(at_ports) == 1:
            print(f"\nRecommended AT port: {at_ports[0]}")
        else:
            print(f"\nMultiple AT ports found. Try the first one: {at_ports[0]}")
    else:
        print("No AT command ports found!")
        print("Make sure:")
        print("1. The module is properly connected")
        print("2. You have permission to access serial ports")
        print("3. The module is powered on")
        print("4. Try running with sudo if needed")

if __name__ == "__main__":
    main() 