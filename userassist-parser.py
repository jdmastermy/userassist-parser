import argparse
import os
import codecs
import struct
from datetime import datetime, timedelta
import csv
import json
from pathlib import Path
from Registry import Registry

def create_help_text():
    """Create detailed help text for the script."""
    help_text = """
UserAssist Registry Parser v1.0
------------------------------

Description:
    This script parses UserAssist registry entries from NTUSER.DAT files. It can recursively scan 
    directories for NTUSER.DAT files and extract user activity data including program execution 
    counts, focus times, and last execution timestamps.

Features:
    - Recursive scanning of directories for NTUSER.DAT files
    - Support for both Windows 7+ and XP UserAssist formats
    - UTC timestamp conversion
    - Multiple output formats (CSV and JSON)
    - Detailed activity information per user

Required Dependencies:
    - python-registry (pip install python-registry)

Usage Examples:
    1. Basic usage with CSV output (default):
       python userassist_parser.py -i "C:\\Users" -o "C:\\Output"

    2. Generate JSON output:
       python userassist_parser.py -i "C:\\Users" -o "C:\\Output" -f json

    3. Parse a specific user's profile:
       python userassist_parser.py -i "C:\\Users\\Username" -o "C:\\Output"

    4. Show this help message:
       python userassist_parser.py -h

Output Fields:
    1. Username: Name of the user profile
    2. Name: Decoded program/item name
    3. Last Execution: Last execution time (UTC)
    4. GUID: UserAssist GUID identifier
    5. Count: Number of executions
    6. Focus_time: Total focused time (UTC)
    7. Source: Path to source NTUSER.DAT file

Note: All timestamps are in UTC format (YYYY-MM-DD HH:MM:SS)
"""
    return help_text

def rot13_decode(encoded_string):
    """Decode ROT13 encoded string."""
    return codecs.decode(encoded_string, 'rot_13')

def convert_filetime(filetime):
    """Convert Windows FILETIME to UTC datetime with specified format."""
    if filetime == 0:
        return "Never"
    try:
        filetime = struct.unpack("<Q", struct.pack("<Q", filetime))[0]
        microseconds = filetime // 10
        if microseconds == 0:
            return "Never"
        
        windows_epoch = datetime(1601, 1, 1)
        timestamp = windows_epoch + timedelta(microseconds=microseconds)
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Error converting timestamp: {e}")
        return "Invalid timestamp"

def convert_focus_time_to_utc(milliseconds):
    """Convert focus time milliseconds to UTC datetime format."""
    try:
        if milliseconds == 0:
            return "Never"
        unix_epoch = datetime(1970, 1, 1)
        delta = timedelta(milliseconds=milliseconds)
        timestamp = unix_epoch + delta
        return timestamp.strftime('%Y-%m-%d %H:%M:%S')
    except Exception as e:
        print(f"Error converting focus time: {e}")
        return "Invalid focus time"

def parse_userassist_entry(data, win7_format=True):
    """Parse UserAssist entry data."""
    if win7_format:
        try:
            if len(data) >= 72:
                count = struct.unpack("<I", data[4:8])[0]
                focus_time = struct.unpack("<I", data[12:16])[0]
                last_execution = struct.unpack("<Q", data[60:68])[0]
                
                return {
                    'count': count,
                    'focus_time': convert_focus_time_to_utc(focus_time),
                    'last_execution': convert_filetime(last_execution)
                }
        except struct.error as e:
            print(f"Error parsing Win7+ format: {e}")
            return None
    else:
        try:
            if len(data) >= 16:
                count = struct.unpack("<I", data[4:8])[0]
                last_execution = struct.unpack("<Q", data[8:16])[0]
                return {
                    'count': count,
                    'last_execution': convert_filetime(last_execution)
                }
        except struct.error as e:
            print(f"Error parsing XP format: {e}")
            return None
    return None

def find_ntuser_dat_files(root_path):
    """Recursively find all NTUSER.DAT files."""
    ntuser_files = []
    for path in Path(root_path).rglob('NTUSER.DAT'):
        ntuser_files.append(str(path))
    return ntuser_files

def parse_userassist(ntuser_path):
    """Parse UserAssist entries from NTUSER.DAT file."""
    userassist_data = []
    
    try:
        registry = Registry.Registry(ntuser_path)
        username = Path(ntuser_path).parent.name
        
        try:
            userassist_key = registry.open(r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist")
            
            for guid_key in userassist_key.subkeys():
                guid = guid_key.name()
                
                try:
                    version_value = guid_key.value("Version").value()
                    win7_format = version_value >= 5
                except Registry.RegistryValueNotFoundException:
                    win7_format = False
                
                try:
                    count_key = guid_key.subkey("Count")
                    
                    for value in count_key.values():
                        name = value.name()
                        data = value.value()
                        
                        if not data:
                            continue
                        
                        decoded_name = rot13_decode(name)
                        parsed_data = parse_userassist_entry(data, win7_format)
                        
                        if parsed_data:
                            entry = {
                                'username': username,
                                'name': decoded_name,
                                'last_execution': parsed_data['last_execution'],
                                'guid': guid,
                                'count': parsed_data['count'],
                                'focus_time': parsed_data.get('focus_time', 'N/A'),
                                'source_file': ntuser_path
                            }
                            userassist_data.append(entry)
                            
                except Registry.RegistryKeyNotFoundException:
                    continue
                    
        except Registry.RegistryKeyNotFoundException:
            print(f"UserAssist key not found in {ntuser_path}")
            return None
            
    except Exception as e:
        print(f"Error parsing UserAssist from {ntuser_path}: {str(e)}")
        return None
    
    return userassist_data

def write_csv_results(all_data, output_file):
    """Write results to CSV file."""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            if all_data:
                fieldnames = ['username', 'name', 'last_execution', 'guid', 
                            'count', 'focus_time', 'source_file']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(all_data)
        
        print(f"Successfully wrote results to {output_file}")
        return True
    except Exception as e:
        print(f"Error writing CSV output: {str(e)}")
        return False

def write_json_results(all_data, output_file):
    """Write results to JSON file."""
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(all_data, f, indent=4)
        
        print(f"Successfully wrote results to {output_file}")
        return True
    except Exception as e:
        print(f"Error writing JSON output: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description='Parse UserAssist registry entries recursively',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=create_help_text())
    
    parser.add_argument('-i', '--input', 
                        required=True, 
                        help='Root folder to scan for NTUSER.DAT files')
    
    parser.add_argument('-o', '--output', 
                        required=True, 
                        help='Output folder for results')
    
    parser.add_argument('-f', '--format', 
                        choices=['csv', 'json'], 
                        default='csv',
                        help='Output format (csv or json, default: csv)')
    
    parser.add_argument('-v', '--version', 
                        action='version',
                        version='UserAssist Parser v1.0',
                        help='Show program version')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.input):
        print(f"Error: Input path does not exist: {args.input}")
        print("Please provide a valid path to scan for NTUSER.DAT files")
        return
    
    print("Scanning for NTUSER.DAT files...")
    ntuser_files = find_ntuser_dat_files(args.input)
    if not ntuser_files:
        print(f"No NTUSER.DAT files found in {args.input}")
        print("Please verify that the input path contains user profiles")
        return
    
    print(f"Found {len(ntuser_files)} NTUSER.DAT files")
    
    all_data = []
    for ntuser_file in ntuser_files:
        print(f"Processing: {ntuser_file}")
        parsed_data = parse_userassist(ntuser_file)
        if parsed_data:
            all_data.extend(parsed_data)
    
    if all_data:
        os.makedirs(args.output, exist_ok=True)
        
        if args.format == 'json':
            output_file = os.path.join(args.output, 'userassist_parsed.json')
            success = write_json_results(all_data, output_file)
        else:
            output_file = os.path.join(args.output, 'userassist_parsed.csv')
            success = write_csv_results(all_data, output_file)
            
        if success:
            print(f"\nSummary:")
            print(f"- Total entries parsed: {len(all_data)}")
            print(f"- Output file: {output_file}")
            print(f"- Format: {args.format.upper()}")
    else:
        print("\nNo UserAssist entries found in any of the processed files")
        print("Please verify that the NTUSER.DAT files contain UserAssist entries")

if __name__ == "__main__":
    main()
