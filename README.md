# UserAssist Parser

A Python script to recursively parse UserAssist registry entries from Windows NTUSER.DAT files. The script extracts user activity data including program execution counts, focus times, and last execution timestamps.

## Features

- Recursive scanning of directories for NTUSER.DAT files
- Support for both Windows 7+ and XP UserAssist formats
- UTC timestamp conversion
- Multiple output formats (CSV and JSON)
- Detailed activity information per user
- No administrator privileges required

## Prerequisites

- Python 3.6 or higher
- python-registry library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/jdmastermy/userassist-parser.git
cd userassist-parser
```

2. Install required dependency:
```bash
pip install python-registry
```

## Usage

Basic syntax:
```bash
python userassist_parser.py -i <input_path> -o <output_path> [-f {csv,json}]
```

### Command Line Arguments

| Argument | Description |
|----------|-------------|
| -i, --input | Root folder to scan for NTUSER.DAT files |
| -o, --output | Output folder for results |
| -f, --format | Output format (csv or json, default: csv) |
| -v, --version | Show program version |
| -h, --help | Show help message |

### Usage Examples

1. Basic usage with CSV output (default):
```bash
python userassist_parser.py -i "C:\Users" -o "C:\Output"
```

2. Generate JSON output:
```bash
python userassist_parser.py -i "C:\Users" -o "C:\Output" -f json
```

3. Parse a specific user's profile:
```bash
python userassist_parser.py -i "C:\Users\Username" -o "C:\Output"
```

## Output Format

The script generates either a CSV or JSON file with the following fields:

1. **Username**: Name of the user profile
2. **Name**: Decoded program/item name
3. **Last Execution**: Last execution time in UTC
4. **GUID**: UserAssist GUID identifier
5. **Count**: Number of executions
6. **Focus_time**: Total focused time in UTC format
7. **Source**: Path to source NTUSER.DAT file

### Sample CSV Output
```csv
username,name,last_execution,guid,count,focus_time,source_file
john,{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\cmd.exe,2024-03-15 14:30:22 UTC,{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA},5,2024-03-15 02:15:30 UTC,C:\Users\john\NTUSER.DAT
```

### Sample JSON Output
```json
[
    {
        "username": "john",
        "name": "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\cmd.exe",
        "last_execution": "2024-03-15 14:30:22 UTC",
        "guid": "{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}",
        "count": 5,
        "focus_time": "2024-03-15 02:15:30 UTC",
        "source_file": "C:\\Users\\john\\NTUSER.DAT"
    }
]
```

## Error Handling

The script includes comprehensive error handling for common scenarios:

- Invalid input/output paths
- Inaccessible NTUSER.DAT files
- Corrupted registry entries
- Missing UserAssist keys
- Invalid timestamp data

Error messages are displayed in the console to help diagnose issues.

## Technical Details

### Timestamp Conversion

- All timestamps are converted to UTC format (YYYY-MM-DD HH:MM:SS UTC)
- Windows FILETIME format is properly handled for both last execution and focus times
- Timestamps start from Windows epoch (1601-01-01) for last execution times
- Focus times are calculated from Unix epoch (1970-01-01)

### UserAssist Format Support

- Windows 7 and later (Version 5+):
  - 72-byte data structure
  - Includes focus time information
  - Session count at offset 4
  - Focus time at offset 12
  - Last execution time at offset 60

- Windows XP:
  - 16-byte data structure
  - Basic execution count and timestamp
  - Count at offset 4
  - Last execution time at offset 8

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

DFIR Jedi

## Version History

- 1.0.0 (2024-03-15)
    - Initial release
    - Basic parsing functionality
    - CSV and JSON output support

## Acknowledgments

- Thanks to [python-registry](https://github.com/williballenthin/python-registry) for the registry parsing library
- Inspired by various UserAssist analysis tools and research
