# OpenINTEL Domain Fetcher

A Python utility for downloading, chunking, and analyzing domain data from the OpenINTEL project.

> **Note**: This project is currently under development. Features may change and the API is not yet stable.

## Overview

This tool downloads domain information from OpenINTEL datasets, processes large parquet files into smaller chunks, and provides options for converting to CSV format. It's designed for efficient handling of large datasets on systems with limited resources.

## Features

- Download zone files from OpenINTEL
- Stream large parquet files directly to manageable chunks
- Process existing parquet files into chunks
- Convert parquet files to CSV format
- Filter downloads by date, source, and more
- Memory-efficient processing through chunking
- Graceful shutdown with Ctrl+C

## Requirements

```
beautifulsoup4
python-whois
tldextract
dnspython
openpyxl
ipwhois
pyarrow
pandas
requests
```

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/todayDomains.git
   cd todayDomains
   ```

2. Install the required packages:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```
python main.py --accept-terms --date 2025-03-29
```

### Command Line Arguments

- `--accept-terms`: Required. Accept the OpenINTEL terms of service
- `--date`: Optional. Specific date to fetch (YYYY-MM-DD)
- `--sources`: Optional. Specific sources to process (e.g., 'source=com')
- `--max-days`: Optional. Maximum days per month to process
- `--csv`: Optional. Convert .parquet files to .csv
- `--no-chunking`: Optional. Disable chunking for large files
- `--chunk-size`: Optional. Specify chunk size (default: 8192 rows)

### Examples

Download data for a specific date:
```
python main.py --accept-terms --date 2025-03-29
```

Download data and convert to CSV:
```
python main.py --accept-terms --date 2025-03-29 --csv
```

Process only specific TLDs:
```
python main.py --accept-terms --date 2025-03-29 --sources "source=com" "source=net"
```

Specify a larger chunk size:
```
python main.py --accept-terms --date 2025-03-29 --chunk-size 16384
```

## Chunking Behavior

The tool automatically streams downloaded files into chunks to optimize memory usage:

1. Files are downloaded to a temporary location
2. The data is processed into chunks of the specified size
3. Each chunk is stored as a separate parquet file in a folder named after the original file
4. A manifest.json file is created with metadata about the chunks
5. The temporary file is removed

## File Structure

```
todayDomains/
├── main.py             # Main program file
├── analyze.py          # Analysis utilities
├── requirements.txt    # Package requirements
├── config/             # Configuration files
├── zoneFile/           # Downloaded zone files and chunks
└── worker.log          # Program log file
```

## Interrupting the Program

The program can be safely interrupted with Ctrl+C. It will:
1. Stop requesting new downloads
2. Finish processing the current file when possible
3. Clean up any temporary files
4. Shut down gracefully

## License

[**CC BY-NC 4.0**](https://creativecommons.org/licenses/by-nc/4.0/) License

## Acknowledgments

Data provided by the [OpenINTEL project](https://www.openintel.nl/).