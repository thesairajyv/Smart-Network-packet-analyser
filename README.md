# Network Packet Analyzer

A comprehensive Python tool for analyzing PCAP files to identify network issues, errors in streams, and provide detailed analysis of packet flows. This tool helps network administrators and developers diagnose network problems and understand traffic patterns.

## Features

- **Multi-Protocol Support**: Analyzes TCP, UDP, ICMP, DNS, and HTTP streams
- **Advanced Error Detection**:
  - TCP retransmissions and out-of-order packets
  - Duplicate ACKs and zero window events
  - Connection establishment/termination issues
  - Flow control problems
  - HTTP and DNS errors
  - IP fragmentation
- **Stream-Based Analysis**: Organizes packets by stream for better context
- **Detailed Statistics**: Tracks packet counts, bytes, timing, and protocol-specific metrics
- **Smart Format Detection**: Automatically detects and converts different PCAP formats
- **Color-Coded Output**: Easy-to-read terminal output with severity levels
- **Configurable Timeout**: Adjustable analysis timeout for large captures

## Requirements

- Python 3.x
- pyshark
- tcpdump or Wireshark (for PCAP format conversion)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-analyzer.git
   cd packet-analyzer
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Basic Usage

```python
from packet_analyzer import PacketAnalyzer

# Create an analyzer instance
analyzer = PacketAnalyzer(
    pcap_file="capture.pcap",
    output_file="analysis_report.txt",
    verbose=True
)

# Run the analysis
analyzer.analyze()
```

### Command Line Example

```bash
python example.py capture.pcap
```

### Configuration Options

- `pcap_file`: Path to the PCAP file for analysis
- `output_file`: Optional file for saving the analysis report
- `verbose`: Enable detailed logging (default: False)
- `timeout`: Analysis timeout in seconds (default: 300)

## Analysis Output

The analyzer provides:
- Stream-by-stream analysis
- Error detection with severity levels
- Protocol-specific statistics
- Timing and performance metrics
- Detailed error descriptions and suggestions

## Error Types

### TCP Errors
- Retransmissions
- Out-of-order packets
- Duplicate ACKs
- Zero window events
- Connection resets

### Application Layer
- HTTP error codes
- DNS resolution issues
- Protocol-specific problems

### Network Layer
- IP fragmentation
- ICMP errors

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
Feel free to contact over www.linkedin.com/in/sairaj-y-v-a4b105174

## Acknowledgments

- Built with [pyshark](https://github.com/KimiNewt/pyshark)
- Uses Wireshark/tcpdump for PCAP processing