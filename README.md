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

- Python 3.8+
- pyshark
- nest_asyncio
- google-generativeai
- scapy
- Wireshark/tshark (system dependency, required for pyshark)
- tcpdump (system dependency, for PCAP conversion)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/packet-analyzer.git
   cd packet-analyzer
   ```

2. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Install system dependencies (required for pyshark and PCAP conversion):
   - On macOS:
     ```bash
     brew install wireshark tcpdump
     ```
   - On Ubuntu/Debian:
     ```bash
     sudo apt-get install wireshark tcpdump
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

## V2 Update (April 2025)

- **AI-Powered Stream Analysis:** Each stream in the report now includes an LLM (Gemini) AI analysis section, even if no errors are detected, providing traffic insights and protocol summaries.
- **Automatic Output Naming:** Output report files are now named using the PCAP file's prefix (e.g., `capture_analysis.txt` for `capture.pcap`).
- **Improved Gemini Model Support:** Now uses the latest supported Gemini model (`gemini-1.5-pro-latest`) for compatibility and better results.
- **Bug Fixes:** Fixed event loop, model selection, and async/sync issues for robust operation on macOS and other platforms.

## Quick Start (How to Run)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/packet-analyzer.git
   cd packet-analyzer
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set your Gemini API key:**
   - Get your API key from Google AI Studio or your Gemini developer console.
   - Export it in your terminal:
     ```bash
     export GEMINI_API_KEY="your-gemini-api-key"
     ```

4. **Run the analyzer on a PCAP file:**
   ```bash
   python3 analyze_pcap.py /path/to/your/capture.pcap
   ```
   - The output report will be saved as `capture_analysis.txt` in the current directory.

5. **View the report:**
   - Open the generated `*_analysis.txt` file to see stream-by-stream analysis and AI insights.

## Troubleshooting

- If you see errors about missing tshark or tcpdump, make sure you have installed the system dependencies as described above.
- If you see ImportError for nest_asyncio, make sure you ran `pip install -r requirements.txt`.
- For Gemini/LLM features, ensure you have set your `GEMINI_API_KEY` environment variable.

## Notes
- If you hit Gemini API rate limits, the tool will automatically wait and resume.
- For best results, use Python 3.8+ and ensure your `google-generativeai` package is up to date.
- For troubleshooting, check the terminal output for warnings or errors.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
Feel free to contact over www.linkedin.com/in/sairaj-y-v-a4b105174

## Acknowledgments

- Built with [pyshark](https://github.com/KimiNewt/pyshark)
- Uses Wireshark/tcpdump for PCAP processing