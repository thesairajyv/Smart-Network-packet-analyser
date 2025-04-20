#!/usr/bin/env python3
"""
Example script demonstrating how to use the packet analyzer
"""

import os
import sys
import asyncio
from packet_analyzer import PacketAnalyzer, Colors

async def run_example():
    # Check if a sample PCAP file was provided as an argument
    if len(sys.argv) > 1:
        pcap_file = sys.argv[1]
    else:
        print("No PCAP file provided. Please provide a path to a PCAP file.")
        print("Usage: python example.py <path_to_pcap_file>")
        sys.exit(1)
    
    # Check if the file exists
    if not os.path.isfile(pcap_file):
        print(f"Error: PCAP file '{pcap_file}' not found.")
        sys.exit(1)
    
    print(f"Analyzing PCAP file: {pcap_file}")
    
    try:
        # Create an analyzer instance with a configurable timeout
        analyzer = PacketAnalyzer(
            pcap_file=pcap_file,
            output_file="example_output.txt",
            verbose=True,
            timeout=300  # 5 minutes timeout
        )
        
        # Run the analysis asynchronously
        await analyzer.analyze()
    except TimeoutError as e:
        print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
        print("\nSuggestions:")
        print("1. Try increasing the timeout value")
        print("2. Consider splitting the PCAP file into smaller chunks")
        print("3. Use a packet filter to analyze specific traffic only")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}Error during analysis: {str(e)}{Colors.ENDC}")
        sys.exit(1)
    
    print("\nAnalysis complete! Check example_output.txt for the full report.")
    print("\nExample of how to use the PacketAnalyzer programmatically:")
    print("""
    import os
    import asyncio
    from packet_analyzer import PacketAnalyzer

    async def main():
        # Get Gemini API key from environment variable
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            print("Warning: GEMINI_API_KEY not found in environment. LLM analysis will be disabled.")
        
        try:
            # Create an analyzer instance with LLM capabilities
            analyzer = PacketAnalyzer(
                pcap_file="your_capture.pcap",
                output_file="analysis_report.txt",
                verbose=False,
                gemini_api_key=gemini_api_key
            )
            
            # Run the analysis
            await analyzer.analyze()
    except TimeoutError as e:
        print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
        print("\nSuggestions:")
        print("1. Try increasing the timeout value")
        print("2. Consider splitting the PCAP file into smaller chunks")
        print("3. Use a packet filter to analyze specific traffic only")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}Error during analysis: {str(e)}{Colors.ENDC}")
        sys.exit(1)
    
    # Access the analysis results programmatically
    for stream_id, errors in analyzer.stream_errors.items():
        print(f"Stream {stream_id} has {len(errors)} errors")
        
    # Get statistics for a specific stream
    tcp_stream = "TCP_0"  # Example stream ID
    if tcp_stream in analyzer.stream_stats:
        stats = analyzer.stream_stats[tcp_stream]
        print(f"TCP Stream 0 has {stats['retransmissions']} retransmissions")
    """)

if __name__ == "__main__":
    async def main():
        try:
            await run_example()
        except Exception as e:
            print(f"\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}")
            sys.exit(1)
    
    # Run the async main function
    # asyncio.run(main())
    # Try explicit loop management
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user.")
        sys.exit(0)