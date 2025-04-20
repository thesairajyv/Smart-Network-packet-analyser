#!/usr/bin/env python3

import sys
import os
import asyncio
import argparse
from packet_analyzer import PacketAnalyzer, Colors

# Patch for nested event loops (fixes 'event loop is already running' error)
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass  # If not available, just skip (user can install with pip if needed)

async def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Analyze PCAP files for network issues and generate detailed reports')
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')
    parser.add_argument('-o', '--output', default=None, help='Output file for the analysis report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=300, help='Analysis timeout in seconds')
    args = parser.parse_args()

    try:
        # Get Gemini API key from environment variable
        gemini_api_key = os.getenv('GEMINI_API_KEY')
        if not gemini_api_key:
            print(f'{Colors.WARNING}Warning: GEMINI_API_KEY not set. LLM analysis will be disabled.{Colors.ENDC}')
        
        # Create output file path and ensure it's absolute
        if args.output:
            output_file = os.path.abspath(args.output)
        else:
            # Use the pcap file name as prefix for the output file
            pcap_base = os.path.splitext(os.path.basename(args.pcap_file))[0]
            output_file = os.path.abspath(f"{pcap_base}_analysis.txt")
        print(f"Analysis results will be saved to: {output_file}")
        
        # Create and run the analyzer
        analyzer = PacketAnalyzer(
            pcap_file=args.pcap_file,
            output_file=output_file,
            verbose=args.verbose,
            timeout=args.timeout,
            gemini_api_key=gemini_api_key
        )
        
        try:
            # Run the analysis asynchronously
            await analyzer.analyze()
            print(f'\n{Colors.GREEN}Analysis complete! Report saved to: {output_file}{Colors.ENDC}')
        except asyncio.TimeoutError:
            print(f'\n{Colors.FAIL}Error: Analysis timed out after {args.timeout} seconds{Colors.ENDC}')
            sys.exit(1)
        except Exception as e:
            print(f'\n{Colors.FAIL}Error during analysis: {str(e)}{Colors.ENDC}')
            sys.exit(1)
            
    except KeyboardInterrupt:
        print(f'\n{Colors.WARNING}Analysis interrupted by user{Colors.ENDC}')
        sys.exit(0)
    except Exception as e:
        print(f'\n{Colors.FAIL}Error: {str(e)}{Colors.ENDC}')
        sys.exit(1)

if __name__ == '__main__':
    # Properly handle asyncio event loop
    try:
        # Use asyncio.run() which properly manages the event loop
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\nAnalysis interrupted by user.')
        sys.exit(0)
    except RuntimeError as e:
        if "Event loop is closed" in str(e):
            print(f"\n{Colors.WARNING}Warning: Event loop was closed. This is likely due to a previous error.{Colors.ENDC}")
        else:
            print(f"\n{Colors.FAIL}Runtime error: {str(e)}{Colors.ENDC}")
        sys.exit(1)