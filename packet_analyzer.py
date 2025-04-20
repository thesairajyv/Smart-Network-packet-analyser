#!/usr/bin/env python3
"""
Packet Analyzer Tool

A comprehensive tool for analyzing PCAP files to identify network issues,
errors in streams, and provide detailed analysis of packet flows.
"""

import os
import sys
import asyncio
import argparse
import pyshark
import tempfile
from collections import defaultdict
from datetime import datetime

# Patch for nested event loops (fixes 'event loop is already running' error)
try:
    import nest_asyncio
    nest_asyncio.apply()
except ImportError:
    pass  # If not available, just skip (user can install with pip if needed)

# Define color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class PacketAnalyzer:
    def __init__(self, pcap_file, output_file=None, verbose=False, timeout=300, gemini_api_key="AIzaSyAuBRI5H_xHpWjWq_2on868LJa9akTwOAo"):  # Default timeout of 5 minutes
        self.timeout = timeout
        self.start_time = None
        self.pcap_file = pcap_file
        self.output_file = output_file
        self.verbose = verbose
        self.streams = defaultdict(list)
        self.stream_errors = defaultdict(list)
        self.llm_analyzer = None
        # Initialize LLM analyzer with provided API key
        try:
            from llm_analyzer import LLMAnalyzer
            if gemini_api_key:
                self.llm_analyzer = LLMAnalyzer(gemini_api_key)
            else:
                if self.verbose:
                    print(f"{Colors.WARNING}Warning: Gemini API key not provided. LLM analysis disabled.{Colors.ENDC}")
        except ImportError:
            if self.verbose:
                print(f"{Colors.WARNING}Warning: llm_analyzer module not found. LLM analysis disabled.{Colors.ENDC}")
            self.llm_analyzer = None # Ensure it's None if import fails

        self.stream_stats = defaultdict(lambda: {
            'packet_count': 0,
            'bytes': 0,
            'start_time': None,
            'end_time': None,
            'protocols': set(),
            'src_ips': set(),
            'dst_ips': set(),
            'src_ports': set(),
            'dst_ports': set(),
            'retransmissions': 0,
            'out_of_order': 0,
            'duplicate_acks': 0,
            'zero_window': 0,
            'window_update': 0,
            'keep_alive': 0,
            'keep_alive_ack': 0,
            'window_full': 0,
            'tcp_errors': 0,
            'http_errors': 0,
            'dns_errors': 0,
            'fragmentation': 0,
            'connection_reset': 0
        })
    
    async def _validate_pcap_format(self):
        """Validate and detect PCAP file format"""
        try:
            # Check if file exists
            if not os.path.exists(self.pcap_file):
                return False, f"File not found: {self.pcap_file}"
            
            # Use file command to detect file type
            proc = await asyncio.create_subprocess_exec(
                'file', self.pcap_file,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            file_type = stdout.decode().lower()
            
            # Try to read file header synchronously (file I/O is relatively quick)
            with open(self.pcap_file, 'rb') as f:
                magic_number = f.read(4)
                
                # Common PCAP magic numbers
                pcap_magic = b'\xd4\xc3\xb2\xa1'  # Little-endian
                pcap_magic_reverse = b'\xa1\xb2\xc3\xd4'  # Big-endian
                pcapng_magic = b'\x0a\x0d\x0d\x0a'  # PCAPng format
                
                if magic_number in [pcap_magic, pcap_magic_reverse, pcapng_magic]:
                    return True, None
                else:
                    return False, "Invalid PCAP format: File has incorrect magic number."
                    
        except Exception as e:
            return False, f"Error validating PCAP format: {str(e)}"
    
    async def _convert_pcap_format(self):
        """Convert capture file to standard PCAP format"""
        temp_pcap = None
        try:
            # Create a temporary file for the converted PCAP
            with tempfile.NamedTemporaryFile(suffix='.pcap', delete=False, dir=tempfile.gettempdir()) as temp_file:
                temp_pcap = temp_file.name
            
            # Try converting using tcpdump
            tcpdump_path = '/usr/sbin/tcpdump'
            if os.path.exists(tcpdump_path):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        tcpdump_path, '-r', self.pcap_file, '-w', temp_pcap,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    _, stderr = await proc.communicate()
                    
                    if proc.returncode == 0 and os.path.getsize(temp_pcap) > 0:
                        self.pcap_file = temp_pcap
                        return True, None
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.WARNING}tcpdump conversion failed: {str(e)}{Colors.ENDC}")
            
            # Try converting using editcap
            editcap_path = '/usr/local/bin/editcap'
            if os.path.exists(editcap_path):
                try:
                    proc = await asyncio.create_subprocess_exec(
                        editcap_path, '-F', 'pcap', self.pcap_file, temp_pcap,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                    _, stderr = await proc.communicate()
                    
                    if proc.returncode == 0 and os.path.getsize(temp_pcap) > 0:
                        self.pcap_file = temp_pcap
                        return True, None
                except Exception as e:
                    if self.verbose:
                        print(f"{Colors.WARNING}editcap conversion failed: {str(e)}{Colors.ENDC}")

            # If conversion failed, clean up temp file
            if temp_pcap and os.path.exists(temp_pcap):
                os.remove(temp_pcap)
            return False, "Failed to convert capture file format using available tools."
            
        except Exception as e:
            if temp_pcap and os.path.exists(temp_pcap):
                try:
                    os.remove(temp_pcap)
                except OSError:
                    pass
            return False, f"Error converting capture file: {str(e)}"

    async def analyze(self):
        """Main analysis function - asynchronous version"""
        print(f"{Colors.HEADER}Starting analysis of {self.pcap_file}...{Colors.ENDC}")
        self.start_time = datetime.now()
        capture = None
        original_pcap_file = self.pcap_file
        temp_pcap_created = False
        
        # The event loop is managed by the calling script

        try:
            # Validate PCAP format first
            is_valid, error_msg = await self._validate_pcap_format()
            if not is_valid:
                print(f"{Colors.WARNING}Warning: {error_msg}{Colors.ENDC}")
                print("Attempting to convert file format...")
                
                converted, conv_error = await self._convert_pcap_format()
                if not converted:
                    raise ValueError(f"Format conversion failed: {conv_error}")
                print(f"{Colors.GREEN}Successfully converted file format to {self.pcap_file}{Colors.ENDC}")
                temp_pcap_created = True
            
            print("Loading capture file...")
            # Create pyshark capture object with custom parameters for better performance
            capture = pyshark.FileCapture(
                input_file=self.pcap_file,
                keep_packets=False,  # Don't store packets in memory
                use_json=True,  # Use JSON output for better performance
                include_raw=False  # Don't include raw packet data
            )
            
            # Count packets synchronously (placeholder, will be replaced)
            print("Counting packets...")
            total_packets = 0
            try:
                # Simple count loop - inefficient but avoids loop issues for now
                for _ in capture:
                    total_packets += 1
                capture.reset() # Reset for actual processing
            except Exception as count_err:
                 print(f"\n{Colors.FAIL}Error during initial packet count: {count_err}{Colors.ENDC}")
                 raise # Stop if counting fails
            print(f"Counted {total_packets} packets.") # Report count

            print("\nPass 1: Organizing packets by stream (running in background thread)...")
            self.processed_packets = 0 # Ensure counter is reset before thread starts
            try:
                # Pass the capture object to the synchronous function run in a thread
                await asyncio.to_thread(self._process_capture_sync, capture, total_packets)
            except asyncio.TimeoutError:
                # Note: asyncio.to_thread doesn't directly handle timeouts like apply_on_packets.
                # Timeout needs to be managed externally if required for the threaded operation.
                print(f"\n{Colors.WARNING}Analysis thread execution potentially timed out or was interrupted.{Colors.ENDC}")
            except Exception as proc_err:
                print(f"\n{Colors.FAIL}Error during threaded packet processing: {proc_err}{Colors.ENDC}")
                raise

            # Report based on the counter updated by the thread
            print(f"\nPass 1 complete. Processed {self.processed_packets} packets.")
            
            # Analyze streams
            print("\nPass 2: Analyzing streams for errors...")
            self._analyze_streams()
            
            # Generate report
            print("\nGenerating final report...")
            await self._generate_report()
            
        except Exception as e:
            print(f"{Colors.FAIL}\nError analyzing pcap file: {str(e)}{Colors.ENDC}")
            raise
        finally:
            if capture:
                capture.close()
            if temp_pcap_created and self.pcap_file != original_pcap_file:
                try:
                    os.remove(self.pcap_file)
                    if self.verbose:
                        print(f"{Colors.CYAN}Cleaned up temporary file: {self.pcap_file}{Colors.ENDC}")
                    self.pcap_file = original_pcap_file
                except OSError as remove_err:
                    if self.verbose:
                        print(f"{Colors.WARNING}Could not remove temporary file {self.pcap_file}: {remove_err}{Colors.ENDC}")

    def _organize_streams_packet(self, packet, i):
        """Organize packets by stream ID"""
        try:
            # Determine stream type and ID
            stream_id = None
            
            # TCP stream
            if hasattr(packet, 'tcp'):
                if hasattr(packet.tcp, 'stream'):
                    stream_id = f"TCP_{packet.tcp.stream}"
                    self.streams[stream_id].append((i, packet))
                    self._update_stream_stats(stream_id, packet, i)
                    self._process_tcp_packet(packet, stream_id, i)
            
            # UDP stream
            elif hasattr(packet, 'udp'):
                # Create a unique ID for UDP streams based on IP and port
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    src_port = packet.udp.srcport
                    dst_port = packet.udp.dstport
                    
                    # Create a consistent ID regardless of direction
                    endpoints = sorted([(src_ip, src_port), (dst_ip, dst_port)])
                    stream_id = f"UDP_{endpoints[0][0]}:{endpoints[0][1]}_{endpoints[1][0]}:{endpoints[1][1]}"
                    
                    self.streams[stream_id].append((i, packet))
                    self._update_stream_stats(stream_id, packet, i)
                    self._process_udp_packet(packet, stream_id, i)
            
            # ICMP
            elif hasattr(packet, 'icmp'):
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Create a consistent ID regardless of direction
                    endpoints = sorted([src_ip, dst_ip])
                    stream_id = f"ICMP_{endpoints[0]}_{endpoints[1]}"
                    
                    self.streams[stream_id].append((i, packet))
                    self._update_stream_stats(stream_id, packet, i)
                    self._process_icmp_packet(packet, stream_id, i)
            
            # DNS
            elif hasattr(packet, 'dns'):
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Use transaction ID if available
                    if hasattr(packet.dns, 'id'):
                        dns_id = packet.dns.id
                        stream_id = f"DNS_{dns_id}"
                    else:
                        # Create a consistent ID based on IPs
                        endpoints = sorted([src_ip, dst_ip])
                        stream_id = f"DNS_{endpoints[0]}_{endpoints[1]}"
                    
                    self.streams[stream_id].append((i, packet))
                    self._update_stream_stats(stream_id, packet, i)
                    self._process_dns_packet(packet, stream_id, i)
            
            # Other protocols
            else:
                # Use highest layer as protocol identifier
                protocol = packet.highest_layer
                if hasattr(packet, 'ip'):
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    
                    # Create a consistent ID regardless of direction
                    endpoints = sorted([src_ip, dst_ip])
                    stream_id = f"{protocol}_{endpoints[0]}_{endpoints[1]}"
                    
                    self.streams[stream_id].append((i, packet))
                    self._update_stream_stats(stream_id, packet, i)
        
        except Exception as e:
                 print(f"{Colors.WARNING}Error organizing packet {i}: {str(e)}{Colors.ENDC}")

    def _process_capture_sync(self, capture, total_packets):
        """Synchronous function to process packets, intended to be run in a thread."""
        # This function runs in a separate thread via asyncio.to_thread
        # It should not use await or interact with the asyncio event loop directly
        print("Processing packets in background thread...")
        self.processed_packets = 0 # Reset counter for this run
        try:
            for packet in capture:
                # Pass the current count as the index 'i'
                self._organize_streams_packet(packet, self.processed_packets)
                self.processed_packets += 1
                # Progress reporting (optional, consider thread safety if complex state is involved)
                if self.processed_packets % 1000 == 0 or self.processed_packets == total_packets:
                    if total_packets > 0: # Avoid division by zero if count failed
                        progress = (self.processed_packets / total_packets) * 100
                        print(f"Progress: {progress:.1f}% ({self.processed_packets}/{total_packets} packets)", end='\r')
                    else:
                        print(f"Processed {self.processed_packets} packets...", end='\r')
        except Exception as e:
            # Log error from within the thread
            # Avoid raising here unless you want the main thread to catch it via the future
            print(f"\n{Colors.FAIL}Error during packet processing loop in thread: {e}{Colors.ENDC}")
            # Depending on severity, you might set a flag or just log

    # Removed _process_packet_callback method

    def _update_stream_stats(self, stream_id, packet, i):
        """Update statistics for a stream"""
        try:
            stats = self.stream_stats[stream_id]
            stats['packet_count'] += 1
            
            # Update time information
            packet_time = float(packet.sniff_timestamp)
            if stats['start_time'] is None or packet_time < stats['start_time']:
                stats['start_time'] = packet_time
            if stats['end_time'] is None or packet_time > stats['end_time']:
                stats['end_time'] = packet_time
            
            # Update protocol information
            highest_layer = packet.highest_layer
            stats['protocols'].add(highest_layer)
            
            # Update IP and port information if available
            if hasattr(packet, 'ip'):
                stats['src_ips'].add(packet.ip.src)
                stats['dst_ips'].add(packet.ip.dst)
                
                if hasattr(packet, 'tcp'):
                    stats['src_ports'].add(packet.tcp.srcport)
                    stats['dst_ports'].add(packet.tcp.dstport)
                    stats['bytes'] += int(packet.tcp.len) if hasattr(packet.tcp, 'len') else 0
                elif hasattr(packet, 'udp'):
                    stats['src_ports'].add(packet.udp.srcport)
                    stats['dst_ports'].add(packet.udp.dstport)
                    stats['bytes'] += int(packet.udp.length) if hasattr(packet.udp, 'length') else 0
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}Error processing packet {i}: {str(e)}{Colors.ENDC}")
    
    def _process_tcp_packet(self, packet, stream_id, packet_index):
        """Process TCP packet and identify issues"""
        try:
            stats = self.stream_stats[stream_id]
            
            # Check for TCP flags
            if hasattr(packet.tcp, 'flags'):
                    flags = packet.tcp.flags
                    
                    # Check for retransmissions
                    if hasattr(packet.tcp, 'analysis_retransmission'):
                        stats['retransmissions'] += 1
                        self.stream_errors[stream_id].append({
                            'type': 'retransmission',
                            'packet_index': packet_index,
                            'details': 'TCP retransmission detected'
                        })
                    
                    # Check for out of order segments
                    if hasattr(packet.tcp, 'analysis_out_of_order'):
                        stats['out_of_order'] += 1
                        self.stream_errors[stream_id].append({
                            'type': 'out_of_order',
                            'packet_index': packet_index,
                            'details': 'TCP out of order segment detected'
                        })
                    
                    # Check for duplicate ACKs
                    if hasattr(packet.tcp, 'analysis_duplicate_ack'):
                        stats['duplicate_acks'] += 1
                        self.stream_errors[stream_id].append({
                            'type': 'duplicate_ack',
                            'packet_index': packet_index,
                            'details': 'TCP duplicate ACK detected'
                        })
                    
                    # Check for zero window
                    if hasattr(packet.tcp, 'window_size') and int(packet.tcp.window_size) == 0:
                        stats['zero_window'] += 1
                        self.stream_errors[stream_id].append({
                            'type': 'zero_window',
                            'packet_index': packet_index,
                            'details': 'TCP zero window detected'
                        })
            
        except Exception as e:
            if self.verbose:
                print(f"{Colors.WARNING}Error processing TCP packet {packet_index}: {str(e)}{Colors.ENDC}")
            if hasattr(packet.tcp, 'analysis_retransmission'):
                stats['retransmissions'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Retransmission',
                    'description': f"TCP retransmission detected at packet {packet_index}",
                    'severity': 'Medium'
                })
            
            # Check for out-of-order packets
            if hasattr(packet.tcp, 'analysis_out_of_order'):
                stats['out_of_order'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Out-of-Order',
                    'description': f"TCP out-of-order packet detected at packet {packet_index}",
                    'severity': 'Medium'
                })
            
            # Check for duplicate ACKs
            if hasattr(packet.tcp, 'analysis_duplicate_ack'):
                stats['duplicate_acks'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Duplicate ACK',
                    'description': f"TCP duplicate ACK detected at packet {packet_index}",
                    'severity': 'Low'
                })
            
            # Check for zero window
            if hasattr(packet.tcp, 'analysis_zero_window'):
                stats['zero_window'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Zero Window',
                    'description': f"TCP zero window detected at packet {packet_index}",
                    'severity': 'High'
                })
            
            # Check for window update
            if hasattr(packet.tcp, 'analysis_window_update'):
                stats['window_update'] += 1
            
            # Check for keep-alive
            if hasattr(packet.tcp, 'analysis_keep_alive'):
                stats['keep_alive'] += 1
            
            # Check for keep-alive ACK
            if hasattr(packet.tcp, 'analysis_keep_alive_ack'):
                stats['keep_alive_ack'] += 1
            
            # Check for window full
            if hasattr(packet.tcp, 'analysis_window_full'):
                stats['window_full'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Window Full',
                    'description': f"TCP window full detected at packet {packet_index}",
                    'severity': 'Medium'
                })
            
            # Check for connection reset
            if hasattr(packet.tcp, 'flags_reset') and int(packet.tcp.flags_reset) == 1:
                stats['connection_reset'] += 1
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': 'TCP Connection Reset',
                    'description': f"TCP connection reset detected at packet {packet_index}",
                    'severity': 'High'
                })
        
        # Check for HTTP errors if this is an HTTP packet
        if hasattr(packet, 'http'):
            if hasattr(packet.http, 'response_code'):
                response_code = int(packet.http.response_code)
                if response_code >= 400:
                    stats['http_errors'] += 1
                    severity = 'Medium' if response_code < 500 else 'High'
                    self.stream_errors[stream_id].append({
                        'packet_index': packet_index,
                        'error_type': f"HTTP {response_code}",
                        'description': f"HTTP error {response_code} detected at packet {packet_index}",
                        'severity': severity
                    })
    
    def _process_udp_packet(self, packet, stream_id, packet_index):
        """Process UDP packet and identify issues"""
        # Check for fragmentation
        if hasattr(packet, 'ip') and hasattr(packet.ip, 'flags_mf') and int(packet.ip.flags_mf) == 1:
            self.stream_stats[stream_id]['fragmentation'] += 1
            self.stream_errors[stream_id].append({
                'packet_index': packet_index,
                'error_type': 'IP Fragmentation',
                'description': f"IP fragmentation detected at packet {packet_index}",
                'severity': 'Low'
            })
    
    def _process_icmp_packet(self, packet, stream_id, packet_index):
        """Process ICMP packet and identify issues"""
        if hasattr(packet.icmp, 'type'):
            icmp_type = int(packet.icmp.type)
            
            # Check for ICMP errors
            if icmp_type in [3, 4, 5, 11]:
                error_types = {
                    3: 'Destination Unreachable',
                    4: 'Source Quench',
                    5: 'Redirect',
                    11: 'Time Exceeded'
                }
                
                self.stream_errors[stream_id].append({
                    'packet_index': packet_index,
                    'error_type': f"ICMP {error_types[icmp_type]}",
                    'description': f"ICMP {error_types[icmp_type]} detected at packet {packet_index}",
                    'severity': 'Medium'
                })
    
    def _process_dns_packet(self, packet, stream_id, packet_index):
        """Process DNS packet and identify issues"""
        if hasattr(packet.dns, 'flags_response') and int(packet.dns.flags_response) == 1:
            # This is a DNS response
            if hasattr(packet.dns, 'flags_rcode'):
                response_code = int(packet.dns.flags_rcode)
                if response_code != 0:
                    # Non-zero response code indicates an error
                    error_types = {
                        1: 'Format Error',
                        2: 'Server Failure',
                        3: 'Name Error',
                        4: 'Not Implemented',
                        5: 'Refused'
                    }
                    
                    error_type = error_types.get(response_code, f"Unknown Error ({response_code})")
                    self.stream_stats[stream_id]['dns_errors'] += 1
                    self.stream_errors[stream_id].append({
                        'packet_index': packet_index,
                        'error_type': f"DNS {error_type}",
                        'description': f"DNS {error_type} detected at packet {packet_index}",
                        'severity': 'Medium'
                    })
    
    def _analyze_streams(self):
        """Analyze each stream for errors and patterns"""
        try:
            for stream_id, packets in self.streams.items():
                # Get stream statistics
                stats = self.stream_stats[stream_id]
                
                # Basic stream analysis
                if len(packets) < 2:
                    continue  # Skip streams with only one packet
                
                duration = stats['end_time'] - stats['start_time']
                stats['duration'] = duration
                stats['bytes_per_second'] = stats['bytes'] / duration if duration > 0 else 0
                
                # Remove synchronous LLM analysis from this phase
                # We'll handle all LLM analysis in the _generate_report method asynchronously
                if self.llm_analyzer and len(self.stream_errors[stream_id]) > 0:
                    # Just mark that this stream has errors for later analysis
                    stats['has_errors'] = True
        except Exception as e:
            print(f"{Colors.WARNING}Error analyzing streams: {str(e)}{Colors.ENDC}")
    
    async def _generate_report(self):
        """Generate a detailed analysis report asynchronously"""
        # Calculate total duration
        duration = (datetime.now() - self.start_time).total_seconds()
        
        # Prepare report content
        report = []
        report.append(f"Packet Analysis Report for {self.pcap_file}")
        report.append(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Analysis duration: {duration:.2f} seconds")
        report.append("")
        
        # Process errors with LLM if available
        if self.llm_analyzer:
            for stream_id, errors in self.stream_errors.items():
                if errors:
                    print(f"\nGetting AI analysis for errors in stream {stream_id}...")
                    
                    # Process each error individually and add to report
                    for i, error in enumerate(errors):
                        try:
                            print(f"Processing error {i+1}/{len(errors)} in stream {stream_id}...")
                            # Get AI analysis for individual error
                            ai_analysis = await self.llm_analyzer.analyze_error(error, self.stream_stats[stream_id])
                            
                            # Add the analysis to the report with clear separation
                            report.append(f"\n{Colors.CYAN}AI-Enhanced Analysis for Error {i+1} in Stream {stream_id}:{Colors.ENDC}")
                            report.append(f"Error Type: {error['error_type']}")
                            report.append(f"Description: {error['description']}")
                            report.append(f"Severity: {error['severity']}")
                            report.append(f"\nAI Analysis:\n{ai_analysis}\n")
                            report.append("-" * 80)
                            
                            # Write intermediate results to file to avoid losing progress
                            if self.output_file:
                                with open(self.output_file, 'w') as f:
                                    f.write("\n".join(report))
                                    
                        except Exception as e:
                            error_msg = f"Error getting AI analysis: {str(e)}"
                            print(f"{Colors.WARNING}{error_msg}{Colors.ENDC}")
                            report.append(f"\n{Colors.WARNING}Error analyzing error {i+1} in stream {stream_id}: {str(e)}{Colors.ENDC}\n")
                            
                    # After processing individual errors, get a sequence analysis if there are multiple errors
                    if len(errors) > 1:
                        try:
                            print(f"Getting sequence analysis for all {len(errors)} errors in stream {stream_id}...")
                            sequence_analysis = await self.llm_analyzer.analyze_error_sequence(errors, self.stream_stats[stream_id])
                            report.append(f"\n{Colors.CYAN}AI-Enhanced Sequence Analysis for Stream {stream_id}:{Colors.ENDC}\n{sequence_analysis}\n")
                            
                            # Update the file with sequence analysis
                            if self.output_file:
                                with open(self.output_file, 'w') as f:
                                    f.write("\n".join(report))
                                    
                        except Exception as e:
                            error_msg = f"Error getting sequence analysis: {str(e)}"
                            print(f"{Colors.WARNING}{error_msg}{Colors.ENDC}")
                            report.append(f"\n{Colors.WARNING}Error analyzing sequence in stream {stream_id}: {str(e)}{Colors.ENDC}\n")
                            
                    # Add a clear separator between streams
                    report.append("\n" + "=" * 80 + "\n")
        report.append(f"Total streams analyzed: {len(self.streams)}")
        report.append("")
        
        # Stream summary
        report.append("Stream Summary:")
        report.append("-" * 80)
        
        # LLM stream summaries for each stream
        if self.llm_analyzer:
            for stream_id, stats in sorted(self.stream_stats.items()):
                # ...existing code for stats formatting...
                duration_str = "N/A"
                if stats['start_time'] is not None and stats['end_time'] is not None:
                    duration = stats['end_time'] - stats['start_time']
                    duration_str = f"{duration:.6f} seconds"
                src_ips = ", ".join(stats['src_ips'])
                dst_ips = ", ".join(stats['dst_ips'])
                src_ports = ", ".join(stats['src_ports'])
                dst_ports = ", ".join(stats['dst_ports'])
                protocols = ", ".join(stats['protocols'])
                report.append(f"Stream: {stream_id}")
                report.append(f"  Packets: {stats['packet_count']}")
                report.append(f"  Bytes: {stats['bytes']}")
                report.append(f"  Duration: {duration_str}")
                report.append(f"  Protocols: {protocols}")
                report.append(f"  Source IPs: {src_ips}")
                report.append(f"  Destination IPs: {dst_ips}")
                report.append(f"  Source Ports: {src_ports}")
                report.append(f"  Destination Ports: {dst_ports}")
                if stream_id.startswith("TCP"):
                    report.append(f"  TCP Retransmissions: {stats['retransmissions']}")
                    report.append(f"  TCP Out-of-Order Packets: {stats['out_of_order']}")
                    report.append(f"  TCP Duplicate ACKs: {stats['duplicate_acks']}")
                    report.append(f"  TCP Zero Window: {stats['zero_window']}")
                    report.append(f"  TCP Window Updates: {stats['window_update']}")
                    report.append(f"  TCP Keep-Alive: {stats['keep_alive']}")
                    report.append(f"  TCP Keep-Alive ACKs: {stats['keep_alive_ack']}")
                    report.append(f"  TCP Window Full: {stats['window_full']}")
                    report.append(f"  TCP Connection Resets: {stats['connection_reset']}")
                if stats['http_errors'] > 0:
                    report.append(f"  HTTP Errors: {stats['http_errors']}")
                if stats['dns_errors'] > 0:
                    report.append(f"  DNS Errors: {stats['dns_errors']}")
                if stats['fragmentation'] > 0:
                    report.append(f"  IP Fragmentation: {stats['fragmentation']}")
                report.append("")
                # LLM stream summary below each stream
                report.append(f"AI Analysis for Stream {stream_id}:")
                ai_summary = await self.llm_analyzer.analyze_stream_summary(stats)
                report.append(ai_summary)
                report.append("\n" + ("-" * 80) + "\n")
            # Skip the old loop for stream stats below
            # ...skip to error details...
            report.append("Error Details:")
            report.append("-" * 80)
            total_errors = sum(len(errors) for errors in self.stream_errors.values())
            report.append(f"Total errors detected: {total_errors}")
            report.append("")
            for stream_id, errors in sorted(self.stream_errors.items()):
                if errors:
                    report.append(f"Stream {stream_id} - {len(errors)} errors:")
                    for error in errors:
                        report.append(f"  Packet {error['packet_index']}: {error['error_type']} - {error['description']} (Severity: {error['severity']})")
                    report.append("")
            # ...existing code for writing report...
            if self.output_file:
                with open(self.output_file, 'w') as f:
                    f.write("\n".join(report))
                print(f"Report written to {self.output_file}")
            else:
                print("\n".join(report))
            return
        # ...existing code for non-LLM fallback...
        for stream_id, stats in sorted(self.stream_stats.items()):
            # Calculate duration if possible
            duration_str = "N/A"
            if stats['start_time'] is not None and stats['end_time'] is not None:
                duration = stats['end_time'] - stats['start_time']
                duration_str = f"{duration:.6f} seconds"
            
            # Format IPs and ports for display
            src_ips = ", ".join(stats['src_ips'])
            dst_ips = ", ".join(stats['dst_ips'])
            src_ports = ", ".join(stats['src_ports'])
            dst_ports = ", ".join(stats['dst_ports'])
            protocols = ", ".join(stats['protocols'])
            
            report.append(f"Stream: {stream_id}")
            report.append(f"  Packets: {stats['packet_count']}")
            report.append(f"  Bytes: {stats['bytes']}")
            report.append(f"  Duration: {duration_str}")
            report.append(f"  Protocols: {protocols}")
            report.append(f"  Source IPs: {src_ips}")
            report.append(f"  Destination IPs: {dst_ips}")
            report.append(f"  Source Ports: {src_ports}")
            report.append(f"  Destination Ports: {dst_ports}")
            
            # TCP specific stats
            if stream_id.startswith("TCP"):
                report.append(f"  TCP Retransmissions: {stats['retransmissions']}")
                report.append(f"  TCP Out-of-Order Packets: {stats['out_of_order']}")
                report.append(f"  TCP Duplicate ACKs: {stats['duplicate_acks']}")
                report.append(f"  TCP Zero Window: {stats['zero_window']}")
                report.append(f"  TCP Window Updates: {stats['window_update']}")
                report.append(f"  TCP Keep-Alive: {stats['keep_alive']}")
                report.append(f"  TCP Keep-Alive ACKs: {stats['keep_alive_ack']}")
                report.append(f"  TCP Window Full: {stats['window_full']}")
                report.append(f"  TCP Connection Resets: {stats['connection_reset']}")
            
            # HTTP errors
            if stats['http_errors'] > 0:
                report.append(f"  HTTP Errors: {stats['http_errors']}")
            
            # DNS errors
            if stats['dns_errors'] > 0:
                report.append(f"  DNS Errors: {stats['dns_errors']}")
            
            # IP Fragmentation
            if stats['fragmentation'] > 0:
                report.append(f"  IP Fragmentation: {stats['fragmentation']}")
            
            report.append("")
        
        # Error details
        report.append("Error Details:")
        report.append("-" * 80)
        
        total_errors = sum(len(errors) for errors in self.stream_errors.values())
        report.append(f"Total errors detected: {total_errors}")
        report.append("")
        
        for stream_id, errors in sorted(self.stream_errors.items()):
            if errors:
                report.append(f"Stream {stream_id} - {len(errors)} errors:")
                for error in errors:
                    report.append(f"  Packet {error['packet_index']}: {error['error_type']} - {error['description']} (Severity: {error['severity']})")
                report.append("")
        
        # Write report to file if specified
        if self.output_file:
            with open(self.output_file, 'w') as f:
                f.write("\n".join(report))
            print(f"Report written to {self.output_file}")
        else:
            # Print report to console
            print("\n".join(report))

def main():
    parser = argparse.ArgumentParser(description='Analyze PCAP files for network issues and errors.')
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')
    parser.add_argument('-o', '--output', help='Output file for the analysis report')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-t', '--timeout', type=int, default=300, help='Timeout in seconds (default: 300)')
    
    args = parser.parse_args()
    
    # Check if the file exists
    if not os.path.isfile(args.pcap_file):
        print(f"Error: PCAP file '{args.pcap_file}' not found.")
        sys.exit(1)
    
    # Create analyzer and run analysis
    analyzer = PacketAnalyzer(
        pcap_file=args.pcap_file,
        output_file=args.output,
        verbose=args.verbose,
        timeout=args.timeout
    )
    
    analyzer.analyze()

if __name__ == "__main__":
    main()