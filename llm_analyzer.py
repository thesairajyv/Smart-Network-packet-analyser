#!/usr/bin/env python3

import google.generativeai as genai
from typing import Dict, List
import asyncio
import time

class LLMAnalyzer:
    def __init__(self, api_key: str):
        """Initialize the LLM analyzer with API credentials"""
        genai.configure(api_key=api_key)
        # Try the most compatible model for v1beta
        self.model = genai.GenerativeModel('gemini-1.5-pro-latest')
        self.request_count = 0
        self.last_request_time = 0
        self.rate_limit = 10  # Maximum requests per minute
    
    def format_error_context(self, error: Dict, stream_stats: Dict) -> str:
        """Format error context for LLM analysis"""
        context = f"Error Type: {error.get('error_type', error.get('type', 'Unknown'))}\n"
        context += f"Severity: {error.get('severity', 'Unknown')}\n"
        context += f"Description: {error.get('description', error.get('details', 'No description'))}\n\n"
        
        # Add relevant stream statistics
        context += "Stream Context:\n"
        context += f"- Total Packets: {stream_stats['packet_count']}\n"
        context += f"- Protocol(s): {', '.join(stream_stats['protocols'])}\n"
        context += f"- Retransmissions: {stream_stats['retransmissions']}\n"
        context += f"- Out of Order Packets: {stream_stats['out_of_order']}\n"
        context += f"- Duplicate ACKs: {stream_stats['duplicate_acks']}\n"
        context += f"- Zero Window Events: {stream_stats['zero_window']}\n"
        
        return context
    
    async def _rate_limit_check(self):
        """Implement rate limiting to avoid API throttling"""
        self.request_count += 1
        current_time = time.time()
        
        # If we've made too many requests in the last minute, wait
        if self.request_count >= self.rate_limit and (current_time - self.last_request_time) < 60:
            wait_time = 60 - (current_time - self.last_request_time) + 1
            print(f"Rate limit reached. Waiting {wait_time:.1f} seconds before next request...")
            await asyncio.sleep(wait_time)
            self.request_count = 0
            self.last_request_time = time.time()
        elif (current_time - self.last_request_time) >= 60:
            # Reset counter if a minute has passed
            self.request_count = 1
            self.last_request_time = current_time
    
    async def analyze_error(self, error: Dict, stream_stats: Dict) -> str:
        """Get LLM analysis for a network error"""
        # Check rate limits before making API call
        await self._rate_limit_check()
        
        prompt = f"""
        As a network analysis expert, please analyze this network error and provide:
        1. A detailed explanation of the issue
        2. Potential causes
        3. Recommended solutions
        4. Impact on network performance

        Error Context:
        {self.format_error_context(error, stream_stats)}
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text if hasattr(response, 'text') else str(response)
        except Exception as e:
            return f"Error getting LLM analysis: {str(e)}"
    
    async def analyze_error_sequence(self, errors: List[Dict], stream_stats: Dict) -> str:
        """Analyze a sequence of related errors in a stream"""
        # Check rate limits before making API call
        await self._rate_limit_check()
        
        # Limit the number of errors to analyze to avoid exceeding context limits
        if len(errors) > 5:
            # Take first 2, last 2, and a middle one for context
            sample_errors = errors[:2] + [errors[len(errors)//2]] + errors[-2:]
            error_note = f"\n(Note: Analyzing a sample of 5 errors from a total of {len(errors)} errors)\n"
        else:
            sample_errors = errors
            error_note = ""
        
        error_contexts = [self.format_error_context(error, stream_stats) for error in sample_errors]
        combined_context = "\n---\n".join(error_contexts)
        
        prompt = f"""
        As a network analysis expert, please analyze this sequence of related network errors and provide:
        1. A comprehensive analysis of the error pattern
        2. Root cause analysis
        3. Potential correlations between the errors
        4. Recommended troubleshooting steps
        5. Mitigation strategies{error_note}

        Error Sequence:
        {combined_context}
        """
        
        try:
            response = self.model.generate_content(prompt)
            return response.text if hasattr(response, 'text') else str(response)
        except Exception as e:
            return f"Error getting LLM analysis: {str(e)}"

    async def analyze_stream_summary(self, stream_stats: dict) -> str:
        """Get LLM analysis for a stream summary (even if no errors)"""
        await self._rate_limit_check()
        prompt = f"""
        As a network analysis expert, please analyze the following network stream and provide:
        1. A summary of the traffic pattern and protocol usage
        2. Any notable characteristics or anomalies (even if not errors)
        3. Insights into the type of communication (e.g., web browsing, file transfer, etc.)
        4. Suggestions for further investigation if needed

        Stream Statistics:
        - Total Packets: {stream_stats['packet_count']}
        - Protocol(s): {', '.join(stream_stats['protocols'])}
        - Source IPs: {', '.join(stream_stats['src_ips'])}
        - Destination IPs: {', '.join(stream_stats['dst_ips'])}
        - Source Ports: {', '.join(stream_stats['src_ports'])}
        - Destination Ports: {', '.join(stream_stats['dst_ports'])}
        - Bytes: {stream_stats['bytes']}
        - Duration: {stream_stats.get('duration', 'N/A')}
        - Retransmissions: {stream_stats['retransmissions']}
        - Out of Order Packets: {stream_stats['out_of_order']}
        - Duplicate ACKs: {stream_stats['duplicate_acks']}
        - Zero Window Events: {stream_stats['zero_window']}
        - HTTP Errors: {stream_stats['http_errors']}
        - DNS Errors: {stream_stats['dns_errors']}
        - IP Fragmentation: {stream_stats['fragmentation']}
        - TCP Connection Resets: {stream_stats['connection_reset']}
        """
        try:
            response = self.model.generate_content(prompt)
            return response.text if hasattr(response, 'text') else str(response)
        except Exception as e:
            return f"Error getting LLM stream summary: {str(e)}"

