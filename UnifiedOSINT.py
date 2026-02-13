#!/usr/bin/env python3
"""
Unified OSINT Information Gathering Tool

This tool performs comprehensive information gathering with user-selected operations:
- Web-based investigation: DNS resolution and geolocation
- Non-web investigation: Social media search
"""

import socket
import requests
import whois
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import quote
from datetime import datetime
import argparse


class OSINTReport:
    """Handles generation of structured OSINT reports."""

    def __init__(self):
        self.sections = []
        self.executive_summary = []
        self.ran_operations = []

    def add_section(self, title: str, content: str):
        """Add a section to the report."""
        self.sections.append({
            'title': title,
            'content': content
        })

    def add_item(self, title: str, value: str, indent: int = 0):
        """Add an item to the current section."""
        if indent > 0:
            value = ' ' * indent + value
        self.sections[-1]['content'] += f"\n{value}"

    def add_executive_item(self, title: str, value: str):
        """Add an item to executive summary."""
        self.executive_summary.append(f"- {title}: {value}")

    def mark_operation_complete(self, operation: str):
        """Mark an operation as completed."""
        self.ran_operations.append(operation)

    def render(self) -> str:
        """Render the complete report as a formatted string."""
        report_lines = []
        report_lines.append("=" * 80)
        report_lines.append(f"OSINT INFORMATION GATHERING REPORT")
        report_lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report_lines.append("=" * 80)

        for section in self.sections:
            report_lines.append("\n" + "-" * 80)
            report_lines.append(f"SECTION: {section['title']}")
            report_lines.append("-" * 80)
            report_lines.append(section['content'])

        # Executive Summary Section
        if self.executive_summary:
            report_lines.append("\n" + "=" * 80)
            report_lines.append("EXECUTIVE SUMMARY")
            report_lines.append("=" * 80)
            for item in self.executive_summary:
                report_lines.append(item)

        report_lines.append("\n" + "=" * 80)
        report_lines.append("END OF REPORT")
        report_lines.append("=" * 80)

        return "\n".join(report_lines)


class DNSResolver:
    """Handles DNS resolution operations."""

    @staticmethod
    def resolve(hostname: str) -> Optional[str]:
        """Resolve hostname to IP address."""
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror as e:
            return None
        except Exception as e:
            raise Exception(f"DNS resolution error: {str(e)}")

    @staticmethod
    def reverse_lookup(ip_address: str) -> Optional[str]:
        """Perform reverse IP lookup."""
        try:
            return socket.gethostbyaddr(ip_address)
        except socket.herror:
            return None
        except Exception as e:
            raise Exception(f"Reverse lookup error: {str(e)}")


class GeolocationChecker:
    """Handles geolocation lookups."""

    @staticmethod
    def get_geolocation(ip_address: str) -> Dict[str, Any]:
        """Retrieve geolocation data for an IP address."""
        url = f"https://ipinfo.io/{ip_address}/json"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            raise Exception(f"Geolocation API error: {str(e)}")

    @staticmethod
    def is_cloudflare_proxy(geo_data: Dict[str, Any]) -> bool:
        """Check if IP appears to be on Cloudflare."""
        org = geo_data.get('org', '').lower()
        return 'cloudflare' in org

    @staticmethod
    def is_data_center(geo_data: Dict[str, Any]) -> bool:
        """Check if IP appears to be in a data center."""
        org = geo_data.get('org', '').lower()
        return any(x in org for x in ['datacenter', 'digital ocean', 'aws', 'google'])


class WHOISRetriever:
    """Handles WHOIS information retrieval."""

    @staticmethod
    def get_whois(hostname: str) -> Optional[whois.WhoisResult]:
        """Retrieve WHOIS information for a domain."""
        try:
            return whois.whois(hostname)
        except Exception as e:
            raise Exception(f"WHOIS query error: {str(e)}")

    @staticmethod
    def extract_registrar(whois_data: Any) -> str:
        """Extract registrar information."""
        if hasattr(whois_data, 'registrar') and whois_data.registrar:
            return whois_data.registrar
        if hasattr(whois_data, 'registrar_name') and whois_data.registrar_name:
            return whois_data.registrar_name
        return "Unknown"

    @staticmethod
    def extract_domain_name(whois_data: Any) -> str:
        """Extract domain name."""
        if hasattr(whois_data, 'domain_name'):
            if isinstance(whois_data.domain_name, list):
                return ", ".join(whois_data.domain_name)
            return whois_data.domain_name
        if hasattr(whois_data, 'name'):
            return whois_data.name
        return "Unknown"

    @staticmethod
    def extract_creation_date(whois_data: Any) -> str:
        """Extract creation date."""
        if hasattr(whois_data, 'creation_date'):
            date = whois_data.creation_date
            if isinstance(date, list):
                date = date[0] if date else None
            return str(date) if date else "Unknown"
        return "Unknown"

    @staticmethod
    def extract_expiration_date(whois_data: Any) -> str:
        """Extract expiration date."""
        if hasattr(whois_data, 'expiration_date'):
            date = whois_data.expiration_date
            if isinstance(date, list):
                date = date[0] if date else None
            return str(date) if date else "Unknown"
        return "Unknown"

    @staticmethod
    def extract_updated_date(whois_data: Any) -> str:
        """Extract last updated date."""
        if hasattr(whois_data, 'updated_date'):
            date = whois_data.updated_date
            if isinstance(date, list):
                date = date[0] if date else None
            return str(date) if date else "Unknown"
        return "Unknown"

    @staticmethod
    def extract_name_servers(whois_data: Any) -> str:
        """Extract name server information."""
        if hasattr(whois_data, 'name_servers'):
            if isinstance(whois_data.name_servers, list):
                return ", ".join(whois_data.name_servers)
            return whois_data.name_servers
        return "Unknown"


class SocialMediaChecker:
    """Handles social media searches."""

    SOCIAL_PLATFORMS = {
        'Facebook': 'https://www.facebook.com/search/people/?q={query}',
        'X (Twitter)': 'https://x.com/search?q={query}&src=typed_query',
        'Instagram': 'https://www.instagram.com/explore/tags/{query}',
        'LinkedIn': 'https://www.linkedin.com/search/results/all/?keywords={query}',
        'YouTube': 'https://www.youtube.com/results?search_query={query}',
        'Pinterest': 'https://pinterest.com/search/pins/?q={query}',
        'TikTok': 'https://www.tiktok.com/search?q={query}',
        'Reddit': 'https://www.reddit.com/search/?q={query}',
    }

    @staticmethod
    def sanitize_input(input_str: str) -> str:
        """Sanitize input for URL encoding."""
        return re.sub(r'[^a-zA-Z0-9\s]', '', input_str).strip()

    @staticmethod
    def check_platform(query: str, platform: str) -> Tuple[bool, str]:
        """Check a single social media platform for results."""
        sanitized_query = SocialMediaChecker.sanitize_input(query)
        if not sanitized_query:
            return False, "Invalid input"

        url = SocialMediaChecker.SOCIAL_PLATFORMS.get(platform, '').format(
            query=quote(sanitized_query)
        )

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }

        try:
            response = requests.get(url, headers=headers, timeout=5)
            return response.status_code == 200, url
        except Exception:
            return False, f"Error checking {platform}"

    @staticmethod
    def check_all(query: str) -> Dict[str, Tuple[bool, str]]:
        """Check all social media platforms."""
        results = {}
        for platform in SocialMediaChecker.SOCIAL_PLATFORMS.keys():
            found, url = SocialMediaChecker.check_platform(query, platform)
            results[platform] = (found, url)
        return results


class UnifiedOSINTTool:
    """Main OSINT information gathering tool."""

    def __init__(self):
        self.report = OSINTReport()

    def validate_input(self, target: str) -> bool:
        """Validate user input."""
        if not target or not target.strip():
            print("Error: Input cannot be empty")
            return False
        if not re.match(r'^[a-zA-Z0-9.-]+$', target.strip()):
            print("Error: Invalid input format. Use hostname, domain, or IP address")
            return False
        return True

    def get_user_target(self) -> str:
        """Get target from user."""
        print("\n" + "=" * 80)
        print("OSINT INFORMATION GATHERING - USER TARGET SELECTION")
        print("=" * 80)
        print("\nPlease enter the target to investigate:")
        print("- Hostname or domain (e.g., example.com)")
        print("- IP address (e.g., 192.168.1.1)")
        print("- Social media username/real name")

        while True:
            target = input("\nEnter target: ").strip()
            if self.validate_input(target):
                return target

    def get_user_operations(self) -> List[str]:
        """Get user-selected operations."""
        print("\n" + "=" * 80)
        print("OPERATION SELECTION")
        print("=" * 80)

        print("\nSelect operations to perform:")
        print("1. Web-based investigation (DNS Resolution + Geolocation)")
        print("2. Non-web investigation (Social Media Search)")
        print("3. Run all operations")
        print("4. Custom selection")

        while True:
            choice = input("\nEnter your selection (1-4): ").strip()

            if choice == '1':
                return ['dns', 'geo']
            elif choice == '2':
                return ['social']
            elif choice == '3':
                return ['dns', 'geo', 'social']
            elif choice == '4':
                print("\nCustom selection:")
                operations = []
                while True:
                    print("\nAvailable operations:")
                    print("- dns: DNS Resolution")
                    print("- geo: Geolocation")
                    print("- social: Social Media Search")
                    print("- all: All operations")

                    custom = input("\nEnter operation(s) to run (comma-separated): ").strip().lower()
                    custom_ops = [op.strip() for op in custom.split(',')]

                    if not custom_ops:
                        continue

                    if 'all' in custom_ops:
                        return ['dns', 'geo', 'social']

                    for op in custom_ops:
                        if op in ['dns', 'geo', 'social']:
                            if op not in operations:
                                operations.append(op)
                        else:
                            print(f"Warning: '{op}' is not a valid operation. Skipping.")

                    if len(operations) > 0:
                        print(f"\nSelected operations: {', '.join(operations)}")
                        confirm = input("Confirm? (yes/no): ").strip().lower()
                        if confirm in ['yes', 'y']:
                            return operations
                    break
            else:
                print("Invalid selection. Please enter 1-4.")

    def run(self, target: str, operations: List[str]) -> OSINTReport:
        """Run selected information gathering operations."""
        print(f"\n{'='*60}")
        print(f"INITIATING OSINT INFORMATION GATHERING")
        print(f"Target: {target}")
        print(f"Operations: {', '.join(operations).upper()}")
        print(f"{'='*60}\n")

        # Validate input
        if not self.validate_input(target):
            raise ValueError("Invalid input")

        try:
            # Operation 1: DNS Resolution
            if 'dns' in operations:
                print("[1/3] Performing DNS resolution...")
                dns_result = self._gather_dns_info(target)
                if dns_result:
                    self.report.add_section("DNS RESOLUTION", dns_result)
                    self.report.mark_operation_complete("DNS Resolution")

            # Operation 2: Geolocation
            if 'geo' in operations:
                print("[2/3] Retrieving geolocation data...")
                geo_result = self._gather_geolocation_info(target)
                if geo_result:
                    self.report.add_section("GEOLOCATION", geo_result)
                    self.report.mark_operation_complete("Geolocation")

            # Operation 3: Social Media Search
            if 'social' in operations:
                print("[3/3] Searching social media platforms...")
                social_result = self._gather_social_media_info(target)
                if social_result:
                    self.report.add_section("SOCIAL MEDIA SEARCH", social_result)
                    self.report.mark_operation_complete("Social Media Search")

            # Generate Executive Summary
            print("\n" + "="*60)
            print("GENERATING EXECUTIVE SUMMARY")
            print("="*60)
            self._generate_executive_summary()

            print("\n" + "="*60)
            print("INFORMATION GATHERING COMPLETE")
            print("="*60)

        except Exception as e:
            self.report.add_section("ERROR", f"An error occurred: {str(e)}")
            raise

        return self.report

    def _gather_dns_info(self, target: str) -> str:
        """Gather DNS information."""
        dns_lines = []
        ip_address = DNSResolver.resolve(target)

        if not ip_address:
            dns_lines.append("DNS Resolution: Failed")
            return "\n".join(dns_lines)

        dns_lines.append(f"Hostname/IP: {target}")
        dns_lines.append(f"Resolved IP Address: {ip_address}")

        # Reverse lookup
        hostname = DNSResolver.reverse_lookup(ip_address)
        if hostname:
            dns_lines.append(f"Reverse Lookup: {hostname[0]}")
            dns_lines.append(f"Name Servers: {', '.join(hostname[1])}")

        return "\n".join(dns_lines)

    def _gather_geolocation_info(self, target: str) -> str:
        """Gather geolocation information."""
        geo_lines = []
        ip_address = DNSResolver.resolve(target)

        if not ip_address:
            geo_lines.append("IP Address: Not resolved")
            return "\n".join(geo_lines)

        try:
            geo_data = GeolocationChecker.get_geolocation(ip_address)

            geo_lines.append(f"IP Address: {ip_address}")

            if geo_data.get('hostname'):
                geo_lines.append(f"Hostname: {geo_data['hostname']}")

            if geo_data.get('city'):
                geo_lines.append(f"City: {geo_data['city']}")

            if geo_data.get('region'):
                geo_lines.append(f"Region: {geo_data['region']}")

            if geo_data.get('country'):
                geo_lines.append(f"Country: {geo_data['country']}")

            if geo_data.get('country_code'):
                geo_lines.append(f"Country Code: {geo_data['country_code']}")

            if geo_data.get('postal'):
                geo_lines.append(f"Postal Code: {geo_data['postal']}")

            if geo_data.get('timezone'):
                geo_lines.append(f"Timezone: {geo_data['timezone']}")

            if geo_data.get('loc'):
                loc_parts = geo_data['loc'].split(',')
                if len(loc_parts) >= 2:
                    geo_lines.append(f"Coordinates: Latitude {loc_parts[0].strip()}, Longitude {loc_parts[1].strip()}")

            if geo_data.get('org'):
                geo_lines.append(f"ISP/Org: {geo_data['org']}")

            # Proxy/Data Center Detection
            if GeolocationChecker.is_cloudflare_proxy(geo_data):
                geo_lines.append("Detection: Cloudflare proxy detected")
            elif GeolocationChecker.is_data_center(geo_data):
                geo_lines.append("Detection: Data center IP detected")

            return "\n".join(geo_lines)

        except Exception as e:
            geo_lines.append(f"Error: {str(e)}")
            return "\n".join(geo_lines)

    def _gather_social_media_info(self, target: str) -> str:
        """Gather social media search results."""
        social_lines = []
        found_count = 0

        results = SocialMediaChecker.check_all(target)

        for platform, (found, url) in results.items():
            if found:
                found_count += 1
                social_lines.append(f"✓ {platform}: {url}")
            else:
                social_lines.append(f"✗ {platform}: No results found")

        social_lines.append(f"\nTotal Platforms Checked: {len(results)}")
        social_lines.append(f"Platforms with Results: {found_count}")

        return "\n".join(social_lines)

    def _generate_executive_summary(self):
        """Generate executive summary based on operations run."""
        if not self.report.ran_operations:
            self.report.add_executive_item("No operations completed", "None")
            return

        summary = []

        # Summary of completed operations
        summary.append(f"Operations Completed: {', '.join(self.report.ran_operations).upper()}")

        # Web-based analysis
        if 'dns' in self.report.ran_operations and 'geo' in self.report.ran_operations:
            summary.append("Web-based investigation completed - target network footprint analyzed")
            summary.append("DNS resolution provides IP address and reverse lookup information")
            summary.append("Geolocation data reveals physical location and ISP information")

        # Non-web analysis
        if 'social' in self.report.ran_operations:
            summary.append("Non-web investigation completed - social media footprint assessed")
            summary.append("Social media search across 8 platforms completed")

        # Recommendations based on findings
        summary.append("\nKey Findings:")
        for section in self.report.sections:
            title = section['title']
            content = section['content']

            if 'DNS' in title and 'Resolved IP Address' in content:
                ip_match = re.search(r'IP Address: (\S+)', content)
                if ip_match:
                    summary.append(f"- Target resolved to IP: {ip_match.group(1)}")

            if 'GEOLOCATION' in title and 'City' in content:
                city_match = re.search(r'City: (\S+)', content)
                if city_match:
                    summary.append(f"- Physical location: {city_match.group(1)}")

            if 'GEOLOCATION' in title and 'ISP/Org' in content:
                isp_match = re.search(r'ISP/Org: (.+)', content)
                if isp_match:
                    summary.append(f"- ISP/Provider: {isp_match.group(1)}")

            if 'GEOLOCATION' in title and 'Detection:' in content:
                detection_match = re.search(r'Detection: (.+)', content)
                if detection_match:
                    summary.append(f"- Network type: {detection_match.group(1)}")

            if 'SOCIAL MEDIA' in title and 'Platforms with Results' in content:
                results_match = re.search(r'Platforms with Results: (\d+)', content)
                if results_match:
                    count = int(results_match.group(1))
                    if count > 0:
                        summary.append(f"- Social media presence: {count} platform(s) with results")
                    else:
                        summary.append(f"- Social media presence: No results found")

        # Recommendations
        summary.append("\nRecommendations:")
        summary.append("- Verify all information through multiple sources")
        summary.append("- Cross-reference geolocation data with WHOIS records if available")
        summary.append("- Monitor social media platforms regularly for new activity")
        summary.append("- Use VPN and anonymity tools when conducting OSINT investigations")
        summary.append("- Consider legal compliance when using this information")

        for item in summary:
            self.report.add_executive_item(item)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Unified OSINT Information Gathering Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com -o report.txt
  %(prog)s 192.168.1.1
        """
    )

    parser.add_argument('target', help='Hostname, domain, or IP address to investigate')
    parser.add_argument('-o', '--output', help='Output file path (optional)')
    parser.add_argument('--dns', action='store_true', help='Run DNS resolution only')
    parser.add_argument('--geo', action='store_true', help='Run geolocation only')
    parser.add_argument('--social', action='store_true', help='Run social media search only')
    parser.add_argument('--all', action='store_true', help='Run all operations')

    args = parser.parse_args()

    try:
        tool = UnifiedOSINTTool()

        # Check for command-line operations
        cli_operations = []
        if args.all:
            cli_operations = ['dns', 'geo', 'social']
        elif args.dns:
            cli_operations = ['dns']
        elif args.geo:
            cli_operations = ['geo']
        elif args.social:
            cli_operations = ['social']

        if cli_operations:
            # Use command-line operations
            report = tool.run(args.target, cli_operations)
        else:
            # Interactive mode
            target = tool.get_user_target()
            operations = tool.get_user_operations()
            report = tool.run(target, operations)

        print("\n" + report.render())

        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report.render())
            print(f"\nReport saved to: {args.output}")

    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        exit(1)


if __name__ == "__main__":
    main()