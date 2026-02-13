# OSINT Investigations
## Security Learnings from an old fart

### 👋 Welcome
Hello and welcome to my OSINT Security Repo. The purpose of this repository is to share my experience and resources back to the community. This community has been amazing to me, and the only thing I can do is to give back my experiences and the things I've garnered over the years.

TLDR: This community has been amazing, and below are tips, tricks, and resources to aid you in your mission.

---

# Unified OSINT Information Gathering Tool

A comprehensive, modular Python tool for gathering publicly available information from the internet. This tool allows users to perform targeted OSINT investigations with flexible operation selection and automatic executive summary generation.

## 🎯 Features

### User-Friendly Interface
- Interactive menu system for easy operation selection
- Command-line support for automation and scripting
- Input validation and error handling

### Operation Types

#### 1. Web-Based Investigation
- **DNS Resolution**: Resolves hostnames/domains to IP addresses with reverse lookup
- **Geolocation**: Retrieves geographic location, ISP information, and network type
- Detects Cloudflare proxies and data center IPs
- Provides coordinates, timezone, and postal information

#### 2. Non-Web Investigation
- **Social Media Search**: Checks 8 major platforms for public presence
  - Facebook
  - X (Twitter)
  - Instagram
  - LinkedIn
  - YouTube
  - Pinterest
  - TikTok
  - Reddit

### Executive Summary Generation
- Automatically generates targeted summaries based on operations run
- Extracts key findings from DNS, geolocation, and social media results
- Provides actionable recommendations
- Saves detailed reports to files

### Privacy Considerations
- Uses user-agent headers to mimic legitimate browser traffic
- Configurable timeouts to avoid detection
- Legal compliance warnings included

## 📋 Contents of this Repo

### Data Sources

- **[SECurities and Exchange Commission](https://www.SEC.gov)** - Company and financial information

### Data Brokers

- **[Beenverified](https://www.beenverified.com)** - Public records aggregator
- **[Whitepages](https://www.whitepages.com)** - Contact information and public records
- **[Spokeo](https://www.spokeo.com)** - People search and background checks
- **[Fastpeoplesearch](https://www.fastpeoplesearch.com)** - Quick people searches
- **[Truepeoplesearch](https://www.truepeoplesearch.com)** - Free people search engine
- **[Intelius](https://www.intelius.com)** - Background checks and public records
- **[Instantcheckmate](https://www.instantcheckmate.com)** - Criminal and background checks
- **[Peoplefinders](https://www.peoplefinders.com)** - People search services
- **[Pipl](https://www.pipl.com)** - People search with deep web results

*Note: Many of these data brokers have a free tier, but subscriptions provide access to more information.*

### Local Data Sources

- **Local Tax Database** - Property ownership information (public records)
- **Local Criminal Database** - Recent mug shots and arrest records
- **Local Court Database** - Court case information

*Note: Many municipal databases are not indexed by Google and must be accessed directly through the municipality's website.*

### Web Tools

- **[Whatsmyip.org](https//www.Whatsmyip.org)** - IP information
- **[MXToolbox](https://mxtoolbox.com/)** - DNS and network diagnostics
- **[Shodan](https://www.shodan.io/)** - Internet-connected device search
- **[Censys](https://www.censys.io/)** - Internet scanning and analysis
- **[Whois](https://www.whois.com/)** - Domain registration information
- **[DNS Dumpster](https://www.dnsdumpster.com/)** - DNS visualization
- **[DNS Lytics](https://www.dnslytics.com/)** - DNS analytics
- **[DNS Stuff](https://www.dnsstuff.com/)** - DNS tools and diagnostics
- **[DNS Checker](https://www.dnschecker.org/)** - DNS propagation checker
- **[DNS Queries](https://www.dnsqueries.com/en/)** - DNS diagnostic tools

### Custom Tools

- **[OSINTUX](https://www.osintux.org/descargas)** - OSINT Linux distribution
- **[OSINT OS List](https://pentestit.com/operating-systems-open-source-intelligence-osint-list/)** - Collection of OSINT operating systems

### Commercial Investigative Software

- **[Maltego](https://www.maltego.com/)** - Link analysis and data visualization tool

### Tips & Tricks

#### Google Dorks

- `site:example.com` - Search within a specific site
- `filetype:pdf` - Search for PDF files
- `intitle:` - Search for specific titles
- `inurl:` - Search for specific URLs
- `intext:` - Search for specific text
- `cache:` - View cached pages
- `link:` - Find pages linking to a site
- `related:` - Find related sites
- `info:` - Get site information
- `allintitle:` - Search multiple titles
- `allinurl:` - Search multiple URLs
- `allintext:` - Search multiple text snippets
- `inanchor:` - Search for specific link text
- `define:` - Search for definitions
- `stocks:` - Stock information
- `map:` - Map searches
- `movie:` - Movie information
- `weather:` - Weather forecasts
- `site:.gov` - Government sites only
- `site:.edu` - Educational sites only

#### Steps in an Investigation

1. Gather information about the target
2. Gather information about the target's assets
3. Gather information about the target's associates
4. Gather information about the target's associates' assets
5. Gather information about the target's associates' associates
6. Gather information about the target's associates' associates' assets...

*You get the picture.*

#### Real Estate

*Note: Real Estate data may be old or inaccurate. Always verify information.*

- **[Zillow](https://www.zillow.com)** - Property listings and information
- **[Trulia](https://www.trulia.com)** - Real estate search
- **[Realtor.com](https://www.realtor.com)** - Official real estate listings
- **[Redfin](https://www.redfin.com)** - Real estate brokerage services
- **[Homes.com](https://www.homes.com)** - Property listings
- **[Remax](https://www.remax.com)** - Real estate services
- **[Century21](https://www.century21.com)** - Real estate franchise
- **[Coldwell Banker](https://www.coldwellbanker.com)** - Real estate brokerage
- **[Sotheby's](https://www.sothebysrealty.com)** - Luxury real estate
- **[Keller Williams](https://www.kw.com)** - Real estate franchise
- **[Loopnet](https://www.loopnet.com)** - Commercial real estate
- **[Landwatch](https://www.landwatch.com)** - Land and property listings

---

# 🚀 Getting Started with Unified OSINT Tool

## Requirements

- **Python Version**: 3.7 or higher
- **Required Libraries**:
  ```bash
  pip install requests whois
  ```
- **Optional Libraries** (for enhanced features):
  ```bash
  pip install ipinfo
  ```

## Installation

1. Clone or download the repository:
   ```bash
   git clone <repository-url>
   cd OSINT_Investigations
   ```

2. Install dependencies:
   ```bash
   pip install requests whois
   ```

3. Make the script executable (Linux/macOS):
   ```bash
   chmod +x UnifiedOSINT.py
   ```

## Usage

### Interactive Mode

Run the script without arguments to use the interactive menu:

```bash
python UnifiedOSINT.py
```

This will prompt you to:
1. Enter your target (hostname, domain, IP, or username)
2. Select the type of investigation you want to perform

### Command-Line Mode

Specify target and operation flags:

```bash
python UnifiedOSINT.py <target> [options]
```

#### Command-Line Options

- `-o, --output FILE` - Save report to file
- `--dns` - Run DNS resolution only
- `--geo` - Run geolocation only
- `--social` - Run social media search only
- `--all` - Run all operations (default)

#### Examples

```bash
# Run all operations for example.com
python UnifiedOSINT.py example.com --all

# Geolocation only
python UnifiedOSINT.py 192.168.1.1 --geo

# Social media search only
python UnifiedOSINT.py username --social

# Custom operations with output file
python UnifiedOSINT.py target --dns --social -o report.txt

# Quick DNS check
python UnifiedOSINT.py domain.com --dns
```

## 📊 Output Format

The tool generates structured reports with the following sections:

### Detailed Sections
- **DNS RESOLUTION**: IP addresses, reverse lookup results, name servers
- **GEOLOCATION**: City, country, region, ISP, coordinates, network type
- **SOCIAL MEDIA SEARCH**: Results from 8 platforms with URLs

### Executive Summary
- Operations completed
- Key findings (IP, location, ISP, social media presence)
- Contextual recommendations

## 🔄 Workflow

### Interactive Workflow
```
1. Select Operation Type
   ├─ Web-based (DNS + Geo)
   ├─ Non-web (Social Media)
   ├─ Run All
   └─ Custom Selection

2. Enter Target
   ├─ Hostname: example.com
   ├─ Domain: mysite.net
   ├─ IP: 192.168.1.1
   └─ Username: john_doe

3. Tool Processes Selected Operations
4. Generates Executive Summary
5. Saves Report (if requested)
```

### Command-Line Workflow
```
python UnifiedOSINT.py target --options
    ↓
Process specified operations
    ↓
Generate report
    ↓
Display and save (if -o flag used)
```

## 💡 Examples

### Example 1: Web-Based Investigation
```bash
python UnifiedOSINT.py example.com --all
```

**Output includes:**
- Target resolved to IP: 93.184.216.34
- Physical location: New York, NY, USA
- ISP/Provider: Example Networks
- Network type: Cloudflare proxy detected
- Social media presence: 3 platform(s) with results

### Example 2: Social Media Search
```bash
python UnifiedOSINT.py username --social
```

**Output includes:**
- ✓ Facebook: https://www.facebook.com/search/people/?q=username
- ✓ X (Twitter): https://x.com/search?q=username&src=typed_query
- ✓ Instagram: https://www.instagram.com/explore/tags/username
- ✓ LinkedIn: https://www.linkedin.com/search/results/all/?keywords=username
- ... (and more)
- Social media presence: 4 platform(s) with results

### Example 3: Automated Reporting
```bash
python UnifiedOSINT.py target --geo --social -o investigation_$(date +%Y%m%d).txt
```

This creates a timestamped report file.

## ⚠️ Security and Legal Considerations

### Important Warnings

1. **Legality**: Only gather information from publicly available sources. Unauthorized access to private data is illegal.

2. **Ethical Use**: Use this tool responsibly and for legitimate purposes only.

3. **Privacy**: Respect individual privacy and comply with applicable laws.

4. **Verification**: Always verify information through multiple sources before taking action.

5. **Anonymity**: Use VPN and anonymity tools when conducting OSINT investigations.

### Recommended Practices

- Only investigate targets you have permission to examine
- Keep detailed records of your investigation methodology
- Cross-reference all findings
- Use the information for legitimate security research, due diligence, or authorized investigations

### Social Media Usage
*Note - Social Media is a great way to gather information about a target. However, it is also a great way to get caught. If you are going to use social media, make sure you are using a VPN and a browser that does not have any of your personal information in it. Also, make sure you aren't logged in to any of your personal accounts.*

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| "DNS resolution error" | Check if the target is accessible and spelling is correct |
| "Geolocation API error" | Ensure internet connection is active |
| "No results found on social media" | The target may not have a public presence. Try with different variations of the target name. |
| "Module not found: requests/whois" | Install required dependencies: `pip install requests whois` |

## 🏗️ Technical Details

### Architecture
- **Modular Design**: Separate classes for DNS, geolocation, social media, and reporting
- **Type Hints**: Full type annotations for better code clarity
- **Error Handling**: Comprehensive error handling and validation

### Classes
- `OSINTReport` - Handles report generation and formatting
- `DNSResolver` - Performs DNS resolution and reverse lookups
- `GeolocationChecker` - Retrieves and analyzes geolocation data
- `SocialMediaChecker` - Searches social media platforms
- `UnifiedOSINTTool` - Main orchestrator with user interaction

### Timeout Configuration
- DNS/Geolocation: 10 seconds
- Social Media: 5 seconds per platform

## 📞 Contact

For questions, issues, or suggestions, please open an issue on the repository.

---

**Last Updated**: 2026-02-13
**Version**: 1.0.0