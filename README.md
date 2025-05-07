 VulnScout

An advanced vulnerability assessment tool with intelligent scanning, advanced visualization, and detailed reporting capabilities.

```
__      __      _       _____                 _   
\ \    / /     | |     / ____|               | |  
 \ \  / /   _  | |_ __| (___   ___ ___  _   _| |_ 
  \ \/ / | | | | | '_ \\___ \ / __/ _ \| | | | __|
   \  /| |_| | | | | | |___) | (_| (_) | |_| | |_ 
    \/  \__,_| |_|_| |_|____/ \___\___/ \__,_|\__| v1.0.0
                                                 
Advanced Vulnerability Assessment Tool
```

 Features

- **Intelligent vulnerability scanning** with customizable Nmap scripts
- Supports both **built-in and custom scripts**
- **Advanced reporting** in multiple formats (PDF, HTML, Markdown, JSON, XML, CSV)
- **Interactive terminal UI** with progress tracking using Rich
- **Beautiful, organized reports** with visualizations
- **API integration** with popular security databases
- **Network topology** and vulnerability visualization
- **Nikto web server scanning** integration for comprehensive web application security assessment
- **False positive reduction** through correlation and empirical validation

# Prerequisites

- Python 3.7+
- Nmap (must be installed and in PATH)
- Nikto (optional, for web scanning)

# Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vulnscout.git
cd vulnscout
```

2. Install the required dependencies:
```bash
pip install -r requirements.txt
```

3. (Optional) Create a `.env` file for your API keys:
```
SHODAN_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

## Usage

Basic scan of a target:
```bash
python final.py --target 192.168.1.1
```

Scan with a predefined template:
```bash
python final.py --target example.com --template thorough
```

Scan multiple targets from a file:
```bash
python final.py --targets-file targets.txt --report-formats html,pdf,json
```

Enable Nikto web scanning:
```bash
python final.py --target example.com --nikto
```

## Templates

VulnScout comes with predefined scan templates:

- **quick**: Fast scan of common ports and vulnerabilities
- **thorough**: Comprehensive scan with extensive vulnerability checks
- **web**: Focused on web application security
- **stealth**: Low-visibility scan that minimizes detection

## Command Line Options

```
--target            Target to scan (hostname or IP address)
--targets-file      File containing multiple targets (one per line)
--ports             Ports to scan (comma-separated list or ranges)
--scripts           Nmap scripts to use
--timeout           Scan timeout in seconds
--template          Use predefined scan template
--output-dir        Directory to save scan results and reports
--report-formats    Report formats to generate (html,pdf,md,json,xml,csv)
--nikto             Enable Nikto web scanning
--visualize         Generate security visualizations
--debug             Enable debug logging
```

## Dependencies

Core dependencies:
- numpy
- matplotlib
- seaborn
- rich
- weasyprint
- reportlab
- pyvis
- networkx
- requests
- python-dotenv
- plotly
- geoip2 (optional)

## Output Structure

Scan results are saved in the `scan_results` directory by default with the following structure:

```
scan_results/
├── html/
│   └── scan_192.168.1.1_20240510_120000.html
├── pdf/
│   └── scan_192.168.1.1_20240510_120000.pdf
├── json/
│   └── scan_192.168.1.1_20240510_120000.json
└── nikto_results/
    └── scan_192.168.1.1_80_20240510_120000.txt
```

## File Structure

- **final.py**: The main application file
- **requirements.txt**: List of dependencies
- **templates/**: HTML and report templates
- **scripts/**: Custom Nmap and scanning scripts

 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

 License

This project is licensed under the MIT License - see the LICENSE file for details.

 Authors

- Desmond
- Simran
- Kelvin

Additional Files 

Here are the additional files you should include in your GitHub repository:

1. **requirements.txt**
```
numpy
pandas
matplotlib
seaborn
rich
weasyprint
plotly
pyvis
networkx
requests
python-dotenv
reportlab
geoip2
socketio
pillow
openssl
```

2. .gitignore
```
# Byte-compiled / optimized / DLL files
__pycache__/
*.py[cod]
*$py.class

# Distribution / packaging
dist/
build/
*.egg-info/

# Environments
.env
.venv
env/
venv/
ENV/

# Scan results
scan_results/
nikto_results/

# Logs
*.log

# Local configuration
.DS_Store
.idea/
.vscode/
*.swp
```

3. LICENSE (MIT License)
```
MIT License

Copyright (c) 2024 VulnScout Authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

