# NetAudit

**Linux Network Infrastructure Security Audit Tool**

A lightweight, read-only security auditing tool for Linux systems. NetAudit analyzes system configurations and produces structured risk reports with actionable recommendations.

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-3776AB.svg?style=flat&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=flat)](LICENSE)
[![Linux](https://img.shields.io/badge/Platform-Linux-FCC624.svg?style=flat&logo=linux&logoColor=black)](https://www.linux.org/)

---

## Features

- **Kernel Auditing** - Sysctl parameters, TCP/IP stack hardening
- **Firewall Analysis** - iptables/nftables/ufw configuration checks
- **Network Security** - Interface configuration, listening ports
- **System Hardening** - SSH, fail2ban, password policies
- **Scored Reports** - 0-100 scoring with letter grades
- **Multiple Formats** - CLI output, JSON export, Web dashboard
- **Safe Execution** - Read-only, no `shell=True`, input sanitization

---

## Quick Start

### Requirements

- Linux operating system
- Python 3.11 or higher
- Root/sudo (recommended for complete audit)

### Installation

```bash
# Clone the repository
git clone https://github.com/cryptsk/netaudit.git
cd netaudit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r netaudit/requirements.txt
```

---

## Usage

### Command Line

```bash
# Run security audit
python -m netaudit.cli.main scan

# JSON output
python -m netaudit.cli.main scan --json

# Save to file
python -m netaudit.cli.main scan -o report.json

# Quick score check
python -m netaudit.cli.main score

# Audit specific category
python -m netaudit.cli.main check firewall
python -m netaudit.cli.main check security
python -m netaudit.cli.main check network
python -m netaudit.cli.main check sysctl
```

### Web Dashboard

```bash
# Start API server
python -m netaudit.api.main

# API runs on http://localhost:3031
```

For the web dashboard, navigate to the `web-dashboard` directory:

```bash
cd web-dashboard
npm install
npm run dev
# Dashboard runs on http://localhost:3000
```

---

## What It Checks

### Sysctl Parameters
- IP forwarding
- ICMP redirects
- Source routing
- SYN cookies
- TCP buffers
- Connection tracking

### Firewall
- Active firewall detection
- Default policies
- INPUT chain rules
- nftables/iptables/ufw status

### Network
- MTU consistency
- NIC offloading
- IRQ balancing
- Listening ports
- DNS configuration

### Security
- SSH configuration
- fail2ban status
- Password policies
- World-writable files
- Sudo configuration

---

## Scoring

| Score | Grade | Status |
|-------|-------|--------|
| 90-100 | A | Excellent |
| 80-89 | B | Good |
| 70-79 | C | Fair |
| 60-69 | D | Poor |
| 0-59 | F | Critical |

**Weights:**
- Firewall: 30%
- Security: 30%
- Sysctl: 25%
- Network: 15%

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/scan` | GET | Run full audit |
| `/api/score` | GET | Get score only |
| `/api/categories` | GET | Category breakdown |
| `/api/findings` | GET | All findings |
| `/api/recommendations` | GET | Action items |
| `/api/export/json` | GET | Download report |

API documentation available at `http://localhost:3031/docs`

---

## Project Structure

```
netaudit/
├── netaudit/                 # Python package
│   ├── core/                 # Core audit modules
│   │   ├── collectors.py     # System data collection
│   │   ├── sysctl_checks.py  # Kernel parameter checks
│   │   ├── firewall_checks.py# Firewall checks
│   │   ├── network_checks.py # Network checks
│   │   ├── security_checks.py# Security checks
│   │   └── scoring_engine.py # Score calculation
│   ├── cli/                  # Command-line interface
│   │   └── main.py
│   ├── api/                  # FastAPI server
│   │   └── main.py
│   └── requirements.txt
├── web-dashboard/            # Next.js web dashboard
│   ├── src/
│   ├── public/
│   └── package.json
├── assets/                   # Logo and images
├── README.md
└── LICENSE
```

---

## Security

NetAudit follows security best practices:

- **Read-only** - Never modifies system configuration
- **Safe execution** - No `shell=True` in subprocess calls
- **Input validation** - All inputs sanitized
- **Local binding** - API only accessible on localhost
- **No privilege escalation** - Runs with current user permissions

---

## Contributing

Contributions welcome. Please read our contributing guidelines before submitting PRs.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit pull request

---

## License

MIT License - see [LICENSE](LICENSE) file.

---

## Support

- **Issues:** [GitHub Issues](https://github.com/cryptsk/netaudit/issues)
- **Email:** info@cryptsk.com
- **Website:** https://cryptsk.com

---

## Author

**CRYPTSK Pvt Ltd**

Made with care for the Linux security community.
