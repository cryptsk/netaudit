# Contributing to NetAudit

Thank you for your interest in contributing to NetAudit! This document provides guidelines and instructions for contributing.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Bugs

1. Check if the bug has already been reported in [Issues](https://github.com/cryptsk/netaudit/issues)
2. If not, create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected vs actual behavior
   - System information (OS, Python version)

### Suggesting Features

1. Open an issue with the "enhancement" label
2. Describe the feature and its use case
3. Explain why it would benefit the project

### Submitting Changes

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes
4. Test your changes thoroughly
5. Commit with clear messages (`git commit -m 'Add amazing feature'`)
6. Push to your branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/netaudit.git
cd netaudit

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r netaudit/requirements.txt

# Run tests
python -m pytest
```

## Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Write docstrings for functions and classes
- Keep functions focused and modular

## Security

- Never introduce code that modifies system configurations
- Always validate and sanitize inputs
- Use safe subprocess execution (no `shell=True`)
- Report security vulnerabilities to info@cryptsk.com

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**CRYPTSK Pvt Ltd**
https://cryptsk.com
