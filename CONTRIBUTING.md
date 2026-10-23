[← Back to README](README.md)

# Contributing

### You Could Be Here!

We welcome contributions of all kinds - code, documentation, bug reports, feature ideas, or testing.

### How to Contribute

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Contribution Ideas

| Area | Ideas |
|------|-------|
| **Bug Fixes** | Stability improvements, edge case handling |
| **Documentation** | Tutorials, examples, API documentation |
| **UI/UX** | Interface improvements, accessibility |
| **Integrations** | Additional SIEM platforms, ticketing systems |
| **Emulation Plans** | New threat actor TTPs |
| **Linux Agent** | Port agent functionality to Linux |
| **macOS Agent** | Port agent functionality to macOS |
| **Detection** | Additional rule sources, rule validation |

### Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/redteamsimmer.git
cd redteamsimmer

# Create development branch
git checkout -b feature/your-feature

# Install dev dependencies
pip install -r requirements-dev.txt

# Run tests
python -m pytest tests/

# Run linting
flake8 app.py
```

### Code Style

- Python: Follow PEP 8
- Go: Run `go fmt` before committing
- JavaScript: Use consistent indentation (2 spaces)
- HTML: Use consistent indentation (2 spaces)
