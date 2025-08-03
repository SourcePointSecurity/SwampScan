# Contributing to SwampScan

We welcome contributions from the security community! SwampScan thrives on collaboration and shared expertise.

## 🚀 Getting Started

### Development Setup

```bash
# Fork the repository on GitHub
git clone https://github.com/yourusername/SwampScan.git
cd SwampScan

# Create development environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -e .[dev]

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/

# Run linting
flake8 src/
black src/
mypy src/
```

## 📋 Contribution Guidelines

### Code Quality Standards

- Follow PEP 8 style guidelines
- Maintain test coverage above 90%
- Include comprehensive docstrings
- Use type hints for all functions
- Write clear, descriptive commit messages

### Testing Requirements

```bash
# Run full test suite
pytest tests/ --cov=swampscan --cov-report=html

# Run specific test categories
pytest tests/unit/          # Unit tests
pytest tests/integration/   # Integration tests
pytest tests/performance/   # Performance tests

# Run security tests
pytest tests/security/ --strict
```

### Documentation Standards

- Update README.md for new features
- Include docstring examples for public APIs
- Add usage examples for new functionality
- Update configuration documentation

## 🐛 Reporting Issues

### Bug Reports

When reporting bugs, please include:

- SwampScan version and Python version
- Complete error messages and stack traces
- Steps to reproduce the issue
- Operating system and environment details
- Relevant log files (sanitized)

### Feature Requests

For feature requests, please provide:

- Description of the use case and business value
- Examples of desired functionality
- Backward compatibility considerations
- Suggested implementation approaches

### Security Issues

- Report security vulnerabilities privately to security@sourcepointsecurity.com
- Include proof of concept if applicable
- Allow reasonable time for response before public disclosure
- Follow responsible disclosure practices

## 🔄 Pull Request Process

1. **Fork the repository** and create your feature branch from `main`
2. **Write tests** for your changes and ensure all tests pass
3. **Update documentation** as needed
4. **Run linting** and fix any issues
5. **Submit a pull request** with a clear description of changes

### Pull Request Checklist

- [ ] Tests pass locally
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Changelog updated (if applicable)
- [ ] No merge conflicts
- [ ] Descriptive commit messages

## 🏗️ Development Workflow

### Branch Naming

- `feature/description` - New features
- `bugfix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring

### Commit Messages

Follow conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Examples:
- `feat(scanner): add support for custom port ranges`
- `fix(cli): resolve argument parsing issue`
- `docs(readme): update installation instructions`

## 🧪 Testing

### Test Categories

- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test component interactions
- **Performance Tests**: Validate performance requirements
- **Security Tests**: Verify security controls

### Writing Tests

```python
import pytest
from swampscan import quick_scan

def test_quick_scan_basic():
    """Test basic quick scan functionality."""
    result = quick_scan("127.0.0.1", "22")
    assert result is not None
    assert hasattr(result, 'vulnerabilities')

@pytest.mark.integration
def test_openvas_integration():
    """Test OpenVAS integration."""
    # Integration test implementation
    pass

@pytest.mark.performance
def test_large_network_scan():
    """Test performance with large networks."""
    # Performance test implementation
    pass
```

## 📚 Documentation

### Code Documentation

- Use clear, descriptive docstrings
- Include parameter types and return values
- Provide usage examples
- Document exceptions that may be raised

```python
def scan_network(network: str, ports: str = "top100") -> ScanResult:
    """
    Perform a vulnerability scan on a network range.
    
    Args:
        network: Network in CIDR notation (e.g., "192.168.1.0/24")
        ports: Port specification (default: top100)
        
    Returns:
        ScanResult object with findings
        
    Raises:
        ValueError: If network format is invalid
        ConnectionError: If OpenVAS is not accessible
        
    Example:
        >>> result = scan_network("192.168.1.0/24", "ssh,web")
        >>> print(f"Scanned {result.targets_scanned} targets")
    """
```

### README Updates

When adding new features:

- Update the feature list
- Add usage examples
- Update command reference
- Include configuration options

## 🌟 Recognition

Contributors will be recognized in:

- GitHub contributors list
- Release notes
- Project documentation
- Annual contributor acknowledgments

## 📞 Getting Help

- 💬 [GitHub Discussions](https://github.com/SourcePointSecurity/SwampScan/discussions)
- 🐛 [Issue Tracker](https://github.com/SourcePointSecurity/SwampScan/issues)
- 📧 [Email Support](mailto:support@sourcepointsecurity.com)

## 📄 License

By contributing to SwampScan, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to SwampScan! Together, we're making the internet more secure. 🐊🔒

