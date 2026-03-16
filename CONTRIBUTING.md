# Contributing to CyberGuardian

Thank you for your interest in contributing to CyberGuardian! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Coding Standards](#coding-standards)
- [Commit Guidelines](#commit-guidelines)
- [Pull Request Process](#pull-request-process)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please be considerate of others and follow standard open-source community guidelines.

---

## Getting Started

1. Fork the repository on GitHub
2. Clone your fork locally
3. Create a new branch for your changes
4. Make your contributions
5. Submit a pull request

---

## Development Setup

### Prerequisites

- Python 3.9 or higher
- Git
- Windows 10/11 (for full functionality testing)

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/Souhaieb-Marzouk/CyberGuardian.git
cd cyberguardian

# Create virtual environment
python -m venv venv
venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Run the application
python main.py
```

### Run Tests

```bash
# Run all tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/
```

---

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Create a new issue with:
   - Clear description of the bug
   - Steps to reproduce
   - Expected behavior
   - Actual behavior
   - System information (Windows version, Python version)
   - Screenshots if applicable

### Suggesting Features

1. Check existing issues for similar suggestions
2. Create a new issue with:
   - Clear description of the feature
   - Use case and benefits
   - Possible implementation approach

---

## Commit Guidelines

### Commit Message Format

```
type(scope): subject

body (optional)

footer (optional)
```

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Examples

```
feat(scanner): add deep analysis mode for process scanning

- Windows Event Log analysis
- PowerShell history analysis
- DNS cache inspection

Closes #123
```

```
fix(ai): handle empty API response gracefully

Fixes crash when AI provider returns empty content.
```

---

## Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Follow coding standards
   - Add tests for new functionality
   - Update documentation

3. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: description of your changes"
   ```

4. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

5. **Create Pull Request**
   - Go to the original repository
   - Click "New Pull Request"
   - Select your branch
   - Fill in the PR template

6. **PR Requirements**
   - All tests pass
   - Code follows style guidelines
   - Documentation updated
   - No merge conflicts

7. **Review Process**
   - Maintainers will review your PR
   - Address any feedback
   - Once approved, it will be merged

---

## Project Structure

See [README.md](README.md) for the complete project structure.

Key directories:
- `scanners/` - Detection engines
- `ai_analysis/` - AI integration
- `ui/` - User interface
- `utils/` - Utility functions
- `tests/` - Test files

---

## Getting Help

- Open an issue for questions
- Check existing documentation
- Review closed issues for solutions

---

Thank you for contributing to CyberGuardian!
