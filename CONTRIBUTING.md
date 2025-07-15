# Contributing to BypassCore SDK

Thank you for your interest in contributing to the BypassCore SDK!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/bypasscore-sdk.git`
3. Create a feature branch: `git checkout -b feature/my-feature`
4. Make your changes
5. Run tests: `cmake --build build && ctest --test-dir build`
6. Commit: `git commit -m "Add my feature"`
7. Push: `git push origin feature/my-feature`
8. Open a Pull Request

## Development Setup

### Prerequisites

- CMake 3.14+
- C++17 compiler (MSVC 2019+, GCC 9+, Clang 10+)
- Windows SDK (for Windows-specific features)
- Python 3.7+ and pybind11 (for Python bindings, optional)

### Building

```bash
cmake -B build -DBYPASSCORE_BUILD_TESTS=ON
cmake --build build
ctest --test-dir build
```

## Code Style

- Use `clang-format` with the project's `.clang-format` (if present)
- Prefer `snake_case` for functions and variables
- Prefer `PascalCase` for types and classes
- Use `SCREAMING_SNAKE_CASE` for macros
- All public APIs must have Doxygen-style documentation

## Pull Request Guidelines

- Keep PRs focused on a single change
- Include tests for new features
- Update documentation if behavior changes
- Ensure CI passes before requesting review

## Commit Messages

Use conventional commit style:
- `feat: add new feature`
- `fix: correct bug in scanner`
- `docs: update API reference`
- `test: add hook engine tests`
- `perf: optimize pattern scanning`

## Code of Conduct

Be respectful, constructive, and professional. We are building tools for
security research and education, and we expect contributors to act responsibly.
