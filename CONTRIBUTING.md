# Contributing to OIDC-Loki

Thank you for your interest in contributing to OIDC-Loki!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/oidc-loki.git`
3. Install dependencies: `npm install`
4. Run tests: `npm test`

## Development

### Prerequisites

- Node.js 22+
- npm

### Commands

```bash
npm run dev        # Start development server with hot reload
npm run build      # Build TypeScript
npm run test       # Run tests in watch mode
npm run test:run   # Run tests once
npm run lint       # Check code style
npm run lint:fix   # Auto-fix code style issues
```

### Project Structure

```
src/
├── admin/           # Hono-based Admin API
├── core/            # Core classes (Loki, MischiefEngine, etc.)
├── ledger/          # Ledger types for audit trail
├── persistence/     # SQLite database layer
├── plugins/         # Mischief plugins
│   ├── built-in/    # Built-in attack plugins
│   └── types.ts     # Plugin interface
└── index.ts         # Library entry point
```

## Contributing Code

### Pull Request Process

1. Create a feature branch: `git checkout -b feature/my-feature`
2. Make your changes
3. Ensure tests pass: `npm run test:run`
4. Ensure linting passes: `npm run lint`
5. Commit with a descriptive message
6. Push and open a Pull Request

### Commit Messages

Use clear, descriptive commit messages:

```
feat: add new mischief plugin for audience injection
fix: handle empty JWKS response in key-confusion plugin
docs: update testing guide with new examples
test: add tests for shuffled session mode
```

### Code Style

We use [Biome](https://biomejs.dev/) for linting and formatting. Run `npm run lint:fix` before committing.

## Contributing Plugins

New mischief plugins are welcome! See [Plugin Development Guide](./docs/plugin-development.md).

Good plugin contributions:
- Test real-world OIDC/OAuth2 attack vectors
- Reference relevant RFCs, OIDC specs, or CWEs
- Include appropriate severity level
- Have clear evidence in the ledger

## Reporting Issues

### Bug Reports

Include:
- Node.js version
- Steps to reproduce
- Expected vs actual behavior
- Relevant logs or error messages

### Feature Requests

Describe:
- The use case
- Why existing features don't address it
- Proposed solution (if any)

## Code of Conduct

Be respectful and constructive. This is a security tool - we take responsible disclosure seriously.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
