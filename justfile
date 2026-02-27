# empirical-security-slack — project commands
# Run `just` or `just --list` to see available commands

# Install dependencies
install-deps:
    npm install

# Install from lockfile (reproducible, same as CI)
ci-install:
    npm ci

# Run npm audit for security vulnerabilities (fails on high/critical)
audit:
    npm audit --audit-level=high

# Run audit with fix suggestions (modifies package.json/package-lock.json)
audit-fix:
    npm audit fix

# Check for outdated packages
outdated:
    npm outdated

# Run all CI checks locally (ci-install + audit)
ci: ci-install audit

# Start the app in development mode with watch
dev:
    npm run dev

# Start the app
start:
    npm start
