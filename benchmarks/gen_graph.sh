#!/usr/bin/env bash
set -e

# Get the directory where this script is located
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

echo "⚙️ Setting up D3.js environment..."
cd "$DIR/assets"

# Install node modules if they don't exist
if [ ! -d "node_modules" ]; then
    npm install
fi

echo "📊 Generating standard benchmark graphs (BENCHMARKS.md)..."
node gen.js

echo "📈 Generating compact README graph..."
node gen_readme.js

echo "✨ All SVGs generated successfully in benchmarks/assets/"
