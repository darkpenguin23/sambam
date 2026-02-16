#!/bin/bash
set -e

# Quick release helper - bump version, commit, tag, and release
# Usage: ./quick-release.sh "1.2.10" "- Feature A\n- Bug fix B"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION="$1"
CHANGELOG="$2"

if [ -z "$VERSION" ]; then
    echo "Quick Release Helper"
    echo ""
    echo "Usage: ./quick-release.sh <version> [changelog]"
    echo ""
    echo "Example:"
    echo "  ./quick-release.sh 1.2.10"
    echo "  ./quick-release.sh 1.2.10 \"- New feature\n- Bug fix\""
    echo ""
    echo "This script will:"
    echo "  1. Update version in main.go"
    echo "  2. Commit changes"
    echo "  3. Create git tag"
    echo "  4. Push to remote"
    echo "  5. Build and release all packages/binaries"
    exit 1
fi

echo "═══════════════════════════════════════════════════════════════════"
echo "Quick Release: v$VERSION"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Step 1: Update version in main.go
echo "▶ Updating version to $VERSION..."
sed -i 's/version = "[^"]*"/version = "'$VERSION'"/' main.go
echo "✓ Version updated in main.go"

# Step 2: Commit
echo "▶ Committing changes..."
git add main.go
git commit -m "v$VERSION: Release version bump"
echo "✓ Changes committed"

# Step 3: Tag
echo "▶ Creating git tag v$VERSION..."
git tag "v$VERSION"
echo "✓ Tag created"

# Step 4: Push
echo "▶ Pushing to remote..."
git push origin master --tags
echo "✓ Pushed to remote"

# Step 5: Release
echo "▶ Building and releasing..."
echo ""
"$SCRIPT_DIR/release.sh" "$VERSION" "$CHANGELOG"
