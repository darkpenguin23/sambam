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
    echo "  1. Check git state is clean"
    echo "  2. Update version in main.go"
    echo "  3. Commit changes"
    echo "  4. Create git tag"
    echo "  5. Push to remote"
    echo "  6. Build and release all packages/binaries"
    exit 1
fi

error() {
    echo "✗ ERROR: $1" >&2
    exit 1
}

echo "═══════════════════════════════════════════════════════════════════"
echo "Quick Release: v$VERSION"
echo "═══════════════════════════════════════════════════════════════════"
echo ""

# Step 0: Check git state is clean
echo "▶ Checking git state..."
if ! git diff-index --quiet HEAD --; then
    git status
    error "Git working directory is dirty. Please commit all changes first."
fi
echo "✓ Git state is clean"

# Step 1: Update version in main.go
echo "▶ Updating version to $VERSION..."
sed -i 's/version = "[^"]*"/version = "'$VERSION'"/' main.go
echo "✓ Version updated in main.go"

# Step 2: Commit
echo "▶ Committing changes..."
git add main.go
git commit -m "v$VERSION: Release version bump"
echo "✓ Changes committed"

# Step 3: Tag (on the commit we just created)
echo "▶ Creating git tag v$VERSION..."
git tag "v$VERSION"
echo "✓ Tag created on current commit"

# Step 4: Push to all remotes (ensure tag is on same commit before release)
echo "▶ Pushing to remotes..."
git push origin master --tags 2>&1 | grep -v "rejected" || true
git push github master --tags 2>&1 | grep -v "rejected" || true
echo "✓ Pushed to remotes"

# Final check: Ensure clean state before release
echo "▶ Final validation before release..."
if ! git diff-index --quiet HEAD --; then
    error "Git state became dirty during commit/tag process"
fi
echo "✓ Ready for release build"

# Step 5: Release
echo ""
"$SCRIPT_DIR/release.sh" "$VERSION" "$CHANGELOG"
