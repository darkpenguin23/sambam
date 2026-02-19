#!/bin/bash
set -e

# Quick release helper - bump version, commit, tag, and release
# Usage: ./quick-release.sh <version> [changelog] [--gitlab|--github|--both]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

VERSION="$1"
CHANGELOG="$2"

if [ -z "$VERSION" ]; then
    echo "Quick Release Helper"
    echo ""
    echo "Usage: ./quick-release.sh <version> [changelog] [--gitlab|--github|--both]"
    echo ""
    echo "Targets (default: --both):"
    echo "  --gitlab   Push and release to GitLab only"
    echo "  --github   Push and release to GitHub only"
    echo "  --both     Push and release to both (default)"
    echo ""
    echo "Examples:"
    echo "  ./quick-release.sh 1.2.10"
    echo "  ./quick-release.sh 1.2.10 \"- New feature\n- Bug fix\""
    echo "  ./quick-release.sh 1.2.10 \"- New feature\" --gitlab"
    echo ""
    echo "This script will:"
    echo "  1. Check git state is clean"
    echo "  2. Update version in main.go"
    echo "  3. Commit changes"
    echo "  4. Create git tag"
    echo "  5. Push to remote(s)"
    echo "  6. Build and release all packages/binaries"
    exit 1
fi

# Parse target flag from any remaining argument
TARGET="both"
for arg in "$@"; do
    case "$arg" in
        --gitlab) TARGET="gitlab" ;;
        --github) TARGET="github" ;;
        --both)   TARGET="both"   ;;
    esac
done

error() {
    echo "✗ ERROR: $1" >&2
    exit 1
}

echo "═══════════════════════════════════════════════════════════════════"
echo "Quick Release: v$VERSION → $TARGET"
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

# Step 4: Push to relevant remotes
echo "▶ Pushing to remote(s)..."
if [ "$TARGET" = "gitlab" ] || [ "$TARGET" = "both" ]; then
    git push origin master --tags 2>&1 | grep -v "rejected" || true
    echo "  ✓ Pushed to GitLab (origin)"
fi
if [ "$TARGET" = "github" ] || [ "$TARGET" = "both" ]; then
    git push github master --tags 2>&1 | grep -v "rejected" || true
    echo "  ✓ Pushed to GitHub"
fi

# Final check: Ensure clean state before release
echo "▶ Final validation before release..."
if ! git diff-index --quiet HEAD --; then
    error "Git state became dirty during commit/tag process"
fi
echo "✓ Ready for release build"

# Step 5: Release
echo ""
"$SCRIPT_DIR/release.sh" "$VERSION" "$CHANGELOG" "--$TARGET"
