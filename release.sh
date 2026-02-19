#!/bin/bash
set -e

# Load release config
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "$SCRIPT_DIR/.release-config"

VERSION="$1"
# Escape [[...]] so GitLab doesn't render them as wiki links
CHANGELOG=$(echo "${2:-See git log for changes}" | sed 's/\[\[/`[[/g; s/\]\]/]]`/g')

if [ -z "$VERSION" ]; then
    echo "Usage: ./release.sh <version> [changelog] [--gitlab|--github|--both]"
    echo "Example: ./release.sh 1.2.10"
    echo "Example: ./release.sh 1.2.10 \"- New feature\n- Bug fix\""
    echo "Example: ./release.sh 1.2.10 \"- New feature\" --gitlab"
    exit 1
fi

# Parse target flag from any argument (default: both)
TARGET="both"
for arg in "$@"; do
    case "$arg" in
        --gitlab) TARGET="gitlab" ;;
        --github) TARGET="github" ;;
        --both)   TARGET="both"   ;;
    esac
done

DO_GITLAB=false
DO_GITHUB=false
[ "$TARGET" = "gitlab" ] || [ "$TARGET" = "both" ] && DO_GITLAB=true
[ "$TARGET" = "github" ] || [ "$TARGET" = "both" ] && DO_GITHUB=true

TAG="v$VERSION"
GO="${GO:-/usr/local/go/bin/go}"
TEMP_JSON=$(mktemp)

trap "rm -f '$TEMP_JSON'" EXIT

# Helper functions
progress() {
    echo "▶ $1"
}

success() {
    echo "✓ $1"
}

error() {
    echo "✗ ERROR: $1" >&2
    exit 1
}

# Check git state before starting
check_git_state() {
    # Ensure clean working directory
    if ! git diff-index --quiet HEAD --; then
        git status
        error "Git working directory is dirty. Please commit all changes first."
    fi

    # Ensure tag matches current commit
    current_commit=$(git rev-parse HEAD)
    tag_commit=$(git rev-list -n 1 "$TAG" 2>/dev/null || echo "")

    if [ -n "$tag_commit" ] && [ "$tag_commit" != "$current_commit" ]; then
        progress "Tag $TAG exists on different commit, recreating..."
        git tag -d "$TAG"
        git tag "$TAG"
        if $DO_GITLAB; then git push origin "$TAG" --force; fi
        if $DO_GITHUB; then git push github "$TAG" --force; fi
    fi
}

# Verify prerequisites
if ! git status > /dev/null 2>&1; then
    error "Not in a git repository"
fi

check_git_state

# Step 1: Build all packages and binaries with GoReleaser
progress "Building packages and binaries with GoReleaser..."
goreleaser release --skip=publish --clean

success "GoReleaser build completed"

# Step 2: Extract standalone binaries from GoReleaser dist (already UPX compressed for Linux)
progress "Extracting standalone binaries from dist/..."
cp dist/sambam-linux_linux_amd64_v1/sambam       sambam-linux-amd64
cp dist/sambam-linux_linux_arm64_v8.0/sambam     sambam-linux-arm64
cp dist/sambam-linux_linux_arm_6/sambam           sambam-linux-armv6
cp dist/sambam-cross_darwin_arm64_v8.0/sambam    sambam-darwin-arm64
cp dist/sambam-cross_windows_amd64_v1/sambam.exe sambam-windows-amd64.exe
success "Standalone binaries ready"

# Step 3: Upload packages and binaries to GitLab
if $DO_GITLAB; then
  progress "Uploading artifacts to GitLab..."

  UPLOAD_COUNT=0

  # Upload all packages
  if [ -d dist ]; then
    for PKG in dist/sambam_${VERSION}_linux_*; do
      if [ -f "$PKG" ]; then
        FILENAME=$(basename "$PKG")
        curl -s --request PUT \
             --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
             --upload-file "$PKG" \
             "$GITLAB_API/packages/generic/sambam/$VERSION/$FILENAME" > /dev/null
        UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
        echo "  ✓ $FILENAME"
      fi
    done
  fi

  # Upload binaries
  for BINARY in sambam-linux-amd64 sambam-linux-arm64 sambam-linux-armv6 sambam-darwin-arm64 sambam-windows-amd64.exe; do
    if [ -f "$BINARY" ]; then
      curl -s --request PUT \
           --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
           --upload-file "$BINARY" \
           "$GITLAB_API/packages/generic/sambam/$VERSION/$BINARY" > /dev/null
      UPLOAD_COUNT=$((UPLOAD_COUNT + 1))
      echo "  ✓ $BINARY"
    fi
  done

  success "Uploaded $UPLOAD_COUNT artifacts"

  # Step 4: Generate and create GitLab release with dynamic links
  progress "Creating GitLab release $TAG..."

  # Build package section of release notes
  PKG_DEB=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.deb" -type f 2>/dev/null | sort | sed 's|.*\(sambam.*\)|[\1](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/'"$VERSION"'/\1)|' | sed 's/^/- /')
  PKG_RPM=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.rpm" -type f 2>/dev/null | sort | sed 's|.*\(sambam.*\)|[\1](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/'"$VERSION"'/\1)|' | sed 's/^/- /')
  PKG_APK=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.apk" -type f 2>/dev/null | sort | sed 's|.*\(sambam.*\)|[\1](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/'"$VERSION"'/\1)|' | sed 's/^/- /')
  PKG_ARCH=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.pkg.tar.zst" -type f 2>/dev/null | sort | sed 's|.*\(sambam.*\)|[\1](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/'"$VERSION"'/\1)|' | sed 's/^/- /')

  DESCRIPTION="## Changes

$CHANGELOG

## Linux Packages

### Debian/Ubuntu (.deb)
$PKG_DEB

### RedHat/Fedora (.rpm)
$PKG_RPM

### Alpine Linux (.apk)
$PKG_APK

### Arch Linux (.pkg.tar.zst)
$PKG_ARCH

## Binary Releases (UPX Compressed)

### Linux
- [sambam-linux-amd64](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-linux-amd64) (x86-64)
- [sambam-linux-arm64](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-linux-arm64) (ARM 64-bit, Raspberry Pi 4+)
- [sambam-linux-armv6](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-linux-armv6) (ARM 32-bit, Raspberry Pi 1-3)

### macOS
- [sambam-darwin-arm64](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-darwin-arm64) (Apple Silicon)

### Windows
- [sambam-windows-amd64.exe](https://git.tcjew.win/api/v4/projects/yaron%2Fsambam/packages/generic/sambam/$VERSION/sambam-windows-amd64.exe)"

  # Create release JSON
  python3 -c "
import json
import sys

data = {
    'tag_name': '$TAG',
    'name': '$TAG',
    'description': '''$DESCRIPTION'''
}

print(json.dumps(data, indent=2))
" > "$TEMP_JSON"

  # Create or update release
  curl -s --request POST \
       --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
       --header "Content-Type: application/json" \
       --data @"$TEMP_JSON" \
       "$GITLAB_API/releases" > /dev/null || \
  curl -s --request PUT \
       --header "PRIVATE-TOKEN: $GITLAB_TOKEN" \
       --header "Content-Type: application/json" \
       --data @"$TEMP_JSON" \
       "$GITLAB_API/releases/$TAG" > /dev/null

  success "GitLab release created"
fi

# Step 5: Create GitHub release and upload artifacts
if $DO_GITHUB; then
  if [ -n "$GITHUB_TOKEN" ]; then
    progress "Creating GitHub release $TAG..."

    GITHUB_API_REPO="https://api.github.com/repos/darkpenguin23/sambam"
    GITHUB_UPLOAD_BASE="https://uploads.github.com/repos/darkpenguin23/sambam/releases"

    # Build package links for GitHub (use release download URLs)
    GH_PKG_DEB=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.deb" -type f 2>/dev/null | sort | sed 's|.*/\(sambam.*\)|[\1](https://github.com/darkpenguin23/sambam/releases/download/'"$TAG"'/\1)|' | sed 's/^/- /')
    GH_PKG_RPM=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.rpm" -type f 2>/dev/null | sort | sed 's|.*/\(sambam.*\)|[\1](https://github.com/darkpenguin23/sambam/releases/download/'"$TAG"'/\1)|' | sed 's/^/- /')
    GH_PKG_APK=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.apk" -type f 2>/dev/null | sort | sed 's|.*/\(sambam.*\)|[\1](https://github.com/darkpenguin23/sambam/releases/download/'"$TAG"'/\1)|' | sed 's/^/- /')
    GH_PKG_ARCH=$(find dist -maxdepth 1 -name "sambam_${VERSION}_linux_*.pkg.tar.zst" -type f 2>/dev/null | sort | sed 's|.*/\(sambam.*\)|[\1](https://github.com/darkpenguin23/sambam/releases/download/'"$TAG"'/\1)|' | sed 's/^/- /')

    GH_BODY="## Changes

$CHANGELOG

## Linux Packages

### Debian/Ubuntu (.deb)
$GH_PKG_DEB

### RedHat/Fedora (.rpm)
$GH_PKG_RPM

### Alpine Linux (.apk)
$GH_PKG_APK

### Arch Linux (.pkg.tar.zst)
$GH_PKG_ARCH

## Binary Releases (UPX Compressed)

### Linux
- [sambam-linux-amd64](https://github.com/darkpenguin23/sambam/releases/download/$TAG/sambam-linux-amd64) (x86-64)
- [sambam-linux-arm64](https://github.com/darkpenguin23/sambam/releases/download/$TAG/sambam-linux-arm64) (ARM 64-bit, Raspberry Pi 4+)
- [sambam-linux-armv6](https://github.com/darkpenguin23/sambam/releases/download/$TAG/sambam-linux-armv6) (ARM 32-bit, Raspberry Pi 1-3)

### macOS
- [sambam-darwin-arm64](https://github.com/darkpenguin23/sambam/releases/download/$TAG/sambam-darwin-arm64) (Apple Silicon)

### Windows
- [sambam-windows-amd64.exe](https://github.com/darkpenguin23/sambam/releases/download/$TAG/sambam-windows-amd64.exe)"

    python3 -c "
import json
data = {
    'tag_name': '$TAG',
    'name': '$TAG',
    'body': '''$GH_BODY''',
    'draft': False,
    'prerelease': False
}
print(json.dumps(data))
" > "$TEMP_JSON"

    GH_RELEASE_ID=$(curl -s \
      --request POST \
      --header "Authorization: Bearer $GITHUB_TOKEN" \
      --header "Content-Type: application/json" \
      --data @"$TEMP_JSON" \
      "$GITHUB_API_REPO/releases" | python3 -c "import json,sys; r=json.load(sys.stdin); print(r.get('id',''))")

    if [ -z "$GH_RELEASE_ID" ]; then
      echo "  ✗ Failed to create GitHub release"
    else
      success "GitHub release created (id=$GH_RELEASE_ID)"
      progress "Uploading artifacts to GitHub..."

      gh_upload() {
        local file="$1"
        local mime="$2"
        local name
        name=$(basename "$file")
        local code
        code=$(curl -s -o /dev/null -w "%{http_code}" \
          --header "Authorization: Bearer $GITHUB_TOKEN" \
          --header "Content-Type: $mime" \
          --data-binary @"$file" \
          "$GITHUB_UPLOAD_BASE/$GH_RELEASE_ID/assets?name=$name")
        echo "  $([ "$code" = "201" ] && echo "✓" || echo "✗ HTTP $code") $name"
      }

      # Packages
      for PKG in dist/sambam_${VERSION}_linux_*.deb;         do gh_upload "$PKG" "application/vnd.debian.binary-package"; done
      for PKG in dist/sambam_${VERSION}_linux_*.rpm;         do gh_upload "$PKG" "application/x-rpm"; done
      for PKG in dist/sambam_${VERSION}_linux_*.apk;         do gh_upload "$PKG" "application/octet-stream"; done
      for PKG in dist/sambam_${VERSION}_linux_*.pkg.tar.zst; do gh_upload "$PKG" "application/octet-stream"; done

      # Standalone binaries
      gh_upload "sambam-linux-amd64"       "application/octet-stream"
      gh_upload "sambam-linux-arm64"       "application/octet-stream"
      gh_upload "sambam-linux-armv6"       "application/octet-stream"
      gh_upload "sambam-darwin-arm64"      "application/octet-stream"
      gh_upload "sambam-windows-amd64.exe" "application/octet-stream"

      success "GitHub artifacts uploaded"
    fi
  else
    echo "  (skipping GitHub release: GITHUB_TOKEN not set)"
  fi
fi

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Release $TAG completed successfully! ✓"
echo ""
if $DO_GITLAB; then
  echo "  GitLab: https://git.tcjew.win/yaron/sambam/-/releases/$TAG"
fi
if $DO_GITHUB; then
  echo "  GitHub: https://github.com/darkpenguin23/sambam/releases/tag/$TAG"
fi
echo "════════════════════════════════════════════════════════════════"
