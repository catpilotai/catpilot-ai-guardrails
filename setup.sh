#!/bin/bash
#
# AI Guardrails Setup Script
# https://github.com/catpilotai/catpilot-ai-guardrails
#
# WHAT IT DOES:
#   - Installs guardrails to .github/copilot-instructions.md
#   - Merges with existing file if present (backs up first)
#   - Auto-detects framework (Next.js, Django, Rails, etc.) and adds patterns
#   - Auto-detects Windsurf and creates symlink to .windsurf/rules/
#
# SUPPORTED IDEs:
#   VS Code + Copilot, Cursor, Windsurf, JetBrains
#
# USAGE:
#   ./setup.sh                    # Auto-detect everything
#   ./setup.sh --framework django # Force specific framework
#   ./setup.sh --no-framework     # Skip framework patterns
#   ./setup.sh --force            # Reinstall/update existing
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Determine script location (works even when called from different directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFETY_GUIDELINES="$SCRIPT_DIR/copilot-instructions.md"
FRAMEWORKS_DIR="$SCRIPT_DIR/frameworks"

# Target location
TARGET_DIR=".github"
TARGET_FILE="$TARGET_DIR/copilot-instructions.md"
BACKUP_FILE="$TARGET_DIR/copilot-instructions.md.backup"

# Size budget (5KB = 5120 bytes)
SIZE_CAP=5120

# Available frameworks
AVAILABLE_FRAMEWORKS="nextjs, django, rails, express, fastapi, springboot"

# Auto-detect framework based on common files
detect_framework() {
    # Next.js - check package.json for next dependency
    if [ -f "package.json" ] && grep -q '"next"' package.json 2>/dev/null; then
        echo "nextjs"
        return
    fi
    
    # Django - check for manage.py or django in requirements
    if [ -f "manage.py" ] || ([ -f "requirements.txt" ] && grep -qi "django" requirements.txt 2>/dev/null); then
        echo "django"
        return
    fi
    
    # Rails - check for Gemfile with rails
    if [ -f "Gemfile" ] && grep -q "rails" Gemfile 2>/dev/null; then
        echo "rails"
        return
    fi
    
    # FastAPI - check requirements.txt for fastapi
    if [ -f "requirements.txt" ] && grep -qi "fastapi" requirements.txt 2>/dev/null; then
        echo "fastapi"
        return
    fi
    
    # Spring Boot - check for pom.xml with spring-boot or build.gradle
    if ([ -f "pom.xml" ] && grep -q "spring-boot" pom.xml 2>/dev/null) || \
       ([ -f "build.gradle" ] && grep -q "spring" build.gradle 2>/dev/null); then
        echo "springboot"
        return
    fi
    
    # Express - check package.json for express (but not next)
    if [ -f "package.json" ] && grep -q '"express"' package.json 2>/dev/null && ! grep -q '"next"' package.json 2>/dev/null; then
        echo "express"
        return
    fi
    
    echo ""
}

# Parse arguments
FORCE=false
FRAMEWORK=""
AUTO_DETECT=true

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE=true
            shift
            ;;
        --framework)
            FRAMEWORK="$2"
            AUTO_DETECT=false
            shift 2
            ;;
        --framework=*)
            FRAMEWORK="${1#*=}"
            AUTO_DETECT=false
            shift
            ;;
        --no-framework)
            AUTO_DETECT=false
            shift
            ;;
        *)
            echo -e "${RED}Unknown option: $1${NC}"
            echo "Usage: setup.sh [--force] [--framework <name>] [--no-framework]"
            echo "Available frameworks: $AVAILABLE_FRAMEWORKS"
            exit 1
            ;;
    esac
done

# Auto-detect framework if not specified
if [ "$AUTO_DETECT" = true ] && [ -z "$FRAMEWORK" ]; then
    DETECTED=$(detect_framework)
    if [ -n "$DETECTED" ]; then
        FRAMEWORK="$DETECTED"
        echo -e "${BLUE}Auto-detected framework: $FRAMEWORK${NC}"
    fi
fi

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║              AI Guardrails Setup                           ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Check if safety guidelines exist
if [ ! -f "$SAFETY_GUIDELINES" ]; then
    echo -e "${RED}Error: Cannot find copilot-instructions.md in $SCRIPT_DIR${NC}"
    echo "Make sure you're running this from a repo with the submodule installed."
    exit 1
fi

# Create .github directory if it doesn't exist
mkdir -p "$TARGET_DIR"

# Check if target file already exists
if [ -f "$TARGET_FILE" ]; then
    echo -e "${YELLOW}Found existing copilot-instructions.md${NC}"
    echo ""
    
    # Check if safety guidelines are already present
    if grep -q "AI Guardrails" "$TARGET_FILE" 2>/dev/null; then
        echo -e "${GREEN}✓ Guardrails already installed!${NC}"
        echo ""
        echo "To update to the latest version:"
        echo "  1. git submodule update --remote .github/ai-guardrails"
        echo "  2. Re-run this script with --force"
        echo ""
        
        if [ "$FORCE" != true ]; then
            exit 0
        fi
        echo -e "${YELLOW}--force flag detected, reinstalling...${NC}"
        echo ""
    fi
    
    # Create backup
    cp "$TARGET_FILE" "$BACKUP_FILE"
    echo -e "Created backup: ${GREEN}$BACKUP_FILE${NC}"
    
    # Count lines in existing file
    EXISTING_LINES=$(wc -l < "$TARGET_FILE" | tr -d ' ')
    echo "Existing file has $EXISTING_LINES lines"
    echo ""
    
    # Extract existing content (skip any previous guardrails section if present)
    # Look for "# Project-Specific" or "# Your" or first heading that's not safety-related
    EXISTING_CONTENT=$(cat "$TARGET_FILE")
    
    # Merge: Guardrails first, then existing content under Project-Specific section
    echo "Merging guardrails with existing content..."
    echo ""
    
    # Create merged file
    {
        # Copy guardrails (everything except the Project-Specific section placeholder)
        sed '/^## 🎯 Project-Specific Rules/,$d' "$SAFETY_GUIDELINES"
        
        echo ""
        echo "## 🎯 Project-Specific Rules"
        echo ""
        echo "<!-- Merged from your existing copilot-instructions.md -->"
        echo ""
        
        # Add existing content
        echo "$EXISTING_CONTENT"
        
        echo ""
        echo "---"
        echo ""
        echo "*Full guardrails with examples: [FULL_GUARDRAILS.md](.github/ai-safety/FULL_GUARDRAILS.md)*"
    } > "$TARGET_FILE"
    
    echo -e "${GREEN}✓ Merged successfully!${NC}"
    echo ""
    echo "Your existing rules are now under '## 🎯 Project-Specific Rules'"
    echo ""
    
else
    echo "No existing copilot-instructions.md found"
    echo "Installing fresh copy..."
    echo ""
    
    # Copy the safety guidelines
    cp "$SAFETY_GUIDELINES" "$TARGET_FILE"
    
    echo -e "${GREEN}✓ Installed successfully!${NC}"
    echo ""
fi

# Append framework-specific patterns if requested or detected
if [ -n "$FRAMEWORK" ]; then
    echo ""
    echo -e "${BLUE}Adding $FRAMEWORK security patterns...${NC}"
    
    FRAMEWORK_FILE="$FRAMEWORKS_DIR/$FRAMEWORK/condensed.md"
    
    if [ ! -f "$FRAMEWORK_FILE" ]; then
        echo -e "${RED}Warning: Framework '$FRAMEWORK' not found at $FRAMEWORK_FILE${NC}"
        echo "Available frameworks: $AVAILABLE_FRAMEWORKS"
    else
        # Check if framework already added
        if grep -q "## 🔷 ${FRAMEWORK^}" "$TARGET_FILE" 2>/dev/null; then
            echo -e "${YELLOW}  ⏭ $FRAMEWORK already included, skipping${NC}"
        else
            # Insert framework content before Project-Specific Rules section
            FRAMEWORK_CONTENT=$(cat "$FRAMEWORK_FILE")
            
            # Create temp file with framework content inserted
            sed -i.tmp '/^## 🎯 Project-Specific Rules/i\
'"$(echo "$FRAMEWORK_CONTENT" | sed 's/$/\\/' | sed '$ s/\\$//')"'\
\
---\
' "$TARGET_FILE"
            rm -f "$TARGET_FILE.tmp"
            
            echo -e "${GREEN}  ✓ Added $FRAMEWORK patterns${NC}"
        fi
    fi
    
    # Check size cap
    CURRENT_SIZE=$(wc -c < "$TARGET_FILE" | tr -d ' ')
    if [ "$CURRENT_SIZE" -gt "$SIZE_CAP" ]; then
        echo ""
        echo -e "${RED}⚠️  Warning: File size ($CURRENT_SIZE bytes) exceeds 5KB cap ($SIZE_CAP bytes)${NC}"
        echo "Consider removing a framework to stay within the context window budget."
    else
        echo ""
        echo -e "${GREEN}✓ File size: $CURRENT_SIZE / $SIZE_CAP bytes ($(( CURRENT_SIZE * 100 / SIZE_CAP ))% of budget)${NC}"
    fi
fi

# Windsurf support: create symlink if .windsurf directory exists
WINDSURF_INSTALLED=false
if [ -d ".windsurf" ]; then
    mkdir -p .windsurf/rules
    ln -sf "../../.github/copilot-instructions.md" ".windsurf/rules/security.md"
    WINDSURF_INSTALLED=true
    echo -e "${GREEN}✓ Windsurf detected — created symlink at .windsurf/rules/security.md${NC}"
fi

# Show summary
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                      Summary                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "  Installed to: ${GREEN}$TARGET_FILE${NC}"

if [ -f "$BACKUP_FILE" ]; then
    echo -e "  Backup at:    ${YELLOW}$BACKUP_FILE${NC}"
fi

if [ "$WINDSURF_INSTALLED" = true ]; then
    echo -e "  Windsurf:     ${GREEN}.windsurf/rules/security.md${NC} (symlinked)"
fi

echo ""
echo "  Next steps:"
echo "    1. Review the merged file: cat $TARGET_FILE"
echo "    2. Commit the changes:"
echo "       git add $TARGET_FILE"
echo "       git commit -m 'Add AI guardrails'"
echo ""
echo "  To update guardrails in the future:"
echo "    git submodule update --remote .github/ai-safety"
echo "    ./.github/ai-safety/setup.sh --force"
echo ""
echo "  Framework options:"
echo "    Auto-detect (default): setup.sh"
echo "    Specify framework:     setup.sh --framework django"
echo "    Skip framework:        setup.sh --no-framework"
echo "    Available: $AVAILABLE_FRAMEWORKS"
echo ""
