#!/bin/bash
#
# AI Guardrails Setup Script (v2.x — DEPRECATED)
# https://github.com/catpilotai/catpilot-ai-guardrails
#
# *** DEPRECATED AS OF RELEASE 2026.05.06 ***
#
# This installer is kept working for v2.x users, but new installs should
# use skills.sh (the vercel-labs/skills CLI) and the Anthropic Agent
# Skills format:
#
#   npx skills add catpilotai/catpilot-ai-guardrails --skill catpilot-security-core
#
# That command works on 51+ AI coding agents (Claude Code, Cursor, Codex,
# OpenClaw, Cline, Aider, GitHub Copilot, OpenCode, etc.) and copies the
# skill into the right place automatically.
#
# See README.md, CHANGELOG.md, and docs/spec/ for migration details.
#
# ---
#
# WHAT THIS SCRIPT DOES (v2.x behavior):
#   - Installs guardrails to .github/copilot-instructions.md
#   - Merges with existing file if present (backs up first)
#   - Auto-detects framework (Next.js, Django, Rails, etc.) and adds patterns
#   - Creates symlinks for multiple AI tools (Claude Code, Cursor, Windsurf, Cline)
#   - Configures Aider if .aider.conf.yml exists
#
# SUPPORTED TOOLS (v2.x):
#   VS Code + Copilot, Cursor, Windsurf, JetBrains, Claude Code, Cline, Aider
#
# USAGE:
#   ./setup.sh                    # Auto-detect everything
#   ./setup.sh --framework django # Force specific framework
#   ./setup.sh --no-framework     # Skip framework patterns
#   ./setup.sh --force            # Reinstall/update existing
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Deprecation notice (shown at every run; doesn't block execution)
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${YELLOW}║${NC} ${RED}DEPRECATED:${NC} setup.sh is the v2.x installer.                          ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} New installs should use:                                            ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC}                                                                     ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC}   ${GREEN}npx skills add catpilotai/catpilot-ai-guardrails \\${NC}                  ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC}     ${GREEN}--skill catpilot-security-core${NC}                                  ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC}                                                                     ${YELLOW}║${NC}"
echo -e "${YELLOW}║${NC} Continuing with v2.x install for backward compatibility...         ${YELLOW}║${NC}"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}"
echo ""

# Determine script location (works even when called from different directory)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAFETY_GUIDELINES="$SCRIPT_DIR/copilot-instructions.md"
FRAMEWORKS_DIR="$SCRIPT_DIR/frameworks"

# Target location
TARGET_DIR=".github"
TARGET_FILE="$TARGET_DIR/copilot-instructions.md"
BACKUP_FILE=""

# A legacy installer must not follow repository-controlled output symlinks.
if [ -L "$TARGET_DIR" ] || [ -L "$TARGET_FILE" ]; then
    echo "Refusing a symlinked .github directory or instruction file" >&2
    exit 1
fi
if [ -e "$TARGET_FILE" ] && [ ! -f "$TARGET_FILE" ]; then
    echo "Refusing a non-regular instruction output" >&2
    exit 1
fi

# Size budget (32KB = 32768 bytes) - Modern LLMs handle this easily
SIZE_CAP=32768

# Available frameworks
AVAILABLE_FRAMEWORKS="nextjs, django, rails, express, fastapi, springboot, python, typescript, openclaw, agentic, docker"

# Auto-detect framework based on common files
detect_framework() {
    # Next.js - check package.json for next dependency
    if [ -f "package.json" ] && grep -q '"next"' package.json 2>/dev/null; then
        echo "nextjs"
        return
    fi
    
    # Django - check for manage.py or django in requirements/pyproject.toml
    if [ -f "manage.py" ] || \
       ([ -f "requirements.txt" ] && grep -qi "django" requirements.txt 2>/dev/null) || \
       ([ -f "pyproject.toml" ] && grep -qi "django" pyproject.toml 2>/dev/null); then
        echo "django"
        return
    fi
    
    # Rails - check for Gemfile with rails
    if [ -f "Gemfile" ] && grep -q "rails" Gemfile 2>/dev/null; then
        echo "rails"
        return
    fi
    
    # FastAPI - check requirements.txt for fastapi
    if ([ -f "requirements.txt" ] && grep -qi "fastapi" requirements.txt 2>/dev/null) || \
       ([ -f "pyproject.toml" ] && grep -qi "fastapi" pyproject.toml 2>/dev/null); then
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

    # OpenClaw - check for openclaw config or project structure
    if [ -f "openclaw.mjs" ] || [ -f ".openclaw" ] || \
       ([ -f "AGENTS.md" ] && grep -qi "openclaw\|clawdbot\|clawhub" AGENTS.md 2>/dev/null) || \
       ([ -f "package.json" ] && grep -q '"openclaw"' package.json 2>/dev/null); then
        echo "openclaw"
        return
    fi

    # Agentic AI - check for common agent framework patterns
    if ([ -f "requirements.txt" ] && grep -qi "langchain\|crewai\|autogpt\|langgraph\|llama.index" requirements.txt 2>/dev/null) || \
       ([ -f "pyproject.toml" ] && grep -qi "langchain\|crewai\|autogpt\|langgraph\|llama.index" pyproject.toml 2>/dev/null) || \
       ([ -f "package.json" ] && grep -qi "langchain\|autogen" package.json 2>/dev/null); then
        echo "agentic"
        return
    fi

    # TypeScript (General) - check for tsconfig.json without specific frameworks
    if [ -f "tsconfig.json" ] && ! grep -q '"next"' package.json 2>/dev/null; then
        echo "typescript"
        return
    fi

    # Python (General) - check for python files if no specific framework found
    if ls *.py >/dev/null 2>&1 || [ -f "requirements.txt" ] || [ -f "pyproject.toml" ]; then
        echo "python"
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
        --verify)
            # Check if guardrails are up to date
            if [ -f "$TARGET_FILE" ] && grep -q "AI Guardrails" "$TARGET_FILE" 2>/dev/null; then
                INSTALLED_VERSION=$(sed -nE 's/.*Version:[* ]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' "$TARGET_FILE" | head -1)
                SOURCE_VERSION=$(sed -nE 's/.*Version:[* ]*([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' "$SAFETY_GUIDELINES" | head -1)
                if [ -n "$SOURCE_VERSION" ] && [ "$INSTALLED_VERSION" = "$SOURCE_VERSION" ]; then
                    BASE_LINES=$(sed '/^## 🎯 Project-Specific Rules/,$d' "$SAFETY_GUIDELINES" | wc -l | tr -d ' ')
                    if ! diff -q <(sed '/^## 🎯 Project-Specific Rules/,$d' "$SAFETY_GUIDELINES" | sed 's|\[FULL_GUARDRAILS.md\](\./FULL_GUARDRAILS.md)|[FULL_GUARDRAILS.md](.github/catpilot-ai-guardrails/FULL_GUARDRAILS.md)|g') <(head -n "$BASE_LINES" "$TARGET_FILE") >/dev/null; then
                        echo "Installed baseline differs from source; review or update it." >&2
                        exit 1
                    fi
                    echo -e "${GREEN}✓ Guardrails up to date (v$INSTALLED_VERSION)${NC}"
                    exit 0
                else
                    echo -e "${YELLOW}⚠ Update available: v$INSTALLED_VERSION → v$SOURCE_VERSION${NC}"
                    echo "  Run: $(basename $0) --force"
                fi
            else
                echo -e "${RED}✗ Guardrails not installed${NC}"
                echo "  Run: $(basename $0)"
            fi
            exit 1
            ;;
        --framework)
            if [ "$#" -lt 2 ]; then
                echo "--framework requires a name" >&2
                exit 1
            fi
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

if [ -n "$FRAMEWORK" ]; then
    case "$FRAMEWORK" in
        nextjs|django|rails|express|fastapi|springboot|python|typescript|openclaw|agentic|docker) ;;
        *) echo "Unsupported framework: $FRAMEWORK" >&2; exit 1 ;;
    esac
    if [ ! -f "$FRAMEWORKS_DIR/$FRAMEWORK/condensed.md" ]; then
        echo "Framework content is unavailable" >&2
        exit 1
    fi
fi

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
        echo "  1. git submodule update --remote .github/catpilot-ai-guardrails"
        echo "  2. Re-run this script with --force"
        echo ""
        
        if [ "$FORCE" != true ]; then
            exit 0
        fi
        echo -e "${YELLOW}--force flag detected, reinstalling...${NC}"
        echo ""
    fi
    
    # Create backup
    BACKUP_FILE=$(mktemp "$TARGET_DIR/copilot-instructions.md.backup.XXXXXX")
    cp "$TARGET_FILE" "$BACKUP_FILE"
    echo -e "Created backup: ${GREEN}$BACKUP_FILE${NC}"
    
    # Count lines in existing file
    EXISTING_LINES=$(wc -l < "$TARGET_FILE" | tr -d ' ')
    echo "Existing file has $EXISTING_LINES lines"
    echo ""
    
    # Extract existing content (skip any previous guardrails section if present)
    # Be more robust: sed to print from 'Project-Specific Rules' to end, but delete that header line itself (since we add it back)
    # If the marker isn't found, we assume the whole file is custom content (migration case)
    if grep -q "## 🎯 Project-Specific Rules" "$TARGET_FILE"; then
        EXISTING_CONTENT=$(sed -n '/^## 🎯 Project-Specific Rules/,$p' "$TARGET_FILE" | tail -n +2)
    else
        # Fallback for raw files: try to avoid duplicating safety headers if they exist
        if grep -q "# AI Guardrails" "$TARGET_FILE"; then
             # It looks like an old version of guardrails without the marker?
             # Risk of duplication here, but safer than deleting everything.
             # Ideally user should have the marker.
             EXISTING_CONTENT=$(cat "$TARGET_FILE") 
             echo -e "${YELLOW}Warning: Could not find '## 🎯 Project-Specific Rules' marker.${NC}"
             echo "Assuming entire file needs to be preserved. Check for duplicates manually."
        else
             # Pure custom file
             EXISTING_CONTENT=$(cat "$TARGET_FILE")
        fi
    fi
    
    # Merge: Guardrails first, then existing content under Project-Specific section
    echo "Merging guardrails with existing content..."
    echo ""
    
    # Create merged file
    {
        # Copy guardrails (everything except the Project-Specific section placeholder) and fix links
        sed '/^## 🎯 Project-Specific Rules/,$d' "$SAFETY_GUIDELINES" | sed 's|\[FULL_GUARDRAILS.md\](\./FULL_GUARDRAILS.md)|[FULL_GUARDRAILS.md](.github/catpilot-ai-guardrails/FULL_GUARDRAILS.md)|g'
        
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
        echo "*Full guardrails with examples: [FULL_GUARDRAILS.md](.github/catpilot-ai-guardrails/FULL_GUARDRAILS.md)*"
    } > "$TARGET_FILE"
    
    echo -e "${GREEN}✓ Merged successfully!${NC}"
    echo ""
    echo "Your existing rules are now under '## 🎯 Project-Specific Rules'"
    echo ""
    
else
    echo "No existing copilot-instructions.md found"
    echo "Installing fresh copy..."
    echo ""
    
    # Copy the safety guidelines and fix links
    sed 's|\[FULL_GUARDRAILS.md\](\./FULL_GUARDRAILS.md)|[FULL_GUARDRAILS.md](.github/catpilot-ai-guardrails/FULL_GUARDRAILS.md)|g' "$SAFETY_GUIDELINES" > "$TARGET_FILE"
    
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
        FRAMEWORK_UPPER="$(echo ${FRAMEWORK} | tr '[:lower:]' '[:upper:]' | cut -c 1)$(echo ${FRAMEWORK} | cut -c 2-)"
        if grep -q "## 🔷 ${FRAMEWORK_UPPER}" "$TARGET_FILE" 2>/dev/null; then
            echo -e "${YELLOW}  ⏭ $FRAMEWORK already included, skipping${NC}"
        else
            # Insert framework content before Project-Specific Rules section
            FRAMEWORK_CONTENT=$(cat "$FRAMEWORK_FILE")
            
            # Fix relative links in framework content
            # 1. Fix ./ references to current framework dir
            FRAMEWORK_CONTENT=$(echo "$FRAMEWORK_CONTENT" | sed "s|](\./|](.github/catpilot-ai-guardrails/frameworks/$FRAMEWORK/|g")
            # 2. Fix ../ references to sibling framework dirs
            FRAMEWORK_CONTENT=$(echo "$FRAMEWORK_CONTENT" | sed "s|](\.\./|](.github/catpilot-ai-guardrails/frameworks/|g")
            
            # Create temp file with framework content inserted
            FRAMEWORK_TEMP=$(mktemp "$TARGET_DIR/.catpilot-framework.XXXXXX")
            sed '/^## 🎯 Project-Specific Rules/i\
'"$(echo "$FRAMEWORK_CONTENT" | sed 's/$/\\/' | sed '$ s/\\$//')"'\
\
---\
' "$TARGET_FILE" > "$FRAMEWORK_TEMP"
            mv "$FRAMEWORK_TEMP" "$TARGET_FILE"
            
            echo -e "${GREEN}  ✓ Added $FRAMEWORK patterns${NC}"
        fi
    fi
    
    # Check size cap
    CURRENT_SIZE=$(wc -c < "$TARGET_FILE" | tr -d ' ')
    if [ "$CURRENT_SIZE" -gt "$SIZE_CAP" ]; then
        echo ""
        echo -e "${RED}⚠️  Warning: File size ($CURRENT_SIZE bytes) exceeds limit ($SIZE_CAP bytes)${NC}"
        echo "Consider removing a framework or condensing project rules to stay optimized."
    else
        echo ""
        echo -e "${GREEN}✓ File size: $CURRENT_SIZE / $SIZE_CAP bytes ($(( CURRENT_SIZE * 100 / SIZE_CAP ))% of budget)${NC}"
    fi
fi

# ═══════════════════════════════════════════════════════════════════
# TOOL-SPECIFIC SYMLINKS & CONFIGURATION
# ═══════════════════════════════════════════════════════════════════

TOOLS_CONFIGURED=""

link_if_absent() {
    local destination="$1" source="$2"
    if [ -L "$destination" ]; then
        if [ "$(readlink "$destination")" = "$source" ]; then
            echo "Already linked: $destination"
        else
            echo "Preserving existing symlink: $destination"
        fi
    elif [ -e "$destination" ]; then
        echo "Preserving existing configuration: $destination"
    else
        ln -s "$source" "$destination"
    fi
}

# Windsurf: create symlink if .windsurf directory exists
if [ -d ".windsurf" ] && [ ! -L ".windsurf" ] && [ ! -L ".windsurf/rules" ]; then
    mkdir -p .windsurf/rules
    link_if_absent ".windsurf/rules/security.md" "../../.github/copilot-instructions.md"
    TOOLS_CONFIGURED="$TOOLS_CONFIGURED windsurf"
    echo "Windsurf path checked: .windsurf/rules/security.md (see link result above)"
fi

# Cursor: always create .cursorrules symlink (Cursor ignores if not used)
if [ ! -f ".cursorrules" ] || [ -L ".cursorrules" ]; then
    link_if_absent ".cursorrules" ".github/copilot-instructions.md"
    TOOLS_CONFIGURED="$TOOLS_CONFIGURED cursor"
    echo "Cursor path checked: .cursorrules (see link result above)"
elif [ -f ".cursorrules" ]; then
    echo -e "${YELLOW}⏭ Cursor — .cursorrules exists (not a symlink), skipping${NC}"
fi

# Claude Code: always create CLAUDE.md symlink
if [ ! -f "CLAUDE.md" ] || [ -L "CLAUDE.md" ]; then
    link_if_absent "CLAUDE.md" ".github/copilot-instructions.md"
    TOOLS_CONFIGURED="$TOOLS_CONFIGURED claude-code"
    echo "Claude Code path checked: CLAUDE.md (see link result above)"
elif [ -f "CLAUDE.md" ]; then
    echo -e "${YELLOW}⏭ Claude Code — CLAUDE.md exists (not a symlink), skipping${NC}"
fi

# Cline: always create .clinerules symlink
if [ ! -f ".clinerules" ] || [ -L ".clinerules" ]; then
    link_if_absent ".clinerules" ".github/copilot-instructions.md"
    TOOLS_CONFIGURED="$TOOLS_CONFIGURED cline"
    echo "Cline path checked: .clinerules (see link result above)"
elif [ -f ".clinerules" ]; then
    echo -e "${YELLOW}⏭ Cline — .clinerules exists (not a symlink), skipping${NC}"
fi

# Preserve Aider YAML; blind appends can duplicate or replace an existing read key.
if [ -f ".aider.conf.yml" ]; then
    if ! grep -q "copilot-instructions.md" ".aider.conf.yml" 2>/dev/null; then
        echo "Aider: manually add .github/copilot-instructions.md to your existing read list."
    else
        echo -e "${YELLOW}⏭ Aider — already configured in .aider.conf.yml${NC}"
    fi
fi

# Show summary
echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                      Summary                               ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo -e "  Installed to: ${GREEN}$TARGET_FILE${NC}"

if [ -f "$BACKUP_FILE" ]; then
    echo -e "  Backup at:    ${YELLOW}$BACKUP_FILE${NC}"
fi

if [ -n "$TOOLS_CONFIGURED" ]; then
    echo ""
    echo -e "  Tool paths checked:${TOOLS_CONFIGURED}"
fi

echo ""
echo "  Next steps:"
echo "    1. Review the merged file: cat $TARGET_FILE"
echo "    2. Commit the changes:"
echo "       git add $TARGET_FILE"
echo "       git commit -m 'Add AI guardrails'"
echo ""
echo "  To update guardrails in the future:"
echo "    git submodule update --remote .github/catpilot-ai-guardrails"
echo "    ./.github/catpilot-ai-guardrails/setup.sh --force"
echo ""
echo "  Framework options:"
echo "    Auto-detect (default): setup.sh"
echo "    Specify framework:     setup.sh --framework django"
echo "    Skip framework:        setup.sh --no-framework"
echo "    Available: $AVAILABLE_FRAMEWORKS"
echo ""
