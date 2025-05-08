#!/bin/bash
# Script to help set up and push the SharpEye GitHub repository

set -e # Exit on any error

# Color constants
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}   SharpEye GitHub Repository Setup   ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""

# Check if git is installed
if ! command -v git &> /dev/null; then
    echo -e "${RED}Error: git is not installed. Please install git and try again.${NC}"
    exit 1
fi

# Check if current directory is the project root
if [ ! -f "README.md" ] || [ ! -d "src" ]; then
    echo -e "${RED}Error: This script must be run from the SharpEye project root directory.${NC}"
    exit 1
fi

# Function to prompt for confirmation
confirm() {
    read -r -p "$1 [y/N] " response
    case "$response" in
        [yY][eE][sS]|[yY]) 
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

# Step 1: Initialize the git repository
echo -e "${GREEN}Step 1: Initializing git repository...${NC}"
git init
echo "Git repository initialized."
echo ""

# Step 2: Add files to staging
echo -e "${GREEN}Step 2: Adding files to staging...${NC}"
git add .
echo "Files added to staging."
echo ""

# Step 3: Make the initial commit
echo -e "${GREEN}Step 3: Making the initial commit...${NC}"
git commit -m "Initial commit of SharpEye"
echo "Initial commit created."
echo ""

# Step 4: Create a GitHub repository (manual step)
echo -e "${GREEN}Step 4: Creating a GitHub repository${NC}"
echo "Please manually create a new repository on GitHub:"
echo "1. Go to https://github.com/new"
echo "2. Repository name: sharpeye"
echo "3. Description: Advanced Linux Intrusion Detection and Threat Hunting System"
echo "4. Select 'Public' repository"
echo "5. DO NOT initialize with README, .gitignore, or license (we already have these)"
echo "6. Click 'Create repository'"
echo ""

if ! confirm "Have you created the GitHub repository?"; then
    echo "Please create the repository before continuing."
    exit 1
fi

# Step 5: Add the remote repository
echo -e "${GREEN}Step 5: Adding the remote repository...${NC}"
echo "Enter the URL of your GitHub repository (e.g., https://github.com/username/sharpeye.git):"
read -r repo_url

if [ -z "$repo_url" ]; then
    echo -e "${RED}Error: Repository URL cannot be empty.${NC}"
    exit 1
fi

git remote add origin "$repo_url"
echo "Remote repository added as 'origin'."
echo ""

# Step 6: Push to GitHub
echo -e "${GREEN}Step 6: Pushing to GitHub...${NC}"
if confirm "Do you want to push to GitHub now?"; then
    git push -u origin main
    echo "Repository pushed to GitHub!"
else
    echo "You can push to GitHub later with the command:"
    echo "  git push -u origin main"
fi

echo ""
echo -e "${BLUE}===============================================${NC}"
echo -e "${BLUE}   Repository setup complete!                 ${NC}"
echo -e "${BLUE}===============================================${NC}"
echo ""
echo "Your SharpEye repository is now ready."
echo "You can view it on GitHub at: $repo_url"