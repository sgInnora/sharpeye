# GitHub Repository Setup Guide

This document guides you through the process of setting up the SharpEye project as a public GitHub repository.

## Prerequisites

1. A GitHub account
2. Git installed on your local machine
3. The SharpEye project code on your local machine

## Setup Process

You can set up the GitHub repository either manually or using the provided setup script.

### Option 1: Using the Setup Script (Recommended)

1. Navigate to the SharpEye project root directory:
   ```bash
   cd /path/to/sharpeye
   ```

2. Make the setup script executable:
   ```bash
   chmod +x setup_github_repo.sh
   ```

3. Run the setup script:
   ```bash
   ./setup_github_repo.sh
   ```

4. Follow the instructions provided by the script.

### Option 2: Manual Setup

1. Initialize a Git repository in the project directory:
   ```bash
   git init
   ```

2. Add all files to staging:
   ```bash
   git add .
   ```

3. Create the initial commit:
   ```bash
   git commit -m "Initial commit of SharpEye"
   ```

4. Create a new repository on GitHub:
   - Go to https://github.com/new
   - Repository name: `sharpeye`
   - Description: Advanced Linux Intrusion Detection and Threat Hunting System
   - Select 'Public' repository
   - DO NOT initialize with README, .gitignore, or license (we already have these)
   - Click 'Create repository'

5. Add the GitHub repository as a remote:
   ```bash
   git remote add origin https://github.com/sgInnora/sharpeye.git
   ```

6. Push the code to GitHub:
   ```bash
   git push -u origin main
   ```

## After Setup

Once the repository is set up, you can:

1. Enable GitHub Pages to host the documentation
2. Configure GitHub Actions for continuous integration
3. Set up issue templates and contribution guidelines
4. Add project tags/topics in the repository settings

## Recommended Repository Settings

1. **Branches**:
   - Enable branch protection for `main`
   - Require pull request reviews before merging

2. **Security**:
   - Enable vulnerability alerts
   - Enable automated security fixes

3. **GitHub Pages**:
   - Source: main branch / docs folder

4. **Topics**:
   - linux
   - security
   - intrusion-detection
   - threat-hunting
   - cybersecurity
   - machine-learning
   - python
   - monitoring
   - cryptominer-detection
   - rootkit-detection