#!/bin/bash
# SharpEye Installation Script

# Color constants
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print a header
print_header() {
    echo -e "${BLUE}==========================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}==========================${NC}"
}

# Function to print status
print_status() {
    case "$2" in
        "info")
            echo -e "[ ${BLUE}INFO${NC} ] $1"
            ;;
        "ok")
            echo -e "[ ${GREEN}OK${NC} ] $1"
            ;;
        "warn")
            echo -e "[ ${YELLOW}WARN${NC} ] $1"
            ;;
        "error")
            echo -e "[ ${RED}ERROR${NC} ] $1"
            ;;
        *)
            echo "[ $2 ] $1"
            ;;
    esac
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_status "This script must be run as root" "error"
        exit 1
    fi
}

# Function to check dependencies
check_dependencies() {
    print_header "Checking Dependencies"
    
    # Check Python version
    python3_version=$(python3 --version 2>&1)
    if [[ $python3_version =~ Python\ 3\.[6-9] ]] || [[ $python3_version =~ Python\ 3\.[1-9][0-9] ]]; then
        print_status "Python 3.6+ is installed: $python3_version" "ok"
    else
        print_status "Python 3.6 or higher is required, found: $python3_version" "error"
        exit 1
    fi
    
    # Check pip
    if command -v pip3 &> /dev/null; then
        print_status "pip3 is installed" "ok"
    else
        print_status "pip3 is not installed, attempting to install..." "warn"
        if command -v apt-get &> /dev/null; then
            apt-get update
            apt-get install -y python3-pip
        elif command -v yum &> /dev/null; then
            yum install -y python3-pip
        else
            print_status "Could not install pip3. Please install it manually." "error"
            exit 1
        fi
    fi
    
    # Check required system packages
    if command -v apt-get &> /dev/null; then
        # Debian/Ubuntu
        apt_packages=("python3-dev" "build-essential" "libssl-dev")
        
        for pkg in "${apt_packages[@]}"; do
            if dpkg -l | grep -q "$pkg"; then
                print_status "$pkg is installed" "ok"
            else
                print_status "$pkg is not installed, attempting to install..." "warn"
                apt-get install -y "$pkg"
            fi
        done
    elif command -v yum &> /dev/null; then
        # RHEL/CentOS
        yum_packages=("python3-devel" "gcc" "openssl-devel")
        
        for pkg in "${yum_packages[@]}"; do
            if rpm -q "$pkg" &> /dev/null; then
                print_status "$pkg is installed" "ok"
            else
                print_status "$pkg is not installed, attempting to install..." "warn"
                yum install -y "$pkg"
            fi
        done
    else
        print_status "Unsupported package manager, please install dependencies manually" "warn"
    fi
}

# Function to install Python dependencies
install_python_deps() {
    print_header "Installing Python Dependencies"
    
    # Install pip requirements
    pip3 install -r requirements.txt
    
    if [ $? -eq 0 ]; then
        print_status "Python dependencies installed successfully" "ok"
    else
        print_status "Failed to install Python dependencies" "error"
        exit 1
    fi
}

# Function to create required directories
create_directories() {
    print_header "Creating Directories"
    
    DIRS=(
        "/etc/sharpeye"
        "/var/lib/sharpeye/baselines"
        "/var/lib/sharpeye/reports"
        "/var/log/sharpeye"
    )
    
    for dir in "${DIRS[@]}"; do
        if [ ! -d "$dir" ]; then
            mkdir -p "$dir"
            print_status "Created directory: $dir" "ok"
        else
            print_status "Directory already exists: $dir" "info"
        fi
    done
}

# Function to install configuration files
install_config() {
    print_header "Installing Configuration Files"
    
    # Copy default configuration
    cp config/default_config.yaml /etc/sharpeye/config.yaml
    
    if [ $? -eq 0 ]; then
        print_status "Configuration installed to /etc/sharpeye/config.yaml" "ok"
    else
        print_status "Failed to install configuration file" "error"
        exit 1
    fi
    
    # Create local configuration
    if [ ! -f "/etc/sharpeye/local_config.yaml" ]; then
        cat > /etc/sharpeye/local_config.yaml << EOF
# SharpEye Local Configuration
# Override settings from the default configuration here

# Example:
# general:
#   log_level: "debug"
EOF
        print_status "Created local configuration template at /etc/sharpeye/local_config.yaml" "ok"
    else
        print_status "Local configuration already exists at /etc/sharpeye/local_config.yaml" "info"
    fi
}

# Function to install SharpEye
install_sentinel() {
    print_header "Installing SharpEye"
    
    # Install the package
    python3 setup.py install
    
    if [ $? -eq 0 ]; then
        print_status "SharpEye installed successfully" "ok"
    else
        print_status "Failed to install SharpEye" "error"
        exit 1
    fi
    
    # Create executable link
    ln -sf $(which sharpeye) /usr/local/bin/sharpeye
    
    if [ $? -eq 0 ]; then
        print_status "Created executable link at /usr/local/bin/sharpeye" "ok"
    else
        print_status "Failed to create executable link" "error"
    fi
}

# Function to install systemd service if applicable
install_service() {
    print_header "Installing Service"
    
    if command -v systemctl &> /dev/null; then
        cat > /etc/systemd/system/sharpeye.service << EOF
[Unit]
Description=SharpEye Linux Intrusion Detection System
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sharpeye --full-scan --format json --output-dir /var/lib/sharpeye/reports
User=root
Restart=on-failure
RestartSec=60

[Install]
WantedBy=multi-user.target
EOF
        
        print_status "Created systemd service at /etc/systemd/system/sharpeye.service" "ok"
        
        # Create timer for scheduled scans
        cat > /etc/systemd/system/sharpeye.timer << EOF
[Unit]
Description=Run SharpEye scans daily

[Timer]
OnBootSec=15min
OnUnitActiveSec=1d

[Install]
WantedBy=timers.target
EOF
        
        print_status "Created systemd timer at /etc/systemd/system/sharpeye.timer" "ok"
        
        # Reload systemd
        systemctl daemon-reload
        
        print_status "Systemd configuration reloaded" "ok"
        
        # Enable the timer
        systemctl enable sharpeye.timer
        
        if [ $? -eq 0 ]; then
            print_status "SharpEye timer enabled" "ok"
        else
            print_status "Failed to enable SharpEye timer" "error"
        fi
    else
        # Create a cron job
        cat > /etc/cron.d/sharpeye << EOF
# Run SharpEye scan daily at 2 AM
0 2 * * * root /usr/local/bin/sharpeye --full-scan --format json --output-dir /var/lib/sharpeye/reports
EOF
        
        print_status "Created cron job at /etc/cron.d/sharpeye" "ok"
    fi
}

# Function to finalize installation
finalize() {
    print_header "Installation Complete"
    
    print_status "SharpEye has been installed successfully" "ok"
    print_status "Configuration directory: /etc/sharpeye" "info"
    print_status "Reports directory: /var/lib/sharpeye/reports" "info"
    print_status "Logs directory: /var/log/sharpeye" "info"
    
    echo ""
    echo -e "${GREEN}To establish a baseline for your system:${NC}"
    echo "sudo sharpeye --establish-baseline"
    echo ""
    echo -e "${GREEN}To run a full scan:${NC}"
    echo "sudo sharpeye --full-scan"
    echo ""
    echo -e "${GREEN}To run a specific detection module:${NC}"
    echo "sudo sharpeye --module <module_name>"
    echo ""
    echo -e "${GREEN}Available modules:${NC} system, users, processes, network, cryptominer, filesystem, logs, scheduled, ssh, kernel, libraries, privileges, rootkit"
    echo ""
    
    if command -v systemctl &> /dev/null; then
        echo -e "${GREEN}To run the service manually:${NC}"
        echo "sudo systemctl start sharpeye"
        echo ""
        echo -e "${GREEN}To enable automatic daily scans:${NC}"
        echo "sudo systemctl enable --now sharpeye.timer"
        echo ""
    fi
}

# Main installation flow
main() {
    print_header "SharpEye Installation"
    
    check_root
    check_dependencies
    
    # Generate requirements.txt if it doesn't exist
    if [ ! -f "requirements.txt" ]; then
        cat > requirements.txt << EOF
pyyaml>=5.1
jinja2>=2.11.0
psutil>=5.7.0
requests>=2.23.0
cryptography>=3.0
python-dateutil>=2.8.1
colorama>=0.4.3
EOF
        print_status "Generated requirements.txt" "info"
    fi
    
    # Generate setup.py if it doesn't exist
    if [ ! -f "setup.py" ]; then
        cat > setup.py << EOF
#!/usr/bin/env python3

from setuptools import setup, find_packages

setup(
    name="sharpeye",
    version="0.1.0",
    description="Advanced Linux Intrusion Detection and Threat Hunting System",
    author="innora.ai",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        'console_scripts': [
            'sharpeye=main:main',
        ],
    },
    install_requires=[
        "pyyaml>=5.1",
        "jinja2>=2.11.0",
        "psutil>=5.7.0",
        "requests>=2.23.0",
        "cryptography>=3.0",
        "python-dateutil>=2.8.1",
        "colorama>=0.4.3"
    ],
    python_requires=">=3.6",
)
EOF
        print_status "Generated setup.py" "info"
    fi
    
    install_python_deps
    create_directories
    install_config
    install_sentinel
    install_service
    finalize
}

# Run main installation
main