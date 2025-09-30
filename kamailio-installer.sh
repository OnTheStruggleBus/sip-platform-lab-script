#!/bin/bash
#
# Kamailio Installation Script with Go-based UI and CrowdSec Security
# For Vintage Telephony Research and Hobbyist Community
# Version: 3.0.0
# 
# Requirements:
# - Ubuntu 22.04 LTS or 24.04 LTS (clean installation)
# - Minimum 2GB RAM, 20GB disk space
# - Internet connectivity
#
# Features:
# - Go-based modern web UI for Kamailio management
# - CrowdSec integration for VoIP security
# - Automatic password generation with secure storage
# - Resume capability from failure points
# - Comprehensive logging and debugging
# - Certificate preparation for TLS
# - Full automation without manual interaction
#
# Usage:
#   sudo ./install-kamailio.sh [OPTIONS]
#   
# Options:
#   --domain FQDN        Set fully qualified domain name
#   --ip IP_ADDRESS      Set server IP (auto-detected if not set)
#   --resume             Resume from last checkpoint
#   --debug              Enable debug logging
#   --skip-crowdsec      Skip CrowdSec installation
#   --cert-email EMAIL   Email for Let's Encrypt certificates
#   --help               Show help message

set -euo pipefail
IFS=$'\n\t'

# ==============================================================================
# CONFIGURATION VARIABLES
# ==============================================================================

readonly SCRIPT_VERSION="3.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly LOG_DIR="/var/log/kamailio-installer"
readonly CHECKPOINT_FILE="${LOG_DIR}/install.checkpoint"
readonly CONFIG_FILE="${LOG_DIR}/install.conf"
readonly PASSWORD_FILE="/root/.kamailio-credentials"
readonly INSTALL_LOG="${LOG_DIR}/install.log"
readonly ERROR_LOG="${LOG_DIR}/error.log"

# Installation options
DOMAIN_NAME=""
SERVER_IP=""
CERT_EMAIL=""
RESUME_MODE=false
DEBUG_MODE=false
SKIP_CROWDSEC=false

# Database passwords (will be generated)
MYSQL_ROOT_PASSWORD=""
KAMAILIO_DB_PASSWORD=""
KAMAILIO_RO_PASSWORD=""
GO_UI_DB_PASSWORD=""
CROWDSEC_DB_PASSWORD=""

# System information
OS_ID=""
OS_VERSION=""
OS_CODENAME=""

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly MAGENTA='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly WHITE='\033[1;37m'
readonly NC='\033[0m' # No Color

# ==============================================================================
# LOGGING FUNCTIONS
# ==============================================================================

log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date +'%Y-%m-%d %H:%M:%S')
    echo -e "[${timestamp}] [${level}] ${message}" | tee -a "${INSTALL_LOG}"
    
    if [[ "${level}" == "ERROR" ]]; then
        echo "[${timestamp}] ${message}" >> "${ERROR_LOG}"
    fi
}

log_info() { log "INFO" "${BLUE}ℹ${NC}  $*"; }
log_success() { log "SUCCESS" "${GREEN}✓${NC}  $*"; }
log_warning() { log "WARNING" "${YELLOW}⚠${NC}  $*"; }
log_error() { 
    log "ERROR" "${RED}✗${NC}  $*"
    echo -e "\n${RED}Installation failed. Check ${ERROR_LOG} for details.${NC}"
    exit 1
}
log_debug() { 
    if [[ "${DEBUG_MODE}" == true ]]; then
        log "DEBUG" "${MAGENTA}◆${NC}  $*"
    fi
}

print_header() {
    echo -e "\n${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}  $1${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

# ==============================================================================
# UTILITY FUNCTIONS
# ==============================================================================

backup_database() {
    local db_name="$1"
    local backup_file="/tmp/${db_name}_backup_$(date +%Y%m%d_%H%M%S).sql"
    
    log_info "Creating backup of ${db_name} database..."
    
    if mysqldump -u root -p"${MYSQL_ROOT_PASSWORD}" "${db_name}" > "${backup_file}" 2>/dev/null; then
        log_success "Database backed up to: ${backup_file}"
        echo "${backup_file}"
    else
        log_warning "Could not create backup of ${db_name}"
        echo ""
    fi
}

export_kamailio_users() {
    local export_file="/tmp/kamailio_users_$(date +%Y%m%d_%H%M%S).csv"
    
    log_info "Exporting existing users..."
    
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio -e \
        "SELECT username, domain, ha1, email, rpid FROM subscriber;" \
        | tr '\t' ',' > "${export_file}" 2>/dev/null
    
    if [[ -s "${export_file}" ]]; then
        log_success "Users exported to: ${export_file}"
        return 0
    else
        log_warning "No users to export or export failed"
        return 1
    fi
}

verify_database_schema() {
    local db_name="$1"
    
    # Check critical tables exist
    local required_tables=("subscriber" "location" "acc" "version")
    local missing_tables=()
    
    for table in "${required_tables[@]}"; do
        if ! mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D "${db_name}" \
            -e "SELECT 1 FROM ${table} LIMIT 1;" &>/dev/null; then
            missing_tables+=("${table}")
        fi
    done
    
    if [[ ${#missing_tables[@]} -eq 0 ]]; then
        return 0  # Schema is valid
    else
        log_warning "Missing tables: ${missing_tables[*]}"
        return 1  # Schema is invalid
    fi
}

# Check if a package is installed, else error and exit
check_package_installed() {
    local pkg="$1"
    if ! dpkg -s "$pkg" &>/dev/null; then
        log_error "Required package '$pkg' is not installed. Aborting."
        exit 1
    fi
}

# Check if a command is available, else error and exit
check_command_exists() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command '$cmd' is missing. Aborting."
        exit 1
    fi
}

# Pre-flight check for Kamailio service
preflight_check_kamailio() {
    print_header "Pre-flight: Checking Kamailio dependencies"

    # Check MariaDB is running
    if ! systemctl is-active --quiet mariadb && ! systemctl is-active --quiet mysql; then
        log_error "MariaDB/MySQL service is not running. Please start it before continuing."
        exit 1
    fi

    # Check Kamailio DB credentials (using values from config or env)
    local db_user="${KAMAILIO_DB_USER:-kamailio}"
    local db_pass="${KAMAILIO_DB_PASSWORD:-kamailio}"
    local db_name="${KAMAILIO_DB_NAME:-kamailio}"
    if ! mysql -u"$db_user" -p"$db_pass" -e "USE $db_name;" 2>/dev/null; then
        log_error "Cannot connect to MariaDB with user '$db_user' and database '$db_name'. Check credentials and DB existence."
        exit 1
    fi

    # Check required Kamailio modules exist
    local mod_dir="/usr/lib/x86_64-linux-gnu/kamailio/modules"
    local missing_mods=()
    local required_mods=(db_mysql.so jsonrpcs.so kex.so corex.so tm.so tmx.so sl.so rr.so pv.so maxfwd.so usrloc.so registrar.so textops.so textopsx.so siputils.so xlog.so sanity.so ctl.so cfg_rpc.so acc.so auth.so auth_db.so alias_db.so domain.so presence.so presence_xml.so nathelper.so rtpengine.so tls.so htable.so pike.so dispatcher.so)
    for mod in "${required_mods[@]}"; do
        if [ ! -f "$mod_dir/$mod" ]; then
            missing_mods+=("$mod")
        fi
    done
    if [ ${#missing_mods[@]} -ne 0 ]; then
        log_error "Missing Kamailio modules: ${missing_mods[*]}"
        exit 1
    fi

    log_success "All Kamailio pre-flight checks passed."
}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

show_help() {
    cat << EOF
${CYAN}Kamailio Installation Script v${SCRIPT_VERSION}${NC}
${WHITE}Modern VoIP Platform with Go UI and CrowdSec Security${NC}

${YELLOW}USAGE:${NC}
    sudo $0 [OPTIONS]

${YELLOW}OPTIONS:${NC}
    ${GREEN}--domain${NC} FQDN        Set fully qualified domain name (e.g., pbx.example.com)
    ${GREEN}--ip${NC} IP_ADDRESS      Set server IP address (auto-detected if not specified)
    ${GREEN}--resume${NC}             Resume installation from last checkpoint
    ${GREEN}--debug${NC}              Enable debug logging for troubleshooting
    ${GREEN}--skip-crowdsec${NC}      Skip CrowdSec security installation
    ${GREEN}--cert-email${NC} EMAIL   Email address for Let's Encrypt certificates
    ${GREEN}--help${NC}               Show this help message

${YELLOW}EXAMPLES:${NC}
    # Basic installation with auto-detection
    sudo $0

    # Full installation with domain and certificates
    sudo $0 --domain pbx.lab.local --cert-email admin@lab.local

    # Resume interrupted installation
    sudo $0 --resume

    # Debug mode for troubleshooting
    sudo $0 --debug --domain pbx.lab.local

${YELLOW}REQUIREMENTS:${NC}
    • Ubuntu 22.04 LTS or 24.04 LTS (fresh installation)
    • Minimum 2GB RAM, 20GB disk space
    • Active internet connection
    • Root or sudo privileges

${YELLOW}INSTALLED COMPONENTS:${NC}
    • Kamailio SIP Server (latest stable)
    • Go-based Web UI (modern, responsive)
    • MariaDB Database
    • Apache Web Server (reverse proxy)
    • CrowdSec Security Engine
    • Let's Encrypt Certificates (optional)

${YELLOW}POST-INSTALLATION:${NC}
    • Web UI: http://your-domain/
    • SIP: your-domain:5060
    • Credentials: /root/.kamailio-credentials

${CYAN}Documentation:${NC} https://github.com/telephony-research/kamailio-installer
${CYAN}Support:${NC} https://github.com/telephony-research/kamailio-installer/issues

EOF
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --domain)
                DOMAIN_NAME="$2"
                shift 2
                ;;
            --ip)
                SERVER_IP="$2"
                shift 2
                ;;
            --resume)
                RESUME_MODE=true
                shift
                ;;
            --debug)
                DEBUG_MODE=true
                shift
                ;;
            --skip-crowdsec)
                SKIP_CROWDSEC=true
                shift
                ;;
            --cert-email)
                CERT_EMAIL="$2"
                shift 2
                ;;
            --help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1\nUse --help for usage information"
                ;;
        esac
    done
}

generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

save_checkpoint() {
    local checkpoint="$1"
    echo "${checkpoint}" > "${CHECKPOINT_FILE}"
    log_debug "Checkpoint saved: ${checkpoint}"
}

get_checkpoint() {
    if [[ -f "${CHECKPOINT_FILE}" ]]; then
        cat "${CHECKPOINT_FILE}"
    else
        echo "START"
    fi
}

save_config() {
    cat > "${CONFIG_FILE}" << EOF
# Kamailio Installation Configuration
# Generated: $(date)

DOMAIN_NAME="${DOMAIN_NAME}"
SERVER_IP="${SERVER_IP}"
CERT_EMAIL="${CERT_EMAIL}"
SKIP_CROWDSEC="${SKIP_CROWDSEC}"
DEBUG_MODE="${DEBUG_MODE}"

# System Information
OS_ID="${OS_ID}"
OS_VERSION="${OS_VERSION}"
OS_CODENAME="${OS_CODENAME}"

# Database Passwords (encrypted reference)
MYSQL_ROOT_PASSWORD="${MYSQL_ROOT_PASSWORD}"
KAMAILIO_DB_PASSWORD="${KAMAILIO_DB_PASSWORD}"
KAMAILIO_RO_PASSWORD="${KAMAILIO_RO_PASSWORD}"
GO_UI_DB_PASSWORD="${GO_UI_DB_PASSWORD}"
CROWDSEC_DB_PASSWORD="${CROWDSEC_DB_PASSWORD}"
EOF
    chmod 600 "${CONFIG_FILE}"
    log_debug "Configuration saved to ${CONFIG_FILE}"
}

load_config() {
    if [[ -f "${CONFIG_FILE}" ]]; then
        source "${CONFIG_FILE}"
        log_debug "Configuration loaded from ${CONFIG_FILE}"
    fi
}

save_credentials() {
    cat > "${PASSWORD_FILE}" << EOF
================================================================================
Kamailio Installation Credentials
Generated: $(date)
Server: ${DOMAIN_NAME:-${SERVER_IP}}
================================================================================

DATABASE CREDENTIALS:
--------------------
MySQL Root Password:     ${MYSQL_ROOT_PASSWORD}
Kamailio DB Password:    ${KAMAILIO_DB_PASSWORD}
Kamailio RO Password:    ${KAMAILIO_RO_PASSWORD}
Go UI DB Password:       ${GO_UI_DB_PASSWORD}
CrowdSec DB Password:    ${CROWDSEC_DB_PASSWORD}

WEB INTERFACE:
--------------
URL:                     http://${DOMAIN_NAME:-${SERVER_IP}}/
Go UI Port:              8080 (proxied through Apache)

SIP CONFIGURATION:
------------------
Domain/IP:               ${DOMAIN_NAME:-${SERVER_IP}}
SIP Port:                5060 (UDP/TCP)
TLS Port:                5061 (TCP)
RTP Ports:               10000-20000 (UDP)

TEST ACCOUNT:
-------------
Username:                1000@${DOMAIN_NAME:-${SERVER_IP}}
Password:                TestPass2024!

SECURITY:
---------
CrowdSec Dashboard:      http://${DOMAIN_NAME:-${SERVER_IP}}:3000/
CrowdSec Console:        Run: cscli console

FILE LOCATIONS:
---------------
Kamailio Config:         /etc/kamailio/kamailio.cfg
Go UI Config:            /opt/kamailio-webui/config.yaml
Logs:                    /var/log/kamailio/
Install Logs:            ${LOG_DIR}/

================================================================================
This file contains sensitive information. Keep it secure!
View with: sudo cat ${PASSWORD_FILE}
================================================================================
EOF
    chmod 600 "${PASSWORD_FILE}"
    chown root:root "${PASSWORD_FILE}"
    log_debug "Credentials saved to ${PASSWORD_FILE}"
}

# ==============================================================================
# SYSTEM CHECK FUNCTIONS
# ==============================================================================

check_root() {
    if [[ ${EUID} -ne 0 ]]; then
        echo -e "${RED}This script must be run as root${NC}"
        echo -e "Use: ${YELLOW}sudo $0${NC}"
        exit 1
    fi
}

detect_system() {
    log_info "Detecting system configuration..."
    
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        OS_ID="${ID}"
        OS_VERSION="${VERSION_ID}"
        OS_CODENAME="${VERSION_CODENAME:-}"
    else
        log_error "Cannot detect operating system. /etc/os-release not found."
    fi
    
    # Verify supported OS
    case "${OS_ID}" in
        ubuntu)
            case "${OS_VERSION}" in
                22.04|24.04)
                    log_success "Detected Ubuntu ${OS_VERSION} LTS"
                    ;;
                *)
                    log_warning "Ubuntu ${OS_VERSION} is untested. Proceeding with caution."
                    ;;
            esac
            ;;
        debian)
            case "${OS_VERSION}" in
                11|12)
                    log_success "Detected Debian ${OS_VERSION}"
                    ;;
                *)
                    log_warning "Debian ${OS_VERSION} is untested. Proceeding with caution."
                    ;;
            esac
            ;;
        *)
            log_error "Unsupported OS: ${OS_ID}. This script requires Ubuntu 22.04/24.04 or Debian 11/12."
            ;;
    esac
    
    # Auto-detect IP if not provided
    if [[ -z "${SERVER_IP}" ]]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
        log_info "Auto-detected IP address: ${SERVER_IP}"
    fi
    
    # Set domain to IP if not provided
    if [[ -z "${DOMAIN_NAME}" ]]; then
        DOMAIN_NAME="${SERVER_IP}"
        log_info "Using IP as domain: ${DOMAIN_NAME}"
    fi
}

check_prerequisites() {
    log_info "Checking system prerequisites..."
    
    # Check disk space (minimum 10GB free)
    local available_space=$(df / | awk 'NR==2 {print int($4/1048576)}')
    if [[ ${available_space} -lt 10 ]]; then
        log_error "Insufficient disk space. Available: ${available_space}GB, Required: 10GB"
    fi
    
    # Check memory (minimum 1GB)
    local total_memory=$(free -m | awk 'NR==2 {print $2}')
    if [[ ${total_memory} -lt 1024 ]]; then
        log_warning "Low memory detected: ${total_memory}MB. Recommended: 2048MB+"
    fi
    
    # Check internet connectivity
    if ! ping -c 1 google.com &>/dev/null; then
        log_error "No internet connection detected. This script requires internet access."
    fi
    
    # Check for existing installations
    local existing_services=()
    
    if systemctl is-active --quiet kamailio; then
        existing_services+=("kamailio")
    fi
    
    if systemctl is-active --quiet mysql || systemctl is-active --quiet mariadb; then
        # Check for existing kamailio database
        if command -v mysql &>/dev/null; then
            if mysql -e "SHOW DATABASES LIKE 'kamailio';" 2>/dev/null | grep -q kamailio; then
                existing_services+=("kamailio-database")
            fi
        fi
    fi
    
    if systemctl is-active --quiet apache2; then
        existing_services+=("apache2")
    fi
    
    if [[ ${#existing_services[@]} -gt 0 ]]; then
        log_warning "Existing services detected: ${existing_services[*]}"
        echo -e "${YELLOW}This may cause conflicts or data loss.${NC}"
        echo -e "${YELLOW}Options:${NC}"
        echo -e "  1) Continue anyway (may overwrite existing configuration)"
        echo -e "  2) Exit and backup your data first"
        echo -e "  3) Clean install (remove existing Kamailio data)"
        
        read -p "Choose an option (1-3): " -n 1 -r choice
        echo
        
        case ${choice} in
            1)
                log_info "Continuing with existing services..."
                ;;
            2)
                log_info "Installation cancelled. Please backup your data first."
                echo -e "\n${CYAN}Backup commands:${NC}"
                echo "  mysqldump -u root -p kamailio > kamailio_backup.sql"
                echo "  cp -r /etc/kamailio /etc/kamailio.backup"
                echo "  cp -r /opt/kamailio-webui /opt/kamailio-webui.backup"
                exit 0
                ;;
            3)
                log_warning "Performing clean install - removing existing Kamailio data..."
                
                # Stop services
                systemctl stop kamailio 2>/dev/null || true
                systemctl stop kamailio-webui 2>/dev/null || true
                
                # Remove database
                if command -v mysql &>/dev/null; then
                    mysql -e "DROP DATABASE IF EXISTS kamailio;" 2>/dev/null || true
                fi
                
                # Remove configuration files
                rm -rf /etc/kamailio.backup 2>/dev/null || true
                mv /etc/kamailio /etc/kamailio.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
                
                log_info "Existing installation cleaned"
                ;;
            *)
                log_error "Invalid option. Exiting."
                ;;
        esac
    fi
    
    log_success "Prerequisites check completed"
}

# ==============================================================================
# INSTALLATION FUNCTIONS
# ==============================================================================

install_base_packages() {
    print_header "Installing Base System Packages"
    
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    log_info "Updating package lists..."
    apt-get update -qq || log_error "Failed to update package lists"
    
    # Upgrade existing packages
    log_info "Upgrading existing packages..."
    apt-get upgrade -y -qq
    
    # Install essential packages
    log_info "Installing essential packages..."
    apt-get install -y -qq \
        curl \
        wget \
        gnupg2 \
        lsb-release \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        openssl \
        git \
        vim \
        htop \
        net-tools \
        dnsutils \
        tcpdump \
        sngrep \
        fail2ban \
        rsyslog \
        logrotate \
        cron \
        sudo \
        build-essential \
        python3 \
        python3-pip \
        || log_error "Failed to install essential packages"
    
    log_success "Base packages installed"
    save_checkpoint "BASE_PACKAGES_INSTALLED"
}

install_mariadb() {
    print_header "Installing MariaDB Database Server"
    
    # Generate passwords
    MYSQL_ROOT_PASSWORD=$(generate_password)
    KAMAILIO_DB_PASSWORD=$(generate_password)
    KAMAILIO_RO_PASSWORD=$(generate_password)
    GO_UI_DB_PASSWORD=$(generate_password)
    
    log_debug "Generated database passwords"
    
    # Install MariaDB
    log_info "Installing MariaDB server..."
    apt-get install -y -qq mariadb-server mariadb-client || log_error "Failed to install MariaDB"
    check_package_installed mariadb-server
    check_package_installed mariadb-client
    
    # Start and enable MariaDB
    systemctl start mariadb
    systemctl enable mariadb
    
    # Secure MariaDB installation
    log_info "Securing MariaDB installation..."
    mysql -e "ALTER USER 'root'@'localhost' IDENTIFIED BY '${MYSQL_ROOT_PASSWORD}';"
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "DELETE FROM mysql.user WHERE User='';"
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "DROP DATABASE IF EXISTS test;"
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "FLUSH PRIVILEGES;"
    
    # Configure MariaDB for Kamailio
    cat > /etc/mysql/mariadb.conf.d/99-kamailio.cnf << 'EOF'
[mysqld]
# Performance optimizations
innodb_buffer_pool_size = 256M
innodb_log_file_size = 64M
innodb_flush_log_at_trx_commit = 2
innodb_flush_method = O_DIRECT
innodb_file_per_table = 1

# Connection settings
max_connections = 500
max_allowed_packet = 32M

# Query cache
query_cache_type = 1
query_cache_size = 64M
query_cache_limit = 2M

# Character set
character-set-server = utf8mb4
collation-server = utf8mb4_general_ci

# Logging
slow_query_log = 1
slow_query_log_file = /var/log/mysql/slow.log
long_query_time = 2

[client]
default-character-set = utf8mb4
EOF
    
    systemctl restart mariadb
    
    log_success "MariaDB installed and configured"
    save_checkpoint "MARIADB_INSTALLED"
}

install_kamailio() {
    print_header "Installing Kamailio SIP Server"
    
    # Add Kamailio repository (handling apt-key deprecation)
    log_info "Adding Kamailio repository..."
    
    # Use the modern way for newer systems, fallback to apt-key for older
    if [[ -d /etc/apt/keyrings ]]; then
        # Modern method (Ubuntu 22.04+, Debian 12+)
        wget -qO- http://deb.kamailio.org/kamailiodebkey.gpg | gpg --dearmor > /etc/apt/keyrings/kamailio.gpg
        KEYRING_OPT="[signed-by=/etc/apt/keyrings/kamailio.gpg] "
    else
        # Legacy method for older systems
        wget -O- http://deb.kamailio.org/kamailiodebkey.gpg | apt-key add -
        KEYRING_OPT=""
    fi
    
    # Determine repository based on OS
    case "${OS_ID}-${OS_VERSION}" in
        ubuntu-22.04)
            echo "deb ${KEYRING_OPT}http://deb.kamailio.org/kamailio57 jammy main" > /etc/apt/sources.list.d/kamailio.list
            ;;
        ubuntu-24.04)
            echo "deb ${KEYRING_OPT}http://deb.kamailio.org/kamailio60 noble main" > /etc/apt/sources.list.d/kamailio.list
            ;;
        debian-11)
            echo "deb ${KEYRING_OPT}http://deb.kamailio.org/kamailio57 bullseye main" > /etc/apt/sources.list.d/kamailio.list
            ;;
        debian-12)
            echo "deb ${KEYRING_OPT}http://deb.kamailio.org/kamailio60 bookworm main" > /etc/apt/sources.list.d/kamailio.list
            ;;
        *)
            echo "deb ${KEYRING_OPT}http://deb.kamailio.org/kamailio60 $(lsb_release -cs) main" > /etc/apt/sources.list.d/kamailio.list
            ;;
    esac
    
    apt-get update -qq
    
    # Install Kamailio packages
    log_info "Installing Kamailio packages..."
    apt-get install -y -qq \
        kamailio \
        kamailio-mysql-modules \
        kamailio-tls-modules \
        kamailio-websocket-modules \
        kamailio-presence-modules \
        kamailio-xml-modules \
        kamailio-json-modules \
        || log_error "Failed to install Kamailio"
    check_package_installed kamailio
    check_package_installed kamailio-mysql-modules
    check_package_installed kamailio-tls-modules
    check_package_installed kamailio-websocket-modules
    check_package_installed kamailio-presence-modules
    check_package_installed kamailio-xml-modules
    check_package_installed kamailio-json-modules
    
    # Setup Kamailio database
    setup_kamailio_database
    
    # Pre-flight check before starting Kamailio
    preflight_check_kamailio
    
    log_success "Kamailio installed and configured"
    save_checkpoint "KAMAILIO_INSTALLED"
}

setup_kamailio_database() {
    log_info "Setting up Kamailio database..."
    
    # Configure kamctlrc with our generated passwords
    # This file tells kamdbctl what passwords to use when creating users
    cat > /etc/kamailio/kamctlrc << EOF
SIP_DOMAIN=${DOMAIN_NAME}
DBENGINE=MYSQL
DBHOST=localhost
DBNAME=kamailio
DBRWUSER=kamailio
DBRWPW=${KAMAILIO_DB_PASSWORD}
DBROUSER=kamailioro
DBROPW=${KAMAILIO_RO_PASSWORD}
DBROOTUSER=root
DBROOTPW=${MYSQL_ROOT_PASSWORD}
INSTALL_EXTRA_TABLES=yes
INSTALL_PRESENCE_TABLES=yes
INSTALL_DBUID_TABLES=yes
CHARSET=utf8mb4
EOF
    
    # Check if database already exists
    DB_EXISTS=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -e "SHOW DATABASES LIKE 'kamailio';" -s -N 2>/dev/null || true)
    
    if [[ -n "${DB_EXISTS}" ]]; then
        log_info "Existing Kamailio database detected. Analyzing..."
        
        # Check for existing data
        USER_COUNT=0
        if mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio -e "SELECT 1 FROM subscriber LIMIT 1;" &>/dev/null; then
            USER_COUNT=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio -e "SELECT COUNT(*) FROM subscriber;" -s -N 2>/dev/null || echo "0")
        fi
        
        if [[ ${USER_COUNT} -gt 0 ]]; then
            log_warning "Database contains ${USER_COUNT} existing user(s)"
            echo -e "\n${YELLOW}The Kamailio database exists with user data.${NC}"
            echo -e "${CYAN}Options:${NC}"
            echo -e "  1) Keep existing database (recommended)"
            echo -e "  2) Backup and recreate"
            echo -e "  3) Drop and recreate (WARNING: Data loss!)"
            
            read -p "Choose an option (1-3): " -n 1 -r db_choice
            echo
            
            case ${db_choice} in
                1)
                    log_info "Keeping existing database"
                    # Update user passwords to match our config
                    log_info "Updating database user passwords to match configuration..."
                    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
ALTER USER IF EXISTS 'kamailio'@'localhost' IDENTIFIED BY '${KAMAILIO_DB_PASSWORD}';
ALTER USER IF EXISTS 'kamailioro'@'localhost' IDENTIFIED BY '${KAMAILIO_RO_PASSWORD}';
FLUSH PRIVILEGES;
EOF
                    return 0
                    ;;
                2)
                    BACKUP_FILE="/tmp/kamailio_backup_$(date +%Y%m%d_%H%M%S).sql"
                    log_info "Creating backup: ${BACKUP_FILE}"
                    mysqldump -u root -p"${MYSQL_ROOT_PASSWORD}" kamailio > "${BACKUP_FILE}"
                    log_success "Backup saved to: ${BACKUP_FILE}"
                    
                    # Drop everything to start fresh
                    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
DROP DATABASE IF EXISTS kamailio;
DROP USER IF EXISTS 'kamailio'@'localhost';
DROP USER IF EXISTS 'kamailioro'@'localhost';
FLUSH PRIVILEGES;
EOF
                    ;;
                3)
                    log_warning "Dropping existing database and users..."
                    mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
DROP DATABASE IF EXISTS kamailio;
DROP USER IF EXISTS 'kamailio'@'localhost';
DROP USER IF EXISTS 'kamailioro'@'localhost';
FLUSH PRIVILEGES;
EOF
                    ;;
                *)
                    log_info "Invalid option, keeping existing database"
                    return 0
                    ;;
            esac
        else
            # Database exists but is empty or corrupt - safe to recreate
            log_info "Database exists but appears empty. Recreating..."
            mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
DROP DATABASE IF EXISTS kamailio;
DROP USER IF EXISTS 'kamailio'@'localhost';
DROP USER IF EXISTS 'kamailioro'@'localhost';
FLUSH PRIVILEGES;
EOF
        fi
    else
        # No database exists - also clean up any orphaned users
        log_info "No existing database found. Cleaning up any orphaned users..."
        mysql -u root -p"${MYSQL_ROOT_PASSWORD}" << EOF
DROP USER IF EXISTS 'kamailio'@'localhost';
DROP USER IF EXISTS 'kamailioro'@'localhost';
FLUSH PRIVILEGES;
EOF
    fi
    
    # Now let kamdbctl create everything from scratch
    log_info "Creating Kamailio database..."
    
    # kamdbctl will:
    # 1. Create the database
    # 2. Create the users with passwords from kamctlrc
    # 3. Grant appropriate privileges
    # 4. Create all tables with proper schema
    printf "y\ny\ny\n" | kamdbctl create > /tmp/kamdbctl.log 2>&1 || {
        if grep -q "ERROR" /tmp/kamdbctl.log; then
            log_error "Database creation failed. Check /tmp/kamdbctl.log for details"
        fi
    }
    
    # Verify the database was created successfully
    if mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio -e "SELECT COUNT(*) FROM version;" &>/dev/null; then
        log_success "Kamailio database created successfully"
        
        # Show what was created
        TABLE_COUNT=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio -e "SHOW TABLES;" 2>/dev/null | wc -l)
        ((TABLE_COUNT--)) # Subtract header
        log_info "Created ${TABLE_COUNT} tables in kamailio database"
    else
        log_error "Database verification failed"
    fi
}

configure_kamailio() {
    print_header "Configuring Kamailio"
    
    # Backup original configuration
    cp /etc/kamailio/kamailio.cfg /etc/kamailio/kamailio.cfg.original
    
    # Create optimized configuration
    cat > /etc/kamailio/kamailio.cfg << 'EOF'
#!KAMAILIO

####### Global Parameters #########
debug=2
log_stderror=no
log_facility=LOG_LOCAL0
fork=yes
children=8
tcp_children=8
port=5060
tls_port=5061

####### Modules Section ########
loadmodule "db_mysql.so"
loadmodule "jsonrpcs.so"
loadmodule "kex.so"
loadmodule "corex.so"
loadmodule "tm.so"
loadmodule "tmx.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "pv.so"
loadmodule "maxfwd.so"
loadmodule "usrloc.so"
loadmodule "registrar.so"
loadmodule "textops.so"
loadmodule "textopsx.so"
loadmodule "siputils.so"
loadmodule "xlog.so"
loadmodule "sanity.so"
loadmodule "ctl.so"
loadmodule "cfg_rpc.so"
loadmodule "acc.so"
loadmodule "auth.so"
loadmodule "auth_db.so"
loadmodule "alias_db.so"
loadmodule "domain.so"
loadmodule "presence.so"
loadmodule "presence_xml.so"
loadmodule "nathelper.so"
loadmodule "rtpengine.so"
loadmodule "tls.so"
loadmodule "htable.so"
loadmodule "pike.so"
loadmodule "dispatcher.so"

####### Setting module-specific parameters #######

# ----- db_mysql params -----
modparam("db_mysql", "ping_interval", 60)

# ----- jsonrpcs params -----
modparam("jsonrpcs", "transport", 7)

# ----- tm params -----
modparam("tm", "failure_reply_mode", 3)

# ----- rr params -----
modparam("rr", "enable_full_lr", 1)

# ----- usrloc params -----
modparam("usrloc", "db_url", "mysql://kamailio:KAMAILIO_DB_PASSWORD@localhost/kamailio")
modparam("usrloc", "db_mode", 2)

# ----- auth_db params -----
modparam("auth_db", "db_url", "mysql://kamailio:KAMAILIO_DB_PASSWORD@localhost/kamailio")
modparam("auth_db", "calculate_ha1", 1)
modparam("auth_db", "password_column", "password")
modparam("auth_db", "use_domain", 1)

# ----- presence params -----
modparam("presence", "db_url", "mysql://kamailio:KAMAILIO_DB_PASSWORD@localhost/kamailio")

# ----- presence_xml params -----
modparam("presence_xml", "db_url", "mysql://kamailio:KAMAILIO_DB_PASSWORD@localhost/kamailio")

# ----- pike params -----
modparam("pike", "sampling_time_unit", 2)
modparam("pike", "reqs_density_per_unit", 30)
modparam("pike", "remove_latency", 4)

# ----- htable params -----
modparam("htable", "htable", "ipban=>size=8;autoexpire=300;")

####### Routing Logic ########

request_route {
    # Security checks
    route(REQINIT);
    
    # Handle CANCEL
    if (is_method("CANCEL")) {
        if (t_check_trans()) {
            route(RELAY);
        }
        exit;
    }
    
    # Handle retransmissions
    if (!is_method("ACK")) {
        if(t_precheck_trans()) {
            t_check_trans();
            exit;
        }
        t_check_trans();
    }
    
    # Handle requests within SIP dialogs
    route(WITHINDLG);
    
    # Handle SIP registrations
    route(REGISTRAR);
    
    # Handle presence
    route(PRESENCE);
    
    # Handle other requests
    if ($rU==$null) {
        sl_send_reply("484", "Address Incomplete");
        exit;
    }
    
    # Dispatch requests
    route(LOCATION);
}

route[REQINIT] {
    # Flood detection
    if (!pike_check_req()) {
        xlog("L_ALERT", "ALERT: pike block $rm from $si:$sp\n");
        $sht(ipban=>$si) = 1;
        exit;
    }
    
    if ($sht(ipban=>$si)!=$null) {
        xlog("L_ALERT", "ALERT: blocked request from $si:$sp\n");
        exit;
    }
    
    if (!mf_process_maxfwd_header("10")) {
        sl_send_reply("483", "Too Many Hops");
        exit;
    }
    
    if (!sanity_check("17895", "7")) {
        xlog("Malformed SIP request from $si:$sp\n");
        exit;
    }
}

route[WITHINDLG] {
    if (!has_totag()) return;
    
    if (loose_route()) {
        if (is_method("BYE")) {
            setflag(1); # Accounting
        }
        route(RELAY);
        exit;
    }
    
    if (is_method("ACK")) {
        if (t_check_trans()) {
            route(RELAY);
            exit;
        } else {
            exit;
        }
    }
    
    sl_send_reply("404", "Not Found");
    exit;
}

route[REGISTRAR] {
    if (!is_method("REGISTER")) return;
    
    if (!save("location")) {
        sl_reply_error();
    }
    exit;
}

route[LOCATION] {
    if (!lookup("location")) {
        t_newtran();
        switch ($rc) {
            case -1:
            case -3:
                sl_send_reply("404", "Not Found");
                exit;
            case -2:
                sl_send_reply("405", "Method Not Allowed");
                exit;
        }
    }
    
    route(RELAY);
}

route[PRESENCE] {
    if (!is_method("PUBLISH|SUBSCRIBE")) return;
    
    if (is_method("SUBSCRIBE") && $hdr(Event)=="message-summary") {
        route(TOVOICEMAIL);
        exit;
    }
    
    if (!t_newtran()) {
        sl_reply_error();
        exit;
    }
    
    if(is_method("PUBLISH")) {
        handle_publish();
        t_release();
    } else if(is_method("SUBSCRIBE")) {
        handle_subscribe();
        t_release();
    }
    
    exit;
}

route[RELAY] {
    if (!t_relay()) {
        sl_reply_error();
    }
    exit;
}

route[TOVOICEMAIL] {
    exit;
}
EOF
    
    # Replace password placeholder
    sed -i "s/KAMAILIO_DB_PASSWORD/${KAMAILIO_DB_PASSWORD}/g" /etc/kamailio/kamailio.cfg
    
    # Enable Kamailio service
    sed -i 's/RUN_KAMAILIO=no/RUN_KAMAILIO=yes/g' /etc/default/kamailio
    
    # Create log directory
    mkdir -p /var/log/kamailio
    
    # Configure rsyslog for Kamailio
    cat > /etc/rsyslog.d/30-kamailio.conf << 'EOF'
local0.*                        -/var/log/kamailio/kamailio.log
& stop
EOF
    
    systemctl restart rsyslog
    
    log_success "Kamailio configuration completed"
    save_checkpoint "KAMAILIO_CONFIGURED"
}

install_golang() {
    print_header "Installing Go Language Runtime"
    
    log_info "Downloading Go..."
    GO_VERSION="1.21.5"
    wget -q -O /tmp/go.tar.gz "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
    
    log_info "Installing Go..."
    rm -rf /usr/local/go
    tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    
    # Add Go to PATH
    cat >> /etc/profile.d/golang.sh << 'EOF'
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/opt/go
export PATH=$PATH:$GOPATH/bin
EOF
    
    source /etc/profile.d/golang.sh
    
    log_success "Go ${GO_VERSION} installed"
    save_checkpoint "GOLANG_INSTALLED"
}

install_go_webui() {
    print_header "Installing Go-based Web UI"
    
    # Create application directory
    mkdir -p /opt/kamailio-webui
    cd /opt/kamailio-webui
    
    # Create Go module
    cat > go.mod << 'EOF'
module kamailio-webui

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/go-sql-driver/mysql v1.7.1
    github.com/gorilla/websocket v1.5.1
    gopkg.in/yaml.v3 v3.0.1
)
EOF
    
    # Create main application
    cat > main.go << 'GOEOF'
package main

import (
    "database/sql"
    "fmt"
    "html/template"
    "log"
    "net/http"
    "os"
    "time"
    
    "github.com/gin-gonic/gin"
    _ "github.com/go-sql-driver/mysql"
    "github.com/gorilla/websocket"
    "gopkg.in/yaml.v3"
)

type Config struct {
    Server struct {
        Port string `yaml:"port"`
        Host string `yaml:"host"`
    } `yaml:"server"`
    Database struct {
        Host     string `yaml:"host"`
        Port     string `yaml:"port"`
        User     string `yaml:"user"`
        Password string `yaml:"password"`
        Name     string `yaml:"name"`
    } `yaml:"database"`
}

type Stats struct {
    RegisteredUsers  int       `json:"registered_users"`
    ActiveCalls      int       `json:"active_calls"`
    TotalCalls       int       `json:"total_calls"`
    SystemUptime     string    `json:"system_uptime"`
    LastUpdate       time.Time `json:"last_update"`
}

type User struct {
    ID       int    `json:"id"`
    Username string `json:"username"`
    Domain   string `json:"domain"`
    Email    string `json:"email"`
    Created  string `json:"created"`
}

var (
    db       *sql.DB
    config   Config
    upgrader = websocket.Upgrader{
        CheckOrigin: func(r *http.Request) bool { return true },
    }
)

func main() {
    // Load configuration
    loadConfig()
    
    // Connect to database
    connectDB()
    defer db.Close()
    
    // Setup Gin router
    gin.SetMode(gin.ReleaseMode)
    router := gin.Default()
    
    // Load HTML templates
    router.SetHTMLTemplate(loadTemplates())
    
    // Static files
    router.Static("/static", "./static")
    
    // Routes
    router.GET("/", dashboardHandler)
    router.GET("/api/stats", statsHandler)
    router.GET("/api/users", usersHandler)
    router.POST("/api/users", createUserHandler)
    router.DELETE("/api/users/:id", deleteUserHandler)
    router.GET("/ws", websocketHandler)
    
    // Start server
    addr := fmt.Sprintf("%s:%s", config.Server.Host, config.Server.Port)
    log.Printf("Starting Kamailio Web UI on %s", addr)
    log.Fatal(router.Run(addr))
}

func loadConfig() {
    data, err := os.ReadFile("config.yaml")
    if err != nil {
        log.Fatal("Error reading config:", err)
    }
    
    err = yaml.Unmarshal(data, &config)
    if err != nil {
        log.Fatal("Error parsing config:", err)
    }
}

func connectDB() {
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=true",
        config.Database.User,
        config.Database.Password,
        config.Database.Host,
        config.Database.Port,
        config.Database.Name,
    )
    
    var err error
    db, err = sql.Open("mysql", dsn)
    if err != nil {
        log.Fatal("Database connection failed:", err)
    }
    
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(5)
    db.SetConnMaxLifetime(5 * time.Minute)
    
    if err = db.Ping(); err != nil {
        log.Fatal("Database ping failed:", err)
    }
    
    log.Println("Connected to database")
}

func dashboardHandler(c *gin.Context) {
    c.HTML(http.StatusOK, "dashboard", gin.H{
        "title": "Kamailio Dashboard",
    })
}

func statsHandler(c *gin.Context) {
    stats := Stats{
        LastUpdate: time.Now(),
    }
    
    // Get registered users count
    db.QueryRow("SELECT COUNT(*) FROM subscriber").Scan(&stats.RegisteredUsers)
    
    // Get active registrations
    var activeRegs int
    db.QueryRow("SELECT COUNT(*) FROM location WHERE expires > NOW()").Scan(&activeRegs)
    
    // Get call statistics
    db.QueryRow("SELECT COUNT(*) FROM acc WHERE time > DATE_SUB(NOW(), INTERVAL 24 HOUR)").Scan(&stats.TotalCalls)
    
    c.JSON(http.StatusOK, stats)
}

func usersHandler(c *gin.Context) {
    rows, err := db.Query("SELECT id, username, domain FROM subscriber LIMIT 100")
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }
    defer rows.Close()
    
    var users []User
    for rows.Next() {
        var user User
        rows.Scan(&user.ID, &user.Username, &user.Domain)
        users = append(users, user)
    }
    
    c.JSON(http.StatusOK, users)
}

func createUserHandler(c *gin.Context) {
    var user User
    if err := c.ShouldBindJSON(&user); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }
    
    // Create user logic here
    c.JSON(http.StatusCreated, user)
}

func deleteUserHandler(c *gin.Context) {
    id := c.Param("id")
    // Delete user logic here
    c.JSON(http.StatusOK, gin.H{"message": "User deleted", "id": id})
}

func websocketHandler(c *gin.Context) {
    conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
    if err != nil {
        log.Println("WebSocket upgrade failed:", err)
        return
    }
    defer conn.Close()
    
    // Send real-time updates
    ticker := time.NewTicker(5 * time.Second)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            stats := Stats{LastUpdate: time.Now()}
            db.QueryRow("SELECT COUNT(*) FROM location WHERE expires > NOW()").Scan(&stats.RegisteredUsers)
            
            if err := conn.WriteJSON(stats); err != nil {
                log.Println("WebSocket write error:", err)
                return
            }
        }
    }
}

func loadTemplates() *template.Template {
    tmpl := template.New("")
    
    dashboard := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .header {
            background: rgba(255,255,255,0.95);
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header h1 { color: #333; font-size: 24px; }
        .container {
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 20px;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value { 
            font-size: 36px; 
            font-weight: bold; 
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-label { 
            color: #666; 
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .content-card {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #f8f9fa;
            padding: 12px;
            text-align: left;
            border-bottom: 2px solid #dee2e6;
            color: #495057;
        }
        td {
            padding: 12px;
            border-bottom: 1px solid #dee2e6;
        }
        .status-badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: bold;
        }
        .status-active { background: #d4edda; color: #155724; }
        .status-inactive { background: #f8d7da; color: #721c24; }
        .pulse {
            display: inline-block;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #28a745;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0.7); }
            70% { box-shadow: 0 0 0 10px rgba(40, 167, 69, 0); }
            100% { box-shadow: 0 0 0 0 rgba(40, 167, 69, 0); }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 Kamailio Management Dashboard</h1>
    </div>
    <div class="container">
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value" id="registered-users">-</div>
                <div class="stat-label">Registered Users</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="active-calls">-</div>
                <div class="stat-label">Active Calls</div>
            </div>
            <div class="stat-card">
                <div class="stat-value" id="total-calls">-</div>
                <div class="stat-label">Total Calls (24h)</div>
            </div>
            <div class="stat-card">
                <div class="stat-value"><span class="pulse"></span> Online</div>
                <div class="stat-label">System Status</div>
            </div>
        </div>
        <div class="content-card">
            <h2>SIP Users</h2>
            <table id="users-table">
                <thead>
                    <tr>
                        <th>Username</th>
                        <th>Domain</th>
                        <th>Status</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <tr><td colspan="4">Loading...</td></tr>
                </tbody>
            </table>
        </div>
    </div>
    <script>
        async function loadStats() {
            try {
                const response = await fetch('/api/stats');
                const data = await response.json();
                document.getElementById('registered-users').textContent = data.registered_users || 0;
                document.getElementById('active-calls').textContent = data.active_calls || 0;
                document.getElementById('total-calls').textContent = data.total_calls || 0;
            } catch (error) {
                console.error('Error loading stats:', error);
            }
        }
        
        async function loadUsers() {
            try {
                const response = await fetch('/api/users');
                const users = await response.json();
                const tbody = document.querySelector('#users-table tbody');
                
                if (users && users.length > 0) {
                    tbody.innerHTML = users.map(user => ` + "`" + `
                        <tr>
                            <td>${user.username}</td>
                            <td>${user.domain}</td>
                            <td><span class="status-badge status-active">Active</span></td>
                            <td><button onclick="deleteUser(${user.id})">Delete</button></td>
                        </tr>
                    ` + "`" + `).join('');
                } else {
                    tbody.innerHTML = '<tr><td colspan="4">No users found</td></tr>';
                }
            } catch (error) {
                console.error('Error loading users:', error);
            }
        }
        
        function deleteUser(id) {
            if (confirm('Delete this user?')) {
                fetch(` + "`/api/users/${id}`" + `, { method: 'DELETE' })
                    .then(() => loadUsers())
                    .catch(error => console.error('Error deleting user:', error));
            }
        }
        
        // WebSocket for real-time updates
        const ws = new WebSocket('ws://' + window.location.host + '/ws');
        ws.onmessage = (event) => {
            const data = JSON.parse(event.data);
            document.getElementById('registered-users').textContent = data.registered_users || 0;
        };
        
        // Initial load
        loadStats();
        loadUsers();
        
        // Refresh every 5 seconds
        setInterval(() => {
            loadStats();
            loadUsers();
        }, 5000);
    </script>
</body>
</html>`
    
    tmpl.New("dashboard").Parse(dashboard)
    return tmpl
}
GOEOF
    
    # Create configuration file
    cat > config.yaml << 'EOF'
server:
    host: "0.0.0.0"
    port: "8090"

database:
    host: "localhost"
    port: "3306"
    user: "kamailioro"
    password: "${KAMAILIO_RO_PASSWORD}"
    name: "kamailio"
EOF
    
    # Download dependencies
    export PATH=$PATH:/usr/local/go/bin
    go mod tidy
    
    # Build application
    go build -o kamailio-webui
    
    # Create systemd service
    cat > /etc/systemd/system/kamailio-webui.service << EOF
[Unit]
Description=Kamailio Web UI
After=network.target mysql.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/kamailio-webui
ExecStart=/opt/kamailio-webui/kamailio-webui
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    
    # Set permissions
    chown -R www-data:www-data /opt/kamailio-webui
    
    # Enable and start service
    systemctl daemon-reload
    systemctl enable kamailio-webui
    systemctl start kamailio-webui
    
    log_success "Go Web UI installed"
    save_checkpoint "GO_WEBUI_INSTALLED"
}

install_apache() {
    print_header "Installing Apache Web Server"
    
    log_info "Installing Apache..."
    apt-get install -y -qq apache2 || log_error "Failed to install Apache"
    check_package_installed apache2
    
    # Enable required modules
    a2enmod proxy proxy_http headers rewrite
    # Only enable ssl if CERT_EMAIL is set
    if [[ -n "${CERT_EMAIL}" ]]; then
        a2enmod ssl
    fi
    
    # Create HTTP virtual host configuration
    cat > /etc/apache2/sites-available/kamailio-ui.conf << EOF
<VirtualHost *:80>
    ServerName ${DOMAIN_NAME}
    ServerAdmin admin@${DOMAIN_NAME}

    # Proxy to Go application
    ProxyPreserveHost On
    ProxyPass / http://localhost:8090/
    ProxyPassReverse / http://localhost:8090/

    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://localhost:8090/\$1" [P,L]

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"

    # Logging
    ErrorLog /var/log/apache2/kamailio-ui-error.log
    CustomLog /var/log/apache2/kamailio-ui-access.log combined
</VirtualHost>
EOF

    # If cert email is specified, add HTTPS virtual host
    if [[ -n "${CERT_EMAIL}" ]]; then
        cat > /etc/apache2/sites-available/kamailio-ui-ssl.conf << EOF
<VirtualHost *:443>
    ServerName ${DOMAIN_NAME}
    ServerAdmin admin@${DOMAIN_NAME}

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/${DOMAIN_NAME}/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN_NAME}/privkey.pem

    # Proxy to Go application
    ProxyPreserveHost On
    ProxyPass / http://localhost:8090/
    ProxyPassReverse / http://localhost:8090/

    # WebSocket support
    RewriteEngine On
    RewriteCond %{HTTP:Upgrade} websocket [NC]
    RewriteCond %{HTTP:Connection} upgrade [NC]
    RewriteRule ^/?(.*) "ws://localhost:8090/\$1" [P,L]

    # Security headers
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set X-XSS-Protection "1; mode=block"

    # Logging
    ErrorLog /var/log/apache2/kamailio-ui-ssl-error.log
    CustomLog /var/log/apache2/kamailio-ui-ssl-access.log combined
</VirtualHost>
EOF
        a2ensite kamailio-ui-ssl
    fi

    # Enable site and disable default
    a2ensite kamailio-ui
    a2dissite 000-default

    # Restart Apache
    systemctl restart apache2
    systemctl enable apache2

    log_success "Apache configured as reverse proxy"
    save_checkpoint "APACHE_INSTALLED"
}

install_crowdsec() {
    if [[ "${SKIP_CROWDSEC}" == true ]]; then
        log_info "Skipping CrowdSec installation (--skip-crowdsec specified)"
        save_checkpoint "CROWDSEC_SKIPPED"
        return
    fi
    
    print_header "Installing CrowdSec Security"
    

    log_info "Installing CrowdSec..."
    curl -s https://install.crowdsec.net | sudo bash

    # Ensure cscli is available
    if ! command -v cscli &>/dev/null; then
        log_info "cscli not found, attempting manual install..."
        apt-get update -qq
        apt-get install -y crowdsec || log_error "Failed to install cscli"
        check_package_installed crowdsec
    fi

    # Install collections
    log_info "Installing security collections..."
    cscli collections install crowdsecurity/linux
    cscli collections install crowdsecurity/apache2
    cscli collections install crowdsecurity/mysql
    cscli collections install crowdsecurity/iptables
    
    # Create custom VoIP scenarios
    cat > /etc/crowdsec/scenarios/kamailio-bruteforce.yaml << 'EOF'
type: leaky
name: kamailio/bruteforce
description: "Detect SIP brute force attacks"
filter: "evt.Meta.service == 'kamailio' && evt.Meta.log_type in ['auth_failed', 'registration_failed']"
leakspeed: "30s"
capacity: 5
groupby: "evt.Meta.source_ip"
blackhole: 1m
labels:
  remediation: true
  service: kamailio
  type: bruteforce
EOF
    
    cat > /etc/crowdsec/scenarios/kamailio-scan.yaml << 'EOF'
type: trigger
name: kamailio/scanner
description: "Detect SIP scanners"
filter: "evt.Meta.service == 'kamailio' && evt.Parsed.request_method == 'OPTIONS'"
groupby: "evt.Meta.source_ip"
blackhole: 5m
labels:
  remediation: true
  service: kamailio
  type: scan
EOF
    
    # Configure log acquisition
    cat >> /etc/crowdsec/acquis.yaml << EOF
---
source: file
filenames:
  - /var/log/kamailio/kamailio.log
labels:
  type: kamailio
---
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=kamailio.service"
labels:
  type: kamailio
EOF
    
    # Install firewall bouncer
    apt-get install -y -qq crowdsec-firewall-bouncer-iptables
    check_package_installed crowdsec-firewall-bouncer-iptables

    # Restart CrowdSec after all components are installed
    systemctl restart crowdsec
    systemctl enable crowdsec

    if ! systemctl is-active --quiet crowdsec; then
        log_warning "CrowdSec service failed to start. See 'systemctl status crowdsec.service' and 'journalctl -xeu crowdsec.service' for details. Script will continue."
    else
        log_success "CrowdSec service is running."
    fi

    # Check for both UFW and nftables
    if systemctl is-active --quiet nftables && systemctl is-active --quiet ufw; then
        log_warning "Both UFW and nftables are active. This may cause conflicts. It is recommended to use only one firewall unless you have a specific reason."
    fi

    log_success "CrowdSec security installed"
    save_checkpoint "CROWDSEC_INSTALLED"
}

configure_firewall() {
    print_header "Configuring Firewall"
    log_info "No UFW configuration will be applied. Please configure your preferred firewall manually if needed."
    log_success "Firewall configuration step skipped (no UFW)."
    save_checkpoint "FIREWALL_CONFIGURED"
}

create_test_accounts() {
    print_header "Creating Test Accounts"
    
    log_info "Setting up test SIP accounts..."
    
    # Check if test accounts already exist
    EXISTING_1000=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio \
        -e "SELECT COUNT(*) FROM subscriber WHERE username='1000';" -s -N 2>/dev/null || echo "0")
    EXISTING_1001=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio \
        -e "SELECT COUNT(*) FROM subscriber WHERE username='1001';" -s -N 2>/dev/null || echo "0")
    
    if [[ "${EXISTING_1000}" -gt 0 ]] && [[ "${EXISTING_1001}" -gt 0 ]]; then
        log_info "Test accounts already exist"
        
        echo -e "\n${YELLOW}Test accounts 1000 and 1001 already exist.${NC}"
        echo -e "${CYAN}Options:${NC}"
        echo -e "  1) Keep existing accounts"
        echo -e "  2) Reset passwords to default (TestPass2024!)"
        echo -e "  3) Delete and recreate accounts"
        echo -e "  4) Skip test account setup"
        
        read -p "Choose an option (1-4): " -n 1 -r acc_choice
        echo
        
        case ${acc_choice} in
            1)
                log_info "Keeping existing test accounts"
                log_success "Test accounts available: 1000 and 1001"
                ;;
            2)
                log_info "Resetting test account passwords..."
                # Update passwords using kamctl
                kamctl passwd 1000@${DOMAIN_NAME} TestPass2024! 2>/dev/null || true
                kamctl passwd 1001@${DOMAIN_NAME} TestPass2024! 2>/dev/null || true
                log_success "Passwords reset to: TestPass2024!"
                ;;
            3)
                log_info "Recreating test accounts..."
                kamctl rm 1000 2>/dev/null || true
                kamctl rm 1001 2>/dev/null || true
                kamctl add 1000@${DOMAIN_NAME} TestPass2024! 2>/dev/null || true
                kamctl add 1001@${DOMAIN_NAME} TestPass2024! 2>/dev/null || true
                log_success "Test accounts recreated"
                ;;
            4)
                log_info "Skipping test account setup"
                ;;
            *)
                log_warning "Invalid option, keeping existing accounts"
                ;;
        esac
    else
        # Create missing accounts
        if [[ "${EXISTING_1000}" -eq 0 ]]; then
            if kamctl add 1000@${DOMAIN_NAME} TestPass2024! 2>/dev/null; then
                log_success "Created test user: 1000@${DOMAIN_NAME}"
            else
                # Try alternate method
                log_debug "Using direct SQL to create user 1000"
                local ha1=$(echo -n "1000:${DOMAIN_NAME}:TestPass2024!" | md5sum | cut -d' ' -f1)
                mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio << EOF
INSERT INTO subscriber (username, domain, password, ha1) 
VALUES ('1000', '${DOMAIN_NAME}', 'TestPass2024!', '${ha1}')
ON DUPLICATE KEY UPDATE password='TestPass2024!', ha1='${ha1}';
EOF
                log_success "Created test user 1000 via SQL"
            fi
        fi
        
        if [[ "${EXISTING_1001}" -eq 0 ]]; then
            if kamctl add 1001@${DOMAIN_NAME} TestPass2024! 2>/dev/null; then
                log_success "Created test user: 1001@${DOMAIN_NAME}"
            else
                # Try alternate method
                log_debug "Using direct SQL to create user 1001"
                local ha1=$(echo -n "1001:${DOMAIN_NAME}:TestPass2024!" | md5sum | cut -d' ' -f1)
                mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio << EOF
INSERT INTO subscriber (username, domain, password, ha1) 
VALUES ('1001', '${DOMAIN_NAME}', 'TestPass2024!', '${ha1}')
ON DUPLICATE KEY UPDATE password='TestPass2024!', ha1='${ha1}';
EOF
                log_success "Created test user 1001 via SQL"
            fi
        fi
    fi
    
    # Verify final state
    USER_COUNT=$(mysql -u root -p"${MYSQL_ROOT_PASSWORD}" -D kamailio \
        -e "SELECT COUNT(*) FROM subscriber WHERE username IN ('1000', '1001');" -s -N 2>/dev/null || echo "0")
    
    if [[ "${USER_COUNT}" -ge 1 ]]; then
        log_success "Test accounts ready: 1000@${DOMAIN_NAME} and 1001@${DOMAIN_NAME}"
        log_info "Default password: TestPass2024!"
    else
        log_warning "Test accounts may need manual creation"
    fi
    
    save_checkpoint "TEST_ACCOUNTS_CREATED"
}

start_services() {
    print_header "Starting Services"
    
    log_info "Starting all services..."
    
    systemctl restart rsyslog
    systemctl restart mariadb
    systemctl restart kamailio
    systemctl restart kamailio-webui
    systemctl restart apache2
    
    if [[ "${SKIP_CROWDSEC}" != true ]]; then
        systemctl restart crowdsec
    fi
    
    # Verify services
    sleep 5
    
    for service in mariadb kamailio kamailio-webui apache2; do
        if systemctl is-active --quiet ${service}; then
            log_success "${service} is running"
        else
            log_warning "${service} may have issues - check logs"
        fi
    done
    
    save_checkpoint "SERVICES_STARTED"
}

prepare_tls() {
    print_header "Preparing TLS Configuration"
    
    if [[ -n "${CERT_EMAIL}" ]]; then
        log_info "Installing Certbot for Let's Encrypt..."
        apt-get install -y -qq certbot python3-certbot-apache
        check_package_installed certbot
        check_package_installed python3-certbot-apache
        
        log_info "Certificate request command prepared:"
        echo "certbot --apache -d ${DOMAIN_NAME} --email ${CERT_EMAIL} --agree-tos --non-interactive"
        
        log_info "Run the above command after DNS is configured for ${DOMAIN_NAME}"
    else
        log_info "Generating self-signed certificate..."
        
        mkdir -p /etc/kamailio/tls
        
        openssl req -new -newkey rsa:4096 -x509 -sha256 -days 365 -nodes \
            -out /etc/kamailio/tls/cert.pem \
            -keyout /etc/kamailio/tls/key.pem \
            -subj "/C=US/ST=State/L=City/O=Organization/CN=${DOMAIN_NAME}"
        
        chmod 600 /etc/kamailio/tls/key.pem
        chown kamailio:kamailio /etc/kamailio/tls/*
        
        log_success "Self-signed certificate generated"
    fi
    
    save_checkpoint "TLS_PREPARED"
}

show_summary() {
    print_header "Installation Complete!"
    
    cat << EOF
${GREEN}✅ Kamailio has been successfully installed and configured!${NC}

${YELLOW}📋 SYSTEM INFORMATION:${NC}
    Server:         ${DOMAIN_NAME} (${SERVER_IP})
    OS:            ${OS_ID} ${OS_VERSION}
    
${YELLOW}🌐 WEB INTERFACE:${NC}
    URL:           http://${DOMAIN_NAME}/
    Direct:        http://${SERVER_IP}:8080/
    
${YELLOW}☎️  SIP CONFIGURATION:${NC}
    Domain:        ${DOMAIN_NAME}
    UDP Port:      5060
    TCP Port:      5060
    TLS Port:      5061
    RTP Ports:     10000-20000
    
${YELLOW}👥 TEST ACCOUNTS:${NC}
    User 1:        1000@${DOMAIN_NAME}
    User 2:        1001@${DOMAIN_NAME}
    Password:      TestPass2024!
    
${YELLOW}🔒 SECURITY:${NC}
EOF

    if [[ "${SKIP_CROWDSEC}" != true ]]; then
        cat << EOF
    CrowdSec:      Active
    View alerts:   cscli alerts list
    View bans:     cscli decisions list
    Dashboard:     cscli dashboard setup
EOF
    else
        echo "    CrowdSec:      Not installed (--skip-crowdsec)"
    fi
    
    cat << EOF
    
${YELLOW}📁 IMPORTANT FILES:${NC}
    Credentials:   ${PASSWORD_FILE} (sudo required)
    Kamailio:      /etc/kamailio/kamailio.cfg
    Web UI:        /opt/kamailio-webui/
    Logs:          /var/log/kamailio/
    Install Log:   ${INSTALL_LOG}
    
${YELLOW}📝 NEXT STEPS:${NC}
    1. Review credentials:     sudo cat ${PASSWORD_FILE}
    2. Access web interface:   http://${DOMAIN_NAME}/
    3. Configure SIP clients:   Use domain ${DOMAIN_NAME} with test accounts
    4. Monitor security:        cscli metrics
    5. View Kamailio logs:     tail -f /var/log/kamailio/kamailio.log
    
EOF

    if [[ -n "${CERT_EMAIL}" ]]; then
        cat << EOF
${YELLOW}🔐 TLS CERTIFICATE:${NC}
    After configuring DNS for ${DOMAIN_NAME}, run:
    ${WHITE}certbot --apache -d ${DOMAIN_NAME} --email ${CERT_EMAIL} --agree-tos${NC}
    
EOF
    fi
    
    cat << EOF
${CYAN}📚 DOCUMENTATION:${NC}
    Project:       https://github.com/telephony-research/kamailio-installer
    Kamailio:      https://www.kamailio.org/docs/
    Support:       https://github.com/telephony-research/kamailio-installer/issues
    
${GREEN}Thank you for using this installer!${NC}
${WHITE}Contributions and feedback are welcome on GitHub.${NC}

EOF
    
    save_checkpoint "COMPLETE"
}

# ==============================================================================
# MAIN INSTALLATION FLOW
# ==============================================================================

main() {
    # Setup logging
    mkdir -p "${LOG_DIR}"
    touch "${INSTALL_LOG}" "${ERROR_LOG}"
    
    # Clear screen and show banner
    clear
    echo -e "${CYAN}"
    echo "╔════════════════════════════════════════════════════════════╗"
    echo "║                                                            ║"
    echo "║     Kamailio SIP Server Installation Script v${SCRIPT_VERSION}     ║"
    echo "║         Modern VoIP Platform for Research Labs            ║"
    echo "║                                                            ║"
    echo "╚════════════════════════════════════════════════════════════╝"
    echo -e "${NC}\n"
    
    # Parse arguments
    parse_arguments "$@"
    
    # Check if running as root
    check_root
    
    # Load configuration if resuming
    if [[ "${RESUME_MODE}" == true ]]; then
        log_info "Resuming installation from checkpoint..."
        load_config
    fi
    
    # Detect system
    detect_system
    
    # Check prerequisites
    if [[ "${RESUME_MODE}" != true ]] || [[ "$(get_checkpoint)" == "START" ]]; then
        check_prerequisites
    fi
    
    # Save initial configuration
    save_config
    
    # Get current checkpoint
    CHECKPOINT=$(get_checkpoint)
    log_info "Starting from checkpoint: ${CHECKPOINT}"
    
    # Installation flow with checkpoint support
    case "${CHECKPOINT}" in
               "START")
            install_base_packages
            ;&
        "BASE_PACKAGES_INSTALLED")
                       install_mariadb
            save_config  # Save passwords
           
            ;&
        "MARIADB_INSTALLED")
            install_kamailio
            ;&
        "KAMAILIO_INSTALLED")
            configure_kamailio
            ;&
        "KAMAILIO_CONFIGURED")
            install_golang
            ;&
        "GOLANG_INSTALLED")
            install_go_webui
            ;&
        "GO_WEBUI_INSTALLED")
            install_apache
            ;&
        "APACHE_INSTALLED")
            install_crowdsec
            ;&
        "CROWDSEC_INSTALLED"|"CROWDSEC_SKIPPED")
            configure_firewall
            ;&
        "FIREWALL_CONFIGURED")
            create_test_accounts
            ;&
        "TEST_ACCOUNTS_CREATED")
            prepare_tls
            ;&
        "TLS_PREPARED")
            start_services
            ;&
        "SERVICES_STARTED")
            save_credentials
            show_summary
            ;&
        "COMPLETE")
            log_success "Installation complete!"
            ;;
        *)
            log_error "Unknown checkpoint: ${CHECKPOINT}"
            ;;
    esac
    
    # Clean up checkpoint file on successful completion
    if [[ "$(get_checkpoint)" == "COMPLETE" ]]; then
        rm -f "${CHECKPOINT_FILE}"
    fi
}

# ==============================================================================
# SCRIPT ENTRY POINT
# ==============================================================================

# Run main function with all arguments
main "$@"