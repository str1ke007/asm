#!/bin/bash

set -o pipefail  # Ensure pipeline failures are properly handled

# Configuration
CONFIG_FILE="$HOME/asm/config/config.conf"
LOG_FILE="$HOME/asm/log/asm.log"
REPORT_DIR="$HOME/asm/reports"
API_KEYS_FILE="$HOME/asm/api/api_keys.conf"
TEMP_DIR="/tmp/asm_tmp"

# Default timeouts (in seconds) - moved after argument parsing
DNS_TIMEOUT=10
PORT_SCAN_TIMEOUT=300
AMASS_TIMEOUT=600
OPERATION_TIMEOUT=30  # Replaces DEFAULT_TIMEOUT

# Exit codes
readonly E_SUCCESS=0
readonly E_GENERAL=1
readonly E_CONFIG=2
readonly E_DEPS=3
readonly E_ARGS=4
readonly E_TIMEOUT=5
readonly E_NETWORK=6

# Colors for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly PURPLE='\033[0;35m'
readonly NC='\033[0m'

# Input validation functions
validate_target() {
    local target=$1
    
    # Function to validate IP address
    is_valid_ip() {
        local ip=$1
        # Enhanced IP validation with subnet support
        if [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
            local IFS='.'
            local -a octets=($ip)
            for octet in "${octets[@]}"; do
                # Remove CIDR notation for octet validation
                octet=${octet%/*}
                if ! [[ $octet =~ ^[0-9]+$ ]] || [ $octet -lt 0 ] || [ $octet -gt 255 ]; then
                    return 1
                fi
            done
            # Validate CIDR if present
            if [[ $ip =~ /([0-9]+)$ ]]; then
                local cidr="${BASH_REMATCH[1]}"
                if [ "$cidr" -lt 0 ] || [ "$cidr" -gt 32 ]; then
                    return 1
                fi
            fi
            return 0
        fi
        return 1
    }

    # Function to validate domain name
    is_valid_domain() {
        local domain=$1
        # Enhanced domain validation including more TLDs and handling international domains
        if [[ $domain =~ ^([a-zA-Z0-9](([a-zA-Z0-9-]){0,61}[a-zA-Z0-9])?\.)+[a-zA-Z][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$ ]]; then
            # Additional checks for domain resolution
            if ! dig +short "$domain" >/dev/null 2>&1; then
                log "WARNING" "Domain $domain could not be resolved"
                return 2
            fi
            return 0
        fi
        return 1
    }

    # Determine target type and validate
    local target_type=""
    if is_valid_ip "$target"; then
        target_type="ip"
        log "INFO" "Valid IP address detected: $target"
        return 0
    elif is_valid_domain "$target"; then
        target_type="domain"
        log "INFO" "Valid domain detected: $target"
        return 0
    else
        log "ERROR" "Invalid target: $target"
        log "ERROR" "Target must be a valid IP address or domain name"
        return 1
    fi
}

# Trap handler for cleanup
cleanup() {
    local exit_code=$?
    [ -d "$TEMP_DIR" ] && rm -rf "$TEMP_DIR"
    log "INFO" "Script terminated with exit code: $exit_code"
    exit $exit_code
}

trap cleanup EXIT
trap 'exit $E_GENERAL' INT TERM

# Enhanced error handling function
handle_error() {
    local exit_code=$1
    local error_msg=$2
    log "ERROR" "$error_msg"
    exit "$exit_code"
}

strip_ansi_codes() {
    # Remove ANSI escape sequences
    sed 's/\x1B\[[0-9;]*[JKmsu]//g'
}

# Load configuration and API keys
load_config() {
    local config_loaded=false
    local api_keys_loaded=false

    if [ -f "$CONFIG_FILE" ]; then
        if source "$CONFIG_FILE"; then
            config_loaded=true
        else
            handle_error $E_CONFIG "Failed to load configuration file: $CONFIG_FILE"
        fi
    else
        handle_error $E_CONFIG "Configuration file not found: $CONFIG_FILE"
    fi

    if [ -f "$API_KEYS_FILE" ]; then
        if source "$API_KEYS_FILE"; then
            api_keys_loaded=true
        else
            log "WARNING" "Failed to load API keys file: $API_KEYS_FILE"
        fi
    fi

    # Validate essential configuration
    [[ -z "$SUBFINDER_CONFIG" ]] && log "WARNING" "SUBFINDER_CONFIG not set"
}

# Enhanced logging with rotation
log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local log_entry="[$timestamp] [$level] $message"
    
    # Rotate log if it exceeds 10MB
    if [ -f "$LOG_FILE" ] && [ "$(stat -f%z "$LOG_FILE" 2>/dev/null || stat -c%s "$LOG_FILE")" -gt 10485760 ]; then
        mv "$LOG_FILE" "$LOG_FILE.old"
    fi
    
    echo -e "$log_entry" >> "$LOG_FILE"
    
    if [ "$SILENT_MODE" != "true" ]; then
        case $level in
            "PROGRESS") echo -e "${BLUE}[*]${NC} $message" ;;
            "ERROR") echo -e "${RED}[-]${NC} $message" >&2 ;;
            "WARNING") echo -e "${YELLOW}[!]${NC} $message" ;;
            "DONE") echo -e "${GREEN}[+]${NC} $message" ;;
        esac
    fi
}

check_dependencies() {
    local required_tools=("dig" "whois" "curl" "jq" "subfinder")
    local optional_tools=("amass" "dnsx" "nmap")
    local missing_required=()
    local missing_optional=()

    # Check required tools with version validation
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_required+=("$tool")
        else
            case $tool in
                "dig")
                    if dig -v 2>&1 | grep -q "DiG"; then
                        log "INFO" "Dig version verified"
                    fi
                    ;;
                "subfinder")
                    if subfinder -version 2>&1 | grep -q "version"; then
                        log "INFO" "Subfinder version verified"
                    fi
                    ;;
            esac
        fi
    done

    if [ ${#missing_required[@]} -ne 0 ]; then
        handle_error $E_DEPS "Missing required tools: ${missing_required[*]}"
    fi

    # Check optional tools
    for tool in "${optional_tools[@]}"; do
        if ! command -v "$tool" &> /dev/null; then
            missing_optional+=("$tool")
            case $tool in
                "amass") AMASS_AVAILABLE=false ;;
                "dnsx") DNSX_AVAILABLE=false ;;
                "nmap") NMAP_AVAILABLE=false ;;
            esac
        else
            case $tool in
                "amass") AMASS_AVAILABLE=true ;;
                "dnsx") DNSX_AVAILABLE=true ;;
                "nmap") NMAP_AVAILABLE=true ;;
            esac
        fi
    done

    [ ${#missing_optional[@]} -ne 0 ] && log "WARNING" "Missing optional tools: ${missing_optional[*]}"
}

passive_dns_enum() {
    local domain=$1
    local output_file="$REPORT_DIR/${domain}_dns.txt"
    local max_retries=3
    local retry_count=0
    
    log "PROGRESS" "Running DNS enumeration..."
    
    while [ $retry_count -lt $max_retries ]; do
        if {
            timeout "$DNS_TIMEOUT" dig +noall +answer "$domain" ANY &&
            timeout "$DNS_TIMEOUT" dig +noall +answer "$domain" MX &&
            timeout "$DNS_TIMEOUT" dig +noall +answer "$domain" TXT
        } > "$output_file" 2>/dev/null; then
            break
        else
            retry_count=$((retry_count + 1))
            [ $retry_count -lt $max_retries ] && sleep 2
        fi
    done
    
    if [ $retry_count -eq $max_retries ]; then
        log "WARNING" "DNS enumeration partially failed after $max_retries attempts"
    fi
    
    # Check for wildcard DNS
    if dig "random123456.$domain" +short &>/dev/null; then
        log "WARNING" "Wildcard DNS detected for $domain"
        echo "WARNING: Wildcard DNS detected" >> "$output_file"
    fi
    
    log "DONE" "DNS enumeration completed"
}

# Enhanced subdomain enumeration with rate limiting and error handling
enumerate_subdomains() {
    local domain=$1
    local subfinder_output="$TEMP_DIR/${domain}_subfinder.txt"
    local amass_output="$TEMP_DIR/${domain}_amass.txt"
    local combined_output="$TEMP_DIR/${domain}_all_subdomains.txt"
    local final_output="$REPORT_DIR/${domain}_subdomains.txt"
    local error_count=0
    
    mkdir -p "$TEMP_DIR" || handle_error $E_GENERAL "Failed to create temporary directory"
    
    log "PROGRESS" "Starting subdomain enumeration..."

    # Run subfinder with rate limiting
    (
        if ! subfinder -d "$domain" ${SUBFINDER_CONFIG:+-config "$SUBFINDER_CONFIG"} \
            -o "$subfinder_output" -silent -rate-limit 10 > /dev/null 2>&1; then
            log "WARNING" "Subfinder execution failed"
            error_count=$((error_count + 1))
        fi
    ) &
    
    # Run amass if available
    if [ "$AMASS_AVAILABLE" = true ]; then
        (
            local amass_cmd="amass enum -d $domain -o $amass_output -silent"
            [ "$PASSIVE_MODE" = true ] && amass_cmd="$amass_cmd -passive"
            
            if ! timeout "$AMASS_TIMEOUT" $amass_cmd; then
                log "WARNING" "Amass execution failed"
                error_count=$((error_count + 1))
            fi
        ) &
    fi
    
    wait
    
    # Process and deduplicate results
    {
        touch "$combined_output"
        for file in "$subfinder_output" "$amass_output"; do
            [ -f "$file" ] && cat "$file" >> "$combined_output"
        done
        sort -u "$combined_output" > "$TEMP_DIR/${domain}_unique_subdomains.txt"
    } || handle_error $E_GENERAL "Failed to process subdomain results"
    
    # Run DNSx validation if available
    if [ "$DNSX_AVAILABLE" = true ]; then
        (
            local dnsx_output="$TEMP_DIR/${domain}_dnsx.txt"
            if ! dnsx -l "$TEMP_DIR/${domain}_unique_subdomains.txt" -a -aaaa -cname -resp -retry 2 -silent > "$dnsx_output"; then
                log "WARNING" "DNSx validation failed"
                error_count=$((error_count + 1))
            fi
        ) &
    fi
    
    # Format final results
    (
        {
            echo "=== Subdomain Enumeration Results ==="
            echo "Timestamp: $(date)"
            echo "Domain: $domain"
            echo "Mode: ${PASSIVE_MODE:+Passive}${ACTIVE_MODE:+Active}"
            echo -e "\n=== Tool Results ===\n"
            
            [ -f "$subfinder_output" ] && {
                echo "=== SubFinder Results ==="
                sed 's/^/[SubFinder] /' "$subfinder_output"
            }
            
            [ -f "$amass_output" ] && {
                echo -e "\n=== Amass Results ==="
                while IFS= read -r line; do
                    cleaned_line=$(echo "$line" | strip_ansi_codes)
                    echo "[Amass] $cleaned_line"
                done < "$amass_output"
            }
        } > "$final_output"
    ) &
    
    wait
    
    # Append DNSx results
    if [ "$DNSX_AVAILABLE" = true ] && [ -f "$TEMP_DIR/${domain}_dnsx.txt" ]; then
        {
            echo -e "\n=== DNSx Validation Results ==="
            sed 's/^/[DNSx] /' "$TEMP_DIR/${domain}_dnsx.txt"
        } >> "$final_output"
    fi
    
    # Cleanup temporary files
    rm -f "$subfinder_output" "$amass_output" "$combined_output" "$TEMP_DIR/${domain}_unique_subdomains.txt" "$TEMP_DIR/${domain}_dnsx.txt"
    
    if [ $error_count -gt 0 ]; then
        log "WARNING" "Subdomain enumeration completed with $error_count errors"
    else
        log "DONE" "Subdomain enumeration completed successfully"
    fi
}

# Enhanced Nmap scanning function with better error handling and optimization
perform_nmap_scan() {
    local target=$1
    local output_file="$REPORT_DIR/${target}_nmap.txt"
    local temp_output_file="$TEMP_DIR/${target}_nmap_temp.txt"
    local scan_status=0
    local retry_count=0
    local max_retries=3
    
    if [ "$NMAP_AVAILABLE" = false ] || [ "$PASSIVE_MODE" = true ]; then
        return 0
    fi
    
    log "PROGRESS" "Starting Nmap scan for $target..."

    # Create temporary directory if it doesn't exist
    mkdir -p "$TEMP_DIR" || {
        log "ERROR" "Failed to create temporary directory"
        return $E_GENERAL
    }

    # Determine scan type based on target
    local scan_target="$target"
    local scan_type=""
    if [[ $target =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        scan_type="ip"
    else
        scan_type="domain"
        [[ ! "$target" =~ ^www\. ]] && scan_target="www.$target"
    fi

    # Prepare scan options based on mode and target type
    local scan_opts=()
    if [ "$ACTIVE_MODE" = true ]; then
        scan_opts=(
            "-sC"        # Default script scan
            "-sV"        # Version detection
            "-O"         # OS detection
            "-T4"
            "-A"
            "--max-retries=2"
            # "--max-rtt-timeout=500ms"
            "--min-rate=300"
            "--max-rate=1000"
            # "--defeat-rst-ratelimit"
        )
        [ "$scan_type" = "domain" ] && scan_opts+=("-Pn")  # Skip host discovery for domains
    else
        scan_opts=(
            "-sS"        # SYN scan
            "-T3"        # Timing template (normal)
            "--max-retries=1"
            # "--max-rtt-timeout=300ms"
        )
    fi

    # Function to handle scan interruption
    handle_scan_interrupt() {
        log "WARNING" "Nmap scan interrupted. Cleaning up..."
        [ -f "$temp_output_file" ] && rm -f "$temp_output_file"
        return $E_GENERAL
    }

    # Set up interrupt handler
    trap handle_scan_interrupt INT TERM

    # Perform scan with retries
    while [ $retry_count -lt $max_retries ]; do
        log "INFO" "Scan attempt $((retry_count + 1)) of $max_retries"
        
        if timeout "$PORT_SCAN_TIMEOUT" nmap "${scan_opts[@]}" "$scan_target" -oN "$temp_output_file" >/dev/null 2>&1; then
            scan_status=$?
            if [ $scan_status -eq 0 ] && [ -s "$temp_output_file" ]; then
                break
            fi
        else
            scan_status=$?
        fi

        retry_count=$((retry_count + 1))
        if [ $retry_count -lt $max_retries ]; then
            log "WARNING" "Scan attempt failed (status $scan_status). Retrying in 5 seconds..."
            sleep 5
        fi
    done

    # Process scan results
    if [ $scan_status -eq 0 ] && [ -s "$temp_output_file" ]; then
        # Post-process the output to add metadata
        {
            echo "# Nmap Scan Report"
            echo "# Target: $target"
            echo "# Timestamp: $(date)"
            echo "# Scan Mode: ${ACTIVE_MODE:+Active}${PASSIVE_MODE:+Passive}"
            echo "# Scan Options: ${scan_opts[*]}"
            echo "# ----------------------------------------"
            cat "$temp_output_file"
        } > "$output_file"

        log "DONE" "Nmap scan completed successfully"
        [ -f "$temp_output_file" ] && rm -f "$temp_output_file"
        return 0
    else
        log "ERROR" "Nmap scan failed after $max_retries attempts (status $scan_status)"
        [ -f "$temp_output_file" ] && rm -f "$temp_output_file"
        return $E_GENERAL
    fi
}

# Enhanced zone transfer check with improved error handling
check_zone_transfer() {
    local domain=$1
    local output_file="$REPORT_DIR/${domain}_zonetransfer.txt"
    local temp_file="$TEMP_DIR/${domain}_zonetransfer_temp.txt"
    local nameservers
    local transfer_found=false
    local failed_string="failed"
    
    log "PROGRESS" "Checking zone transfer vulnerability for $domain..."
    
    # Get nameservers with timeout and retry
    local retry_count=0
    while [ $retry_count -lt 3 ]; do
        if nameservers=$(timeout 10 dig +short NS "$domain" 2>/dev/null); then
            break
        fi
        retry_count=$((retry_count + 1))
        [ $retry_count -lt 3 ] && sleep 2
    done
    
    if [ -z "$nameservers" ]; then
        log "ERROR" "Failed to retrieve nameservers for $domain"
        return $E_NETWORK
    fi
    
    # Create temporary directory for individual NS results
    local ns_temp_dir="$TEMP_DIR/ns_results"
    mkdir -p "$ns_temp_dir"
    
    {
        echo "=== DNS Zone Transfer Check ==="
        echo "Timestamp: $(date)"
        echo "Domain: $domain"
        echo -e "\nNameservers found:"
        echo "$nameservers"
        echo -e "\nZone Transfer Results:"
    } > "$temp_file"
    
    # Test each nameserver in parallel with proper error handling
    local ns_pids=()
    while IFS= read -r ns; do
        if [ -n "$ns" ]; then
            (
                local ns_output="$ns_temp_dir/${ns//[^a-zA-Z0-9]/_}"
                echo -e "\nTesting nameserver: $ns" > "$ns_output"
                if timeout 30 dig @"$ns" "$domain" AXFR +noall +answer 2>/dev/null > "${ns_output}_transfer"; then
                    if [ -s "${ns_output}_transfer" ]; then
                        cat "${ns_output}_transfer" >> "$ns_output"
                        transfer_found=true
                    else
                        echo "Zone transfer attempt failed - Transfer denied" >> "$ns_output"
                    fi
                else
                    echo "Zone transfer attempt failed - Connection error or timeout" >> "$ns_output"
                fi
            ) & ns_pids+=($!)
        fi
    done <<< "$nameservers"
    
    # Wait for all zone transfer tests to complete
    for pid in "${ns_pids[@]}"; do
        wait $pid
    done
    
    # Combine results
    find "$ns_temp_dir" -type f -not -name "*_transfer" -exec cat {} + >> "$temp_file"
    
    # Cleanup temporary files
    rm -rf "$ns_temp_dir"
    
    # Move temporary file to final location
    mv "$temp_file" "$output_file"
    
    # Check transfer_found status and log appropriately
    if [ "$transfer_found" = false ]; then
        log "DONE" "Zone transfer check completed"
    else
        log "WARNING" "Zone transfer vulnerability found for $domain!"
    fi
    
    return $E_SUCCESS
}

# Generate HTML report
generate_report() {
    local domain=$1
    local report_file="$REPORT_DIR/${domain}_report.html"
    local temp_report="$TEMP_DIR/${domain}_report_temp.html"
    local scan_date=$(date)
    local scan_duration=$(($(date +%s) - start_time))
    
    log "INFO" "Generating HTML report for $domain"
    
    # Create temp report file
    {
        cat << EOF > "$temp_report"
<!DOCTYPE html>
<html>
<head>
    <title>ASM Report - $domain</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 30px;
        }
        .section {
            margin: 25px 0;
            padding: 20px;
            border: 1px solid #e1e1e1;
            border-radius: 5px;
            background: #fff;
        }
        h3 {
            color: #34495e;
            margin-top: 0;
            margin-bottom: 15px;
            font-size: 1.2em;
        }
        h2 {
            color: #2980b9;
            margin-top: 0;
        }
        pre {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            overflow-x: auto;
            border: 1px solid #e1e1e1;
            font-family: 'Consolas', monospace;
            line-height: 1.4;
        }
        .subsection {
            margin: 15px 0;
            padding: 15px;
            border: 1px solid #e1e1e1;
            border-radius: 4px;
            background: #fafafa;
        }
        .subfinder-output {
            border-left: 4px solid #00a0a0;
        }
        .amass-output {
            border-left: 4px solid #9b59b6;
        }
        .dnsx-output {
            border-left: 4px solid #3498db;
        }        
        .tool-info {
            color: #666;
            font-style: italic;
            margin-bottom: 10px;
            padding: 5px 0;
        }
        .vulnerability {
            color: #e74c3c;
            font-weight: bold;
        }
        .subfinder-output {
            color: #00a0a0;
        }
        .amass-output {
            color: #9b59b6;
        }
        .dnsx-output {
            color: #3498db;
        }
        .metrics {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin: 20px 0;
        }
        .metric-card {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            border: 1px solid #dee2e6;
        }
        .metric-value {
            font-size: 1.5em;
            font-weight: bold;
            color: #2c3e50;
        }
        .warning {
            background-color: #fff3cd;
            border-color: #ffeeba;
            color: #856404;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .error {
            background-color: #f8d7da;
            border-color: #f5c6cb;
            color: #721c24;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .timestamp {
            color: #6c757d;
            font-size: 0.9em;
            margin-bottom: 20px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Attack Surface Mapping Report - $domain</h1>
        <div class="timestamp">Generated on: $scan_date</div>
EOF

        # Add scan overview section
        cat << EOF >> "$temp_report"
        <div class="section">
            <h2>Scan Overview</h2>
            <div class="metrics">
                <div class="metric-card">
                    <h3>Scan Duration</h3>
                    <div class="metric-value">${scan_duration}s</div>
                </div>
                <div class="metric-card">
                    <h3>Scan Mode</h3>
                    <div class="metric-value">${PASSIVE_MODE:+Passive}${ACTIVE_MODE:+Active}</div>
                </div>
                <div class="metric-card">
                    <h3>Tools Used</h3>
                    <div class="metric-value">
                        subfinder${AMASS_AVAILABLE:+, amass}${DNSX_AVAILABLE:+, dnsx}${NMAP_AVAILABLE:+, nmap}
                    </div>
                </div>
            </div>
        </div>
EOF
        
        # Add DNS Information Section
        if [ -f "$REPORT_DIR/${domain}_dns.txt" ]; then
            cat << EOF >> "$temp_report"
        <div class="section">
            <h2>DNS Information</h2>
            <pre>$(cat "$REPORT_DIR/${domain}_dns.txt")</pre>
        </div>
EOF
        fi
        
        # Add Subdomain Section
        if [ -f "$REPORT_DIR/${domain}_subdomains.txt" ]; then
            local subdomain_count=$(grep -c "\[SubFinder\]\|\[Amass\]\|\[DNSx\]" "$REPORT_DIR/${domain}_subdomains.txt")
            cat << EOF >> "$temp_report"
        <div class="section">
            <h2>Subdomains Discovered</h2>
            <div class="metric-card">
                <h3>Total Subdomains</h3>
                <div class="metric-value">$subdomain_count</div>
            </div>
            
            <!-- SubFinder Results -->
            <div class="subsection subfinder-output">
                <h3>SubFinder Results</h3>
                <pre>$(grep "\[SubFinder\]" "$REPORT_DIR/${domain}_subdomains.txt" 2>/dev/null | sed 's/\[SubFinder\] //')</pre>
            </div>
EOF

            # Add Amass results if available
            if [ "$AMASS_AVAILABLE" = true ]; then
                cat << EOF >> "$temp_report"
            <div class="subsection amass-output">
                <h3>Amass Results</h3>
                <pre>$(grep "\[Amass\]" "$REPORT_DIR/${domain}_subdomains.txt" 2>/dev/null | sed 's/\[Amass\] //' | strip_ansi_codes)</pre>
            </div>
EOF
            fi

            # Add DNSx results if available
            if [ "$DNSX_AVAILABLE" = true ]; then
                cat << EOF >> "$temp_report"
            <div class="subsection dnsx-output">
                <h3>DNSx Results</h3>
                <pre>$(grep "\[DNSx\]" "$REPORT_DIR/${domain}_subdomains.txt" 2>/dev/null | sed 's/\[DNSx\] //')</pre>
            </div>
EOF
            fi

            echo "</div>" >> "$temp_report"
        fi
        
        # Add Zone Transfer Results
        if [ -f "$REPORT_DIR/${domain}_zonetransfer.txt" ]; then
            cat << EOF >> "$temp_report"
        <div class="section">
            <h2>DNS Zone Transfer Results</h2>
            <pre>$(cat "$REPORT_DIR/${domain}_zonetransfer.txt")</pre>
        </div>
EOF
        fi
        
        # Add Nmap Results if available
        if [ -f "$REPORT_DIR/${domain}_nmap.txt" ]; then
            local open_ports=$(grep "^[0-9].*open[[:space:]]" "$REPORT_DIR/${domain}_nmap.txt" | wc -l)
            cat << EOF >> "$temp_report"
        <div class="section">
            <h2>Nmap Scan Results</h2>
            <div class="metric-card">
                <h3>Open Ports</h3>
                <div class="metric-value">$open_ports</div>
            </div>
            <pre>$(cat "$REPORT_DIR/${domain}_nmap.txt")</pre>
        </div>
EOF
        fi
        
        # Add Warnings Section if any were logged
        if grep -q "WARNING" "$LOG_FILE"; then
            cat << EOF >> "$temp_report"
        <div class="section">
            <h2>Scan Warnings</h2>
            <div class="warning">
                <pre>$(grep "WARNING" "$LOG_FILE" | sed 's/\[[0-9-]\{10\} [0-9:]\{8\}\] \[WARNING\] //')</pre>
            </div>
        </div>
EOF
        fi
        
        # Close HTML
        echo "</div></body></html>" >> "$temp_report"
        
        # Move temporary report to final location
        if ! mv "$temp_report" "$report_file"; then
            log "ERROR" "Failed to save final report"
            return $E_GENERAL
        fi
        
        log "DONE" "Report generated successfully at $report_file"
        return $E_SUCCESS
    }
}

# Enhanced main function with argument validation
main() {
    local domain=""
    SILENT_MODE="false"
    local start_time=$(date +%s)
    
    # Validate and parse arguments
    while getopts ":d:t:spa" opt; do
        case $opt in
            d) 
                domain="$OPTARG"
                if ! validate_target "$domain"; then
                    handle_error $E_ARGS "Invalid target: $domain"
                fi
                ;;
            t)
                if ! [[ "$OPTARG" =~ ^[0-9]+$ ]]; then
                    handle_error $E_ARGS "Timeout must be a number: $OPTARG"
                fi
                OPERATION_TIMEOUT="$OPTARG"
                # Scale other timeouts proportionally
                DNS_TIMEOUT=$((OPERATION_TIMEOUT/3))
                PORT_SCAN_TIMEOUT=$((OPERATION_TIMEOUT*10))
                AMASS_TIMEOUT=$((OPERATION_TIMEOUT*20))
                ;;
            s) SILENT_MODE="true" ;;
            p) PASSIVE_MODE=true; ACTIVE_MODE=false ;;
            a) ACTIVE_MODE=true; PASSIVE_MODE=false ;;
            :) handle_error $E_ARGS "Option -$OPTARG requires an argument" ;;
            \?) handle_error $E_ARGS "Invalid option: -$OPTARG" ;;
        esac
    done
    
    [ -z "$domain" ] && handle_error $E_ARGS "Target parameter is required. Usage: $0 -d domain.com|ip [-t timeout] [-s] [-p|-a]"
    
    # Initialize directories and logging
    mkdir -p "$REPORT_DIR" "$TEMP_DIR" || handle_error $E_GENERAL "Failed to create required directories"
    echo "--- ASM Tool Log - $(date) ---" > "$LOG_FILE"
    
    # Load configuration and check dependencies
    load_config
    check_dependencies
    
    echo -e "\n${CYAN}[*] Starting Attack Surface Mapping for ${domain}${NC}\n"
    
    # Execute reconnaissance tasks with job control
    local pids=()
    passive_dns_enum "$domain" & pids+=($!)
    check_zone_transfer "$domain" & pids+=($!)
    enumerate_subdomains "$domain" & pids+=($!)
    [ "$ACTIVE_MODE" = true ] && perform_nmap_scan "$domain" & pids+=($!)
    
    # Monitor background jobs
    local failed_jobs=0
    for pid in "${pids[@]}"; do
        if ! wait $pid; then
            failed_jobs=$((failed_jobs + 1))
            log "ERROR" "Task with PID $pid failed"
        fi
    done
    
    # Generate report and cleanup
    log "PROGRESS" "Generating final report..."
    generate_report "$domain"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    echo -e "\n${GREEN}[+] Attack surface mapping completed in ${duration}s with $failed_jobs failed tasks${NC}"
    echo -e "${BLUE}[*] Report available at: $REPORT_DIR/${domain}_report.html${NC}\n"
    
    [ $failed_jobs -gt 0 ] && exit $E_GENERAL
    exit $E_SUCCESS
}

# Execute main function with all arguments
main "$@"