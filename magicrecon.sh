#!/bin/bash

# MagicRecon - Comprehensive Reconnaissance and Vulnerability Scanning Tool
# Version: 2.0
# Author: Security Engineer

set -e

# Load configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/configuration.cfg" ]; then
    . "${SCRIPT_DIR}/configuration.cfg"
else
    echo "Error: configuration.cfg not found!"
    exit 1
fi

# Create necessary directories
mkdir -p "$TOOLS_DIR" "$RESULTS_DIR"

# Import functions
. "${SCRIPT_DIR}/functions.sh"

# Main execution
main() {
    print_banner
    check_dependencies
    
    local domain=""
    local wildcard=""
    local list_file=""
    local notify=false
    local mode=""
    
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--domain)
                domain="$2"
                shift 2
                ;;
            -w|--wildcard)
                wildcard="$2"
                shift 2
                ;;
            -l|--list)
                list_file="$2"
                shift 2
                ;;
            -a|--all)
                mode="all"
                shift
                ;;
            -p|--passive)
                mode="passive"
                shift
                ;;
            -x|--active)
                mode="active"
                shift
                ;;
            -r|--recon)
                mode="recon"
                shift
                ;;
            -v|--vulnerabilities)
                mode="vulnerabilities"
                shift
                ;;
            -m|--massive)
                mode="massive"
                shift
                ;;
            -n|--notify)
                notify=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    if [[ -z "$mode" ]]; then
        echo "Error: No mode specified!"
        show_help
        exit 1
    fi
    
    if [[ "$mode" != "massive" && -z "$domain" && -z "$list_file" && -z "$wildcard" ]]; then
        echo "Error: No target specified!"
        show_help
        exit 1
    fi
    
    # Execute based on mode
    case $mode in
        "all")
            if [[ -n "$list_file" ]]; then
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    all "$target" "$notify"
                done < "$list_file"
            else
                all "$domain" "$notify"
            fi
            ;;
        "passive")
            if [[ -n "$list_file" ]]; then
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    passive_recon "$target" "$notify"
                done < "$list_file"
            else
                passive_recon "$domain" "$notify"
            fi
            ;;
        "active")
            if [[ -n "$list_file" ]]; then
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    active_recon "$target" "$notify"
                done < "$list_file"
            else
                active_recon "$domain" "$notify"
            fi
            ;;
        "recon")
            if [[ -n "$list_file" ]]; then
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    all_recon "$target" "$notify"
                done < "$list_file"
            else
                all_recon "$domain" "$notify"
            fi
            ;;
        "vulnerabilities")
            if [[ -n "$list_file" ]]; then
                while IFS= read -r target; do
                    [[ -z "$target" ]] && continue
                    vulnerabilities "$target" "$notify"
                done < "$list_file"
            else
                vulnerabilities "$domain" "$notify"
            fi
            ;;
        "massive")
            if [[ -z "$wildcard" ]]; then
                echo "Error: Wildcard domain required for massive mode!"
                exit 1
            fi
            massive_recon "$wildcard" "$notify"
            ;;
    esac
    
    echo -e "${GREEN}[+] Scan completed successfully!${NORMAL}"
}

main "$@"
