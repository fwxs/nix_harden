#!/bin/bash

function is_root()
{
    if [ $(id -u) != 0 ]; then
        echo "You need to run this script as root."
        exit 13;
    fi

}

function harden_kernel_stack()
{

    echo "[*] Enabling TCP SYN Cookie protection."
    sysctl -q net.ipv4.tcp_syncookies=1

    echo "[*] Enabling TCP RFC 1337."
    sysctl -q net.ipv4.tcp_rfc1337=1

    # Uncomment this if you want, the script will use (ip/nf)tables instead.
    #echo "[*] Enabling Reverse path filtering."
    #sysctl -q net.ipv4.conf.default.rp_filter=1
    #sysctl -q net.ipv4.conf.all.rp_filter=1

    echo "[!] Do you want to log martian packets? [y/n]"
    read q

    case $q in
        y|Y)
            echo "[*] Enabling log martian packets."
            sysctl -q net.ipv4.conf.default.log_martians=1
            sysctl -q net.ipv4.conf.all.log_martians=1
            ;;
        n|N)
            ;;
    esac

    echo "[*] Disabling ICMP redirection."
    sysctl -q net.ipv4.conf.all.accept_redirects=0
    sysctl -q net.ipv4.conf.default.accept_redirects=0
    sysctl -q net.ipv4.conf.all.secure_redirects=0
    sysctl -q net.ipv4.conf.default.secure_redirects=0
    sysctl -q net.ipv4.conf.default.accept_source_route=0
    sysctl -q net.ipv6.conf.all.accept_redirects=0
    sysctl -q net.ipv6.conf.default.accept_redirects=0

    # Disabling redirection on a non router.
    sysctl -q net.ipv4.conf.all.send_redirects=0
    sysctl -q net.ipv4.conf.default.send_redirects=0

    echo "[!] Do you want to ignore ICMP requests? [y/n]"
    read q

    case $q in
        y|Y)
            echo "[*] Ignoring ICMP requests, at the kernel level."
            sysctl -q net.ipv4.icmp_echo_ignore_all=1
            ;;
        n|N)
            ;;
    esac

    echo "[*] Disabling sysrq"
    sysctl -q kernel.sysrq=0

    echo "[*] Restricting access to kernel logs"
    sysctl -q kernel.dmesg_restrict=1

    echo "[*] Restricting access to kernel pointers"
    sysctl -q kernel.kptr_restrict=1

    echo "[*] Disabling kernel.unprivileged_userns_clone"
    sysctl -q kernel.unprivileged_userns_clone=0
}

function check_if_iface_exists()
{
    if [ ! -L "/sys/class/net/$1" ]; then
        echo "[!] $1 doesn't exists."
        exit 19
    fi
}

function set_ip6tables_fw()
{
    echo "[*] Setting ipv6 tables rules"

    echo "[*] Creating TCP chain."
    ip6tables -N TCP

    echo "[*] Creating UDP chain."
    ip6tables -N UDP

    echo "[*] Allow all incomming RELATED, ESTABLISHED traffic"
    ip6tables -A INPUT $1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    echo "[*] Allow all traffic from localhost"
    ip6tables -A INPUT -i lo -j ACCEPT

    echo "[*] Allow ICMPv6 'Neighbor Discovery'"
    ip6tables -A INPUT $1 -s fe80::/10 -p ipv6-icmp -j ACCEPT

    echo "[*] Allowing 'ICMP echo request' packets"
    ip6tables -A INPUT $1 -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j LOG --log-prefix "[INCOMING ICMP] " --log-level 6 --log-ip-options
    ip6tables -A INPUT $1 -p ipv6-icmp --icmpv6-type 128 -m conntrack --ctstate NEW -j ACCEPT

    echo "[*] Ignoring invalid packets"
    ip6tables -A INPUT $1 -m conntrack --ctstate INVALID -j DROP
    
    echo "[*] Allow new incomming UDP traffic"
    ip6tables -A INPUT $1 -p udp -m conntrack --ctstate NEW -j UDP
    
    echo "[*] Allow new incomming TCP traffic"
    ip6tables -A INPUT $1 -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j TCP
    
    echo "[*] 'Rejecting' TCP-PORTSCAN traffic"
    ip6tables -A INPUT $1 -p tcp -m recent --set --name TCP-PORTSCAN --rsource -j REJECT --reject-with tcp-reset
    
    echo "[*] 'Rejecting' UDP-PORTSCAN traffic"
    ip6tables -A INPUT $1 -p udp -m recent --set --name UDP-PORTSCAN --rsource -j REJECT --reject-with icmp6-port-unreachable
    
    echo "[*] 'Rejecting' all unrelated traffic"
    ip6tables -A INPUT $1 -j REJECT --reject-with icmp6-port-unreachable
    
    echo "[*] 'Rejecting' recent TCP traffic (Port scan)"
    ip6tables -A TCP $1 -p tcp -m recent --update --seconds 60 --name TCP-PORTSCAN --rsource -j REJECT --reject-with tcp-reset

    echo "[*] Allowing outgoing traffic to 22,53,80,443 TCP ports"
    ip6tables -A TCP $IFACE_OPT -p tcp --dport 22 -j ACCEPT
    ip6tables -A TCP $1 -p tcp -m multiport --dports 53,80,443 -j ACCEPT

    echo "[*] 'Rejecting' recent UDP traffic (Port scan)"
    ip6tables -A UDP $1 -p udp -m recent --update --seconds 60 --name UDP-PORTSCAN --rsource -j REJECT --reject-with icmp6-port-unreachable
    
    echo "[*] Allowing outgoing traffic to 53 UDP ports"
    ip6tables -A UDP $1 -p udp -m udp --dport 53 -j ACCEPT

    echo "[*] Setting default DROP policy on FORWARD traffic"
    ip6tables -P FORWARD $1 DROP

    echo "[*] Setting default DROP policy on INPUT traffic"
    ip6tables -P INPUT $1 DROP

    echo "[*] Saving rules"
    ip6tables-save > /etc/iptables/ip6tables.rules

    echo "[*] Activating/Enabling iptables service"
    systemctl start ip6tables.service
    systemctl enable ip6tables.service

}

function set_iptables_fw()
{
    IFACE_OPT=""

    echo "[!] Set iptables rules on all interfaces? [y/n]: "
    read q

    case $q in
        y|Y)
            ;;
        n|Y)
            echo "[*] Specify the interface: "
            read IFACE_OPT

            check_if_iface_exists $IFACE_OPT

            IFACE="-i "$IFACE_OPT
            ;;
        *)
            echo "[!] Select a valid option."
            exit 1
            ;;
    esac

    echo "[*] Disabling reverse path filtering."
    iptables -t raw -A PREROUTING -m rpfilter --invert -j DROP

    echo "[*] Creating TCP chain."
    iptables -N TCP

    echo "[*] Creating UDP chain."
    iptables -N UDP

    echo "[*] Allow all incomming RELATED, ESTABLISHED traffic"
    iptables -A INPUT $IFACE_OPT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

    echo "[*] Allow all traffic from localhost"
    iptables -A INPUT -i lo -j ACCEPT

    echo "[*] Ignoring invalid packets"
    iptables -A INPUT $IFACE_OPT -m conntrack --ctstate INVALID -j DROP

    echo "[*] Allowing 'ICMP echo request' packets"
    iptables -A INPUT $IFACE_OPT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
    iptables -A INPUT $IFACE_OPT -p icmp -m icmp --icmp-type 8 -m conntrack --ctstate NEW -j LOG --log-prefix "[INCOMING ICMP] " --log-level 6 --log-ip-options
    
    echo "[*] Allow new incomming UDP traffic"
    iptables -A INPUT $IFACE_OPT -p udp -m conntrack --ctstate NEW -j UDP
    
    echo "[*] Allow new incomming TCP traffic"
    iptables -A INPUT $IFACE_OPT -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m conntrack --ctstate NEW -j TCP
    
    echo "[*] 'Rejecting' TCP-PORTSCAN traffic"
    iptables -A INPUT $IFACE_OPT -p tcp -m recent --set --name TCP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with tcp-reset
    
    echo "[*] 'Rejecting' UDP-PORTSCAN traffic"
    iptables -A INPUT $IFACE_OPT -p udp -m recent --set --name UDP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with icmp-port-unreachable
    
    echo "[*] 'Rejecting' recent TCP traffic (Port scan)"
    iptables -A TCP $IFACE_OPT -p tcp -m recent --update --seconds 60 --name TCP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with tcp-reset

    echo "[*] Allowing outgoing traffic to 22,53,80,443 TCP ports"
    iptables -A TCP $IFACE_OPT -p tcp --dport 22 -j ACCEPT
    iptables -A TCP $IFACE_OPT -p tcp -m multiport --dports 53,80,443 -j ACCEPT

    echo "[*] 'Rejecting' recent UDP traffic (Port scan)"
    iptables -A UDP $IFACE_OPT -p udp -m recent --update --seconds 60 --name UDP-PORTSCAN --mask 255.255.255.255 --rsource -j REJECT --reject-with icmp-port-unreachable
    
    echo "[*] Allowing outgoing traffic to 53 UDP ports"
    iptables -A UDP $IFACE_OPT -p udp -m udp --dport 53 -j ACCEPT

    echo "[*] 'Rejecting' all unrelated traffic"
    iptables -A INPUT $IFACE_OPT -j REJECT --reject-with icmp-proto-unreachable

    echo "[*] Setting default DROP policy on FORWARD traffic"
    iptables -P FORWARD DROP

    echo "[*] Setting default DROP policy on INPUT traffic"
    iptables -P INPUT DROP

    echo "[*] Saving rules"
    iptables-save > /etc/iptables/iptables.rules

    echo "[*] Activating/Enabling iptables service"
    systemctl start iptables.service
    systemctl enable iptables.service

    set_ip6tables_fw $IFACE_OPT
}

function harden_file_permissions()
{
    echo -ne "\n[*] Hardening file permissions."
    is_proc_mounted=$(grep --only-matching "nosuid,nodev,noexec,hidepid=2,gid=proc" /etc/fstab)

    if [ $is_proc_mounted != 0 ]; then
        echo "[*] Registering procfs with 'nosuid,nodev,noexec,hidepid=2,gid=proc' options"
        echo -ne "#/proc\nproc\t/proc\tnosuid,nodev,noexec,hidepid=2,gid=proc\t0\t0\n" >> /etc/fstab

        echo "[*] Adding modification to systemd-logind"
        if [ -d "/etc/systemd/system/systemd-logind.service.d/" ]; then
            echo -ne "[Service]\nSupplementaryGroups=proc\n" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
        else
            mkdir -p "/etc/systemd/system/systemd-logind.service.d"
            echo -ne "[Service]\nSupplementaryGroups=proc\n" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
        fi
    fi

    echo "[*] Setting the inmutable flag on '/etc/resolv.conf'"
    chattr +i /etc/resolv.conf
    chattr +i /etc/resolv.conf.bak
    chattr +i /etc/resolvconf.conf

    echo "[*] Setting the inmutable flag on '/etc/hosts'"
    chattr +i /etc/hosts

    echo "[*] Restricting read access on /boot directory"
    chmod u=rw /boot

    echo "[*] Restricting /etc/iptables and /etc/nftables.conf read access"
    chmod 400 /etc/iptables
    chmod u=rw /etc/iptables/*.*
    chmod u=rw /etc/nftables.conf

    echo "[*] Restricting /etc/ssh rw access"
    chmod 400 /etc/ssh
    chmod u=rw /etc/ssh/*
}

function secure_sshd()
{
    echo "[*] Setting sshd protocol version 2"
    sed --quiet s'/Protocol \d/Protocol 2/' /etc/ssh/sshd_config

    echo "[*] Disabling ssh root login"
    sed --quiet s'/^PermitRootLogin [a-z]*/PermitRootLogin no/' /etc/ssh/sshd_config

    echo "[!] Ssh Port (Default 22): "
    read ssh_port

    if [ -z $ssh_port ]; then
        ssh_port=22;
    elif [[ $ssh_port =~ ^[^0-9]+$ ]]; then
        echo "[*] $ssh_port is not a number."
        return;
    fi

    # Check this link for more information https://wiki.archlinux.org/index.php/Secure_Shell#Deny"
    # And https://wiki.archlinux.org/index.php/Simple_stateful_firewall#Bruteforce_attacks
    echo "[*] Setting an iptables-based (IPv4) brute force protection on port $ssh_port"
    iptables -N IN_SSH
    iptables -R TCP 2 -p tcp --dport $ssh_port -m conntrack --ctstate NEW -j IN_SSH
    iptables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --set --name DEFAULT --rsource
    iptables -I TCP 3 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 90 --hitcount 3 --name DEFAULT --rsource -j IN_SSH
    iptables -I TCP 4 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 900 --hitcount 4 --name DEFAULT --rsource -j IN_SSH
    iptables -I TCP 5 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 9000 --hitcount 5 --name DEFAULT --rsource -j IN_SSH
    iptables -I TCP 6 -p tcp -m tcp --dport $ssh_port -j ACCEPT
    iptables -A IN_SSH -j LOG --log-prefix "[SSH BRUTEFORCING]" --log-level 7 --log-tcp-options --log-ip-options
    iptables -A IN_SSH -j DROP
    echo "[*] Saving rules"
    iptables-save > /etc/iptables/iptables.rules

    echo "[*] Setting an iptables-based (IPv6) brute force protection on port $ssh_port"
    ip6tables -N IN_SSH
    ip6tables -R TCP 2 -p tcp --dport $ssh_port -m conntrack --ctstate NEW -j IN_SSH
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --set --name DEFAULT --rsource
    ip6tables -I TCP 3 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 90 --hitcount 3 --name DEFAULT --rsource -j IN_SSH
    ip6tables -I TCP 4 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 900 --hitcount 4 --name DEFAULT --rsource -j IN_SSH
    ip6tables -I TCP 5 -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 9000 --hitcount 5 --name DEFAULT --rsource -j IN_SSH
    ip6tables -I TCP 6 -p tcp -m tcp --dport $ssh_port -j ACCEPT
    ip6tables -A IN_SSH -j LOG --log-prefix "[SSH BRUTEFORCING]" --log-level 7 --log-tcp-options --log-ip-options
    ip6tables -A IN_SSH -j DROP

    echo "[*] Saving rules"
    ip6tables-save > /etc/iptables/ip6tables.rules

    # Set inmutable attribute on each user, authorized_keys file.
    USERS=$(ls /home)
    for user in ${USERS[*]};
    do
        au_keys_path="/home/$user/.ssh"
        if [ -d $au_keys_path ] && [ -e "$au_keys_path/authorized_keys" ]; then
            echo "[*] Settng $au_keys_path/authorized_keys read only"
            chmod 400 "$au_keys_path/authorized_keys"

            echo "[*] Setting the immutable bit on $au_keys_path/authorized_keys and $au_keys_path"
            chattr +i "$au_keys_path/authorized_keys"
            chattr +i "$au_keys_path";
        fi
    done
}

function restrict_services()
{
    echo "[!] Mask FTP service? [y/n]: "
    read q

    case $q in
        y|Y)
            echo "[*] Masking FTP service."
            systemctl mask ftpd.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask rpcbind.service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking rpcbind service."
            systemctl mask rpcbind.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask rpcbind.socket? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking rpcbind socket."
            systemctl mask rpcbind.socket
            ;;
        *)
        ;;
    esac

    echo "[!] Mask sshd.service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking ssh service."
            systemctl mask sshd.service
            ;;
        n|N)
            secure_sshd
            ;;
        *)
            echo "[!] Select a valid option."
            ;;
    esac

    echo "[!] Mask sshd.socket? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking ssh socket."
            systemctl mask sshd.socket
            systemctl mask sshd.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask talk service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking talk service."
            systemctl mask ralk.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask rlogin.service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking rlogin service."
            systemctl mask rlogin.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask rsh.service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking rsh service."
            systemctl mask rsh.service
            ;;
        *)
        ;;
    esac

    echo "[!] Mask talk.socket? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking talk socket."
            systemctl mask talk.socket
            ;;
        *)
        ;;
    esac

    echo "[!] Mask telnet.socket? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking telnet socket."
            systemctl mask telnet.socket
            ;;
        *)
        ;;
    esac

    echo "[!] Mask telnet.service? [y/n]: "
    read q
    case $q in
        y|Y)
            echo "[*] Masking telnet service."
            systemctl mask telnet.service
            ;;
        *)
        ;;
    esac
}

echo "[*] Checking if you have superuser permissions."
is_root

# Based on https://wiki.archlinux.org/index.php/Security#Kernel_hardening
echo "[*] Hardening TCP/IP stack."
harden_kernel_stack

# This firewall rules are based on the ArchLinux wiki simple stateful firewall
# Link: https://wiki.archlinux.org/index.php/Simple_stateful_firewall
echo "[*] Setting (ip/nf)tables rules."
set_iptables_fw

echo "[*] Masking services."
restrict_services

echo "[*] Enforcing file permissions"
harden_file_permissions
