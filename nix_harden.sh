#!/bin/bash

function is_root
{
    if [ $(id -u) != 0 ]; then
        echo "You need to run this script as root."
        exit 13;
    fi

}

function harden_kernel_stack
{
    sysctl_file="/etc/sysctl.conf"

    if ! [ -e $sysctl_file ]; then
        sysctl_file="/etc/sysctl.d/nix_harden.conf"
        touch $sysctl_file
        ln -sf $sysctl_file "/etc/sysctl.conf"
    fi

    echo "[*] Saving configuration in $sysctl_file"

    echo "[*] Enabling Virtual address randomization."
    echo "kernel.randomize_va_space = 2" > $sysctl_file

    echo "[*] Enabling TCP SYN Cookie protection."
    echo "net.ipv4.tcp_syncookies = 1" >> $sysctl_file
    echo "net.ipv4.tcp_synack_retries = 5" >> $sysctl_file

    echo "[*] Enabling TCP RFC 1337."
    echo "net.ipv4.tcp_rfc1337 = 1" >> $sysctl_file

    # Uncomment this if you want, the script will use (ip/nf)tables instead.
    #echo "[*] Enabling Reverse path filtering."
    #sysctl -q net.ipv4.conf.default.rp_filter=1
    #sysctl -q net.ipv4.conf.all.rp_filter=1

    echo -n "[!] Do you want to log martian packets? [y/n] "
    read question

    case $question in
        y|Y)
            echo "[*] Enabling log martian packets."
            echo "net.ipv4.conf.default.log_martians = 1" >> $sysctl_file
            echo "net.ipv4.conf.all.log_martians = 1" >> $sysctl_file
            ;;
        n|N)
            ;;
    esac

    echo "[*] Disabling ICMP redirection."
    echo "net.ipv4.conf.all.accept_redirects = 0" >>$sysctl_file
    echo "net.ipv4.conf.default.accept_redirects = 0" >>$sysctl_file
    echo "net.ipv4.conf.all.secure_redirects = 0" >>$sysctl_file
    echo "net.ipv4.conf.default.secure_redirects = 0" >>$sysctl_file
    echo "net.ipv4.conf.default.accept_source_route = 0" >>$sysctl_file
    echo "net.ipv6.conf.all.accept_redirects = 0" >>$sysctl_file
    echo "net.ipv6.conf.default.accept_redirects = 0" >>$sysctl_file

    # Disabling redirection on a non router.
    echo "net.ipv4.conf.all.send_redirects = 0" >>$sysctl_file
    echo "net.ipv4.conf.default.send_redirects = 0" >>$sysctl_file

    echo -n "[!] Do you want to ignore ICMP requests? [y/n] "
    read question

    case $question in
        y|Y)
            echo "[*] Ignoring ICMP requests, at the kernel level."
            echo "net.ipv4.icmp_echo_ignore_all = 1" >>$sysctl_file
            ;;
        n|N)
            ;;
    esac

    # Thanks to https://www.cyberciti.biz/faq/linux-kernel-etcsysctl-conf-security-hardening/
    echo "[*] Limit number of Router Solicitations to send until assuming no routers are present."
    echo "net.ipv6.conf.default.router_solicitations = 0" >>$sysctl_file
    
    echo "[*] Reject Router Preference in Router advertisement"
    echo "net.ipv6.conf.default.accept_ra_rtr_pref = 0" >>$sysctl_file
    
    echo "[*] Learn Prefix Information in Router Advertisement"
    echo "net.ipv6.conf.default.accept_ra_pinfo = 0" >>$sysctl_file
    
    echo "[*] Reject hop limits from router advertisement"
    echo "net.ipv6.conf.default.accept_ra_defrtr = 0" >>$sysctl_file
    
    echo "[*] Disabling global unicast address to interfaces"
    echo "net.ipv6.conf.default.autoconf = 0" >>$sysctl_file
    
    echo "[*] Don't send neighbor solicitations packets"
    echo "net.ipv6.conf.default.dad_transmits = 0" >>$sysctl_file
    
    echo "[*] Setting 1 global unicast IPv6 address on each interface"
    echo "net.ipv6.conf.default.max_addresses = 1" >>$sysctl_file

    echo "[*] Disabling sysrq"
    echo "kernel.sysrq = 0" >>$sysctl_file

    echo "[*] Restricting access to kernel logs"
    echo "kernel.dmesg_restrict = 1" >>$sysctl_file

    echo "[*] Restricting access to kernel pointers"
    echo "kernel.kptr_restrict = 1" >>$sysctl_file

    echo "[*] Disabling kernel.unprivileged_userns_clone"
    echo "kernel.unprivileged_userns_clone = 0" >>$sysctl_file

    sysctl -q -p $sysctl_file
}

function check_if_iface_exists
{
    if [ ! -L "/sys/class/net/$1" ]; then
        echo "[!] $1 doesn't exists."
        exit 19
    fi
}

function set_ip6tables_fw
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
    ip6tables -P FORWARD DROP

    echo "[*] Setting default DROP policy on INPUT traffic"
    ip6tables -P INPUT DROP

    echo "[*] Saving rules"
    ip6tables-save > /etc/iptables/ip6tables.rules

    echo "[*] Activating/Enabling iptables service"
    systemctl start ip6tables.service
    systemctl enable ip6tables.service

}

function set_iptables_fw
{
    IFACE_OPT=""

    echo -n "[!] Set iptables rules on all interfaces? [y/n]: "
    read question

    case $question in
        y|Y)
            ;;
        n|N)
            echo -n "[*] Specify the interface: "
            read IFACE_OPT

            check_if_iface_exists $IFACE_OPT

	    IFACE_OPT="-i "$IFACE_OPT
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

    set_ip6tables_fw "$IFACE_OPT"
}

function harden_xorg
{
	if [[ -d "/etc/X11" ]]; then
		echo "[*] Hardening Xorg"
		vtswitch_enabled=$(grep -r -E '(Option\s"DontVTSwitch"\s"True")' /etc/X11/)

		if [[ ! $vtswitch_enabled ]]; then
			xorgsec_file="/etc/X11/xorg.conf.d/10-xorgsec.conf"
			
			echo "[*] Setting 'DontVTSwitch' Option"
			echo -ne "Section \"ServerFlags\"\n" >> $xorgsec_file
			echo -ne "\tOption \"DontVTSwitch\" \"True\"\n" >> $xorgsec_file
			
			zap_enabled=$(grep -r -E 'Option\s"DontZap"\s"True"' /etc/X11)
			if [[ ! $zap_enabled ]]; then
				echo "[*] Setting 'DontZap' Option"
				echo -ne "\tOption \"DontZap\" \"True\"\n" >> $xorgsec_file
			fi
			echo -ne "EndSection" >> $xorgsec_file;
		fi
	fi
}

function harden_file_permissions
{
    echo "[*] Hardening file permissions."
    is_proc_mounted=$(grep -E "proc\s{1,}(nosuid,nodev,noexec,hidepid=2,gid=proc)" /etc/fstab)

    if [[ ! $is_proc_mounted ]]; then
        echo "[*] Registering procfs with 'nosuid,nodev,noexec,hidepid=2,gid=proc' options"
        echo -ne "#/proc\nproc\t/proc\tnosuid,nodev,noexec,hidepid=2,gid=proc\n" >> /etc/fstab

        echo "[*] Adding modification to systemd-logind"
        if [ -d "/etc/systemd/system/systemd-logind.service.d/" ]; then
            echo -ne "[Service]\nSupplementaryGroups=proc\n" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
        else
            mkdir -p "/etc/systemd/system/systemd-logind.service.d"
            echo -ne "[Service]\nSupplementaryGroups=proc\n" > /etc/systemd/system/systemd-logind.service.d/hidepid.conf
        fi
    fi


    if [[ ! $(grep -E "/var/tmp\s{1,}none\s{1,}rw,nodev,nosuid,noexec,bind" /etc/fstab) ]]; then
	    echo "[*] Binding /tmp mount with /var/tmp"	
	    echo -ne "# /tmp -> /var/tmp\n" >> /etc/fstab
	    echo -ne "/tmp\t/var/tmp\tnone\trw,nodev,nosuid,noexec,bind\t0 0\n" >> /etc/fstab;
    fi

    is_shm_sec=$(grep --only-matching -E "tmpfs\s{1,}/dev/shm\s{1,}tmpfs\s{1,}rw,nosuid,noexec" /etc/fstab)

    if [[ ! $is_shm_sec ]]; then
        echo "[*] Securing /dev/shm."
        echo -ne "#/dev/shm\n" >> /etc/fstab
        echo -ne "tmpfs\t/dev/shm\ttmpfs\trw,nosuid,noexec,nodev\t0 0\n" >> /etc/fstab
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

    # Thanks to trimstray, practical linux hardening guide
    # https://github.com/trimstray
    echo "[*] Protecting grub bootloader config files"
    chown -R root:root /etc/grub.d
    chmod og-rwx -R /etc/grub.d

    harden_xorg
}

function secure_sshd
{
    echo "[*] Setting sshd protocol version 2"
    sed --quiet s'/^Protocol \d/Protocol 2/' /etc/ssh/sshd_config

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
    iptables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 90 --hitcount 3 --name DEFAULT --rsource -j IN_SSH
    iptables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 900 --hitcount 4 --name DEFAULT --rsource -j IN_SSH
    iptables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 9000 --hitcount 5 --name DEFAULT --rsource -j IN_SSH
    iptables -A IN_SSH -p tcp -m tcp --dport $ssh_port -j ACCEPT
    iptables -A IN_SSH -j LOG --log-prefix "[SSH BRUTEFORCING]" --log-level 7 --log-tcp-options --log-ip-options
    iptables -A IN_SSH -j DROP
    echo "[*] Saving rules"
    iptables-save > /etc/iptables/iptables.rules

    echo "[*] Setting an iptables-based (IPv6) brute force protection on port $ssh_port"
    ip6tables -N IN_SSH
    ip6tables -R TCP 2 -p tcp --dport $ssh_port -m conntrack --ctstate NEW -j IN_SSH
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --set --name DEFAULT --rsource
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 90 --hitcount 3 --name DEFAULT --rsource -j IN_SSH
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 900 --hitcount 4 --name DEFAULT --rsource -j IN_SSH
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -m state --state NEW -m recent --update --seconds 9000 --hitcount 5 --name DEFAULT --rsource -j IN_SSH
    ip6tables -A IN_SSH -p tcp -m tcp --dport $ssh_port -j ACCEPT
    ip6tables -A IN_SSH -j LOG --log-prefix "[SSH BRUTEFORCING]" --log-level 7 --log-tcp-options --log-ip-options
    ip6tables -A IN_SSH -j DROP

    echo "[*] Saving rules"
    ip6tables-save > /etc/iptables/ip6tables.rules

    # Set inmutable attribute on each user, authorized_keys file.
    USERS=$(ls /home)
    for user in ${USERS[*]};
    do
        au_keys_path="/home/$user/.ssh"
        if [[ -d $au_keys_path && -e "$au_keys_path/authorized_keys" ]]; then
            echo "[*] Settng $au_keys_path/authorized_keys read only"
            chmod 400 "$au_keys_path/authorized_keys"

            echo "[*] Setting the immutable bit on $au_keys_path/authorized_keys and $au_keys_path"
            chattr +i "$au_keys_path/authorized_keys"
            chattr +i "$au_keys_path";
        fi
    done
}

function restrict_services
{
    echo -n "[!] Mask FTP service? [y/n]: "
    read question

    case $question in
        y|Y)
            echo "[*] Masking FTP service."
            systemctl mask ftpd.service
            ;;
        *)
        ;;
    esac

    echo -n "[!] Mask rpcbind.service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking rpcbind service."
            systemctl mask rpcbind.service
            systemctl mask rpcbind.socket
            ;;
        *)
        ;;
    esac

    echo -n "[!] Mask sshd.service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking ssh service."
            systemctl mask sshd.socket
            systemctl mask sshd.service
            ;;
        n|N)
            secure_sshd
            ;;
        *)
            ;;
    esac

    echo -n "[!] Mask talk service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking talk service."
            systemctl mask ralk.service
            systemctl mask talk.socket
            ;;
        *)
        ;;
    esac

    echo -n "[!] Mask rlogin.service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking rlogin service."
            systemctl mask rlogin.service
            ;;
        *)
        ;;
    esac

    echo -n "[!] Mask rsh.service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking rsh service."
            systemctl mask rsh.service
            ;;
        *)
        ;;
    esac

    echo -n "[!] Mask telnet.service? [y/n]: "
    read question
    case $question in
        y|Y)
            echo "[*] Masking telnet service."
            systemctl mask telnet.service
            systemctl mask telnet.socket
            ;;
        *)
        ;;
    esac
}

echo "[*] Checking if you have superuser permissions."
is_root

echo "[*] Locking root."
passwd -l root

# Based on https://wiki.archlinux.org/index.php/Security#Kernel_hardening
echo "[*] Hardening Kernel stack."
harden_kernel_stack

# This firewall rules are based on the ArchLinux wiki simple stateful firewall
# Link: https://wiki.archlinux.org/index.php/Simple_stateful_firewall
echo -n "[*] Set new iptables rules [y/n]? "
read question

case $question in
	y|Y)
		echo "[*] Flushing iptables rules."
		iptables -F
		
		echo "[*] Flushing ip6tables rules."
		ip6tables -F
		
		echo "[*] Setting (ip/nf)tables rules."
		set_iptables_fw
		;;
	*)
	;;
esac

echo "[*] Masking services."
restrict_services

echo "[*] Enforcing file permissions"
harden_file_permissions

