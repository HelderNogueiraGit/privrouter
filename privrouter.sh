#!/bin/bash
#author: Helder Nogueira
#target: Privacy-Focused Virtual Routing Applicance

#clean previous iptables rules
iptables -F
iptables -t nat

iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP

iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

#iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

#enable web services (later to implement web portal using react)
#systemctl start php8.2-fpm &
#systemctl start nginx &
#sleep 2;

#make sure no previous instances are running to prevent conflicts
sudo killall openvpn dhclient

#setup lan interface 
ip addr add 10.0.0.254/24 dev usb0
ip link set dev usb0 up

#setup ssh for binding to lan interface only
sed -i '/^.*ListenAddress.*$/d' /etc/ssh/sshd_config
sed -i "1iListenAddress 10.0.0.254" /etc/ssh/sshd_config
sleep 1
sudo systemctl start ssh
echo "waiting" > /tmp/status

#flag to not initialize privrouter
#if [ -f /etc/privrouter/disabled ]; then echo "running" > /tmp/status; exit 0; fi
rm -rf /tmp/pass /tmp/lock

#check for privrouter key to unlock encrypted partition (transferred via ssh)
while [ ! -d /tmp/privrouter ]; do 

	if [ ! -f /tmp/pass ]; then sleep 2; continue; fi
	echo -n $(cat /tmp/pass 2>/dev/null) | sudo cryptsetup luksOpen /etc/privrouter/app.volume privrouterfs --key-file=-	

	if [ "$(lsblk | grep 'privrouterfs')" != "" ]; then 

		echo "ok" > /tmp/lock
		mkdir /tmp/privrouter
		mount /dev/mapper/privrouterfs /tmp/privrouter
	else sudo poweroff -f; fi
	sleep 2; 
done

#cleaning temp privrouter directories
echo "booting"  > /tmp/status
rm -rf /tmp/privrouter/*.inf
rm -rf /tmp/privrouter/tmpfs/*
rm -rf /tmp/privrouter/logs/*

#getting lan conf files
LAN_CONF='/tmp/privrouter/lan.conf';
LAN_ADDR=$(grep '^lan_addr' $LAN_CONF | head -n 1 | cut -d '=' -f2);
LAN_MGMT_ADDR=$(grep '^lan_mgmt_addr' $LAN_CONF | head -n 1 | cut -d '=' -f2);
iptables -A INPUT -i usb0 -p tcp -s $LAN_MGMT_ADDR -d $LAN_ADDR --dport 22 -j ACCEPT

#waiting for interfaces to be available before proceed
while [ "$(ip -br a | grep 'usb0')" == "" ]; do sleep 1; done
while [ "$(ip -br a | grep 'wlan0')" == "" ]; do sleep 1; done 

#adding second virtual wifi interface if supported
#sudo iw dev wlan0 interface add wlan1 type station

#resetting routing tables on system
cp /tmp/privrouter/baks/rt_tables /etc/iproute2/rt_tables

#loading circuits conf files
circuit_idx=1
for circuit in /tmp/privrouter/circuits/*.circuit; do

	#loading vars from conf files associated with circuit conf
	cir_enabled=$(grep -a '^enabled' $circuit | head -n 1 | cut -d '=' -f2);
	gw_name=$(grep -a '^gateway' $circuit | head -n 1 | cut -d '=' -f2);
	tun_name=$(grep -a '^tunnel' $circuit | head -n 1 | cut -d '=' -f2);
	net_name=$(grep -a '^network' $circuit | head -n 1 | cut -d '=' -f2);
	rst_name=$(grep -a '^ruleset' $circuit | head -n 1 | cut -d '=' -f2);

	gw=/tmp/privrouter/gateways/${gw_name}.gateway
	tun=/tmp/privrouter/tunnels/${tun_name}.tunnel
	net=/tmp/privrouter/networks/${net_name}.network
	rst=/tmp/privrouter/rulesets/${rst_name}.ruleset

	#checking if is supposed to initialize or if it is broken
	if [ "$cir_enabled" != "yes" ]; then echo "[-] circuit is not enabled: $circuit"; continue; fi
	if [ ! -f $gw ] || [ ! -f $tun ] || [ ! -f $net ] || [ ! -f $rst ]; then echo "[-] circuit is broken: $circuit"; continue; fi

	gw_ns="";
	gw_addr="";
	gw_upst="";
	gw_mask="";
	gw_cidr="";
	gw_backup="";
	gw_cidrmask="";
	gw_type=$(grep '^type' $gw | head -n 1 | cut -d '=' -f2);
	gw_ifname=$(grep '^ifname' $gw | head -n 1 | cut -d '=' -f2);
	gw_ntpaddr=$(grep '^ntp_addr' $gw | head -n 1 | cut -d '=' -f2);
	gw_dnsaddr=$(grep '^dns_addr' $gw | head -n 1 | cut -d '=' -f2);

	#checking if this gateway is already initialized 
	if [ ! -f /tmp/privrouter/tmpfs/${gw_name}.inf ]; then
		
		#checking gateway type, if wifi connect via wpa_supplicant
		if [ "$gw_type" == "wifi" ]; then

			gw_ssid=$(grep '^ssid' $gw | head -n 1 | cut -d '=' -f2);
			gw_pass=$(grep '^pass' $gw | head -n 1 | cut -d '=' -f2);
	
			echo "country=PT" > /tmp/privrouter/tmpfs/$gw_name.wpa
			wpa_passphrase "$gw_ssid" "$gw_pass" >> /tmp/privrouter/tmpfs/$gw_name.wpa
			wpa_supplicant -i $gw_ifname -c /tmp/privrouter/tmpfs/$gw_name.wpa &>/tmp/privrouter/logs/$gw_name.supplicant &

			while [ "$(grep 'CONNECTED' "/tmp/privrouter/logs/$gw_name.supplicant")" == "" ]; do sleep 1; done
			sleep 2;
		fi

		#getting a lease
		touch /tmp/privrouter/tmpfs/$gw_name.leases
		dhclient -1 -sf /bin/true $gw_ifname -lf /tmp/privrouter/tmpfs/$gw_name.leases &
		while [ "$(grep -a 'expire ' /tmp/privrouter/tmpfs/$gw_name.leases)" == "" ]; do sleep 1; done

		#parse dhcp lease data
		gw_backup=""
		gw_ns=$(grep -a 'domain-name-servers' /tmp/privrouter/tmpfs/$gw_name.leases | head -n 1 | awk '{print $3}' | tr -d ';');
		gw_addr=$(grep -a 'fixed-address' /tmp/privrouter/tmpfs/$gw_name.leases | head -n 1 | awk '{print $2}' | tr -d ';');
		gw_upst=$(grep -a 'option routers' /tmp/privrouter/tmpfs/$gw_name.leases | head -n 1 | awk '{ print $3}' | tr -d ';');
		gw_mask=$(grep -a 'subnet-mask' /tmp/privrouter/tmpfs/$gw_name.leases | head -n 1 | awk '{print $3}' | tr -d ';');
		gw_cidr=$(ipcalc $gw_addr $gw_mask | grep 'Network:' | awk '{print $2}');
		gw_cidrmask=$(ipcalc $gw_addr $gw_mask | grep 'Netmask:' | awk '{print $4}');
		echo -e "${circuit_idx}100\t$gw_name" >> /etc/iproute2/rt_tables
	
		#adding necessary routes and rules to linux ip stack
		ip addr add $gw_addr/$gw_cidrmask dev $gw_ifname
		ip route del $gw_cidr dev $gw_ifname table main
		ip route add $gw_cidr dev $gw_ifname table $gw_name
		ip rule add from $gw_cidr dev $gw_ifname table $gw_name
		ip rule add from all to $gw_cidr table $gw_name

		ip rule add from all to $gw_ntpaddr table $gw_name
		ip rule add from all to $gw_dnsaddr table $gw_name
		ip route add $gw_ntpaddr via $gw_upst dev $gw_ifname table $gw_name
		ip route add $gw_dnsaddr via $gw_upst dev $gw_ifname table $gw_name

		#adding firewall rules
		iptables -A OUTPUT -o $gw_ifname -p udp --dport 53 -d $gw_dnsaddr -j ACCEPT
		iptables -A OUTPUT -o $gw_ifname -p udp --dport 123 -d $gw_ntpaddr -j ACCEPT

		#updating time via ntp
		ntpdate -u $gw_ntpaddr 
		echo "$gw_ns:$gw_addr:$gw_upst:$gw_mask:$gw_cidr:$gw_cidrmask" > /tmp/privrouter/tmpfs/$gw_name.inf
	else
	
		#getting same info if is already intiialized
		gw_ns=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f1);
		gw_addr=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f2);
		gw_upst=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f3);
		gw_mask=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f4);
		gw_cidr=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f5);
		gw_cidrmask=$(cat /tmp/privrouter/tmpfs/$gw_name.inf | cut -d ':' -f6);
	fi


	#getting tunnel and network conf vars	
	tun_type=$(grep -a '^type' $tun | head -n 1 | cut -d '=' -f2);
	net_id=$(grep -a '^id' $net | head -n 1 | cut -d '=' -f2);
	net_cidr=$(grep -a '^cidr' $net | head -n 1 | cut -d '=' -f2);
	net_mask=$(ipcalc $net_cidr | grep 'Network:' | awk '{print $2}');
	net_ruleset=$(grep -a '^ruleset' $net | head -n 1 | cut -d '=' -f2);
	echo -e "${circuit_idx}200\t$net_name" >> /etc/iproute2/rt_tables	

	#craeting vlan, adding routes, rules and checking tunnel type (null, vpn, tor)
	ip link add link usb0 name $net_name type vlan id $net_id 
	ip addr add $net_cidr dev $net_name
	ip link set dev $net_name up
	ip route del $net_mask dev $net_name
	ip route add $net_mask dev $net_name table $net_name
	ip rule add from $net_mask dev $net_name table $net_name
	ip rule add from all to $net_mask table $net_name
	
	upst_ifname=$gw_ifname	
	if [ "$tun_type" == "null" ]; then	

		#if null, just redirect the traffic simply thorugh the gateway
		ip route add default via $gw_upst dev $gw_ifname table $net_name
		iptables -t nat -A POSTROUTING -s $net_mask -o $gw_ifname -j MASQUERADE

	elif [ "$tun_type" == "vpn" ]; then

		if [ ! -f /tmp/privrouter/tmpfs/${tun_name}.inf ]; then
			
			#validdate ovpn file and parse it for connection
			tun_ovpn=$(grep '^ovpn' $tun | head -n 1 | cut -d '=' -f2);
			tun_auth=$(grep '^auth' $tun | head -n 1 | cut -d '=' -f2);
	
			cp /tmp/privrouter/vpns/$tun_ovpn /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			tun_remote=$(grep '^remote .*$' /tmp/privrouter/tmpfs/${tun_ovpn}.pr | head -n1);
		
			sed -i '/^local/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^lport/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^nobind/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^.*remote-random.*$/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^.*remote .*$/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^#.*$/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i '/^$/d' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i "s/^.*dev tun.*$/dev tun${circuit_idx}/g" /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i "4i${tun_remote}" /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i "4ilocal ${gw_addr}" /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			sed -i "6ilport 500${circuit_idx}" /tmp/privrouter/tmpfs/${tun_ovpn}.pr

			if [ "$(grep -a '^route-nopull' /tmp/privrouter/tmpfs/${tun_ovpn}.pr)" == "" ]; then 
				sed -i '6iroute-nopull' /tmp/privrouter/tmpfs/${tun_ovpn}.pr
			fi
		
			ovpn_addr=$(echo $tun_remote | cut -d ' ' -f2);
			ovpn_port=$(echo $tun_remote | cut -d ' ' -f3);
			ovpn_proto=$(grep '^proto' /tmp/privrouter/tmpfs/${tun_ovpn}.pr | head -n 1 | cut -d ' ' -f2);

			ip rule add from all to $ovpn_addr table $gw_name
			ip route add $ovpn_addr via $gw_upst dev $gw_ifname table $gw_name
			iptables -A OUTPUT -o $gw_ifname -p $ovpn_proto -s $gw_cidr -d $ovpn_addr --dport $ovpn_port -j ACCEPT

			#checking if vpn needs external credentials file
			if [ "$tun_auth" == "null" ]; then openvpn --config /tmp/privrouter/tmpfs/${tun_ovpn}.pr &>/tmp/privrouter/logs/${tun_name}.log &
			else openvpn --config /tmp/privrouter/tmpfs/${tun_ovpn}.pr --auth-user-pass /tmp/privrouter/vpns/$tun_auth &>/tmp/privrouter/logs/${tun_name}.log & fi

			#adding vpn connection timeout to prevent from hanging the whole script
			timeout=0;
			while [ "$(grep 'Initialization Sequence Completed' /tmp/privrouter/logs/${tun_name}.log)" == "" ]; do 
				
				if [ $timeout -ge 30 ]; then echo "vpn timed out."; timeout=1000; break; fi
				timeout=$((timeout+4));	
				sleep 4; 
			done

			if [ "$timeout" -ge 1000 ]; then continue; fi
			echo "tun${circuit_idx}" > /tmp/privrouter/tmpfs/${tun_name}.inf;
		fi

		upst_ifname=$(cat /tmp/privrouter/tmpfs/${tun_name}.inf);
		ip route add default dev $upst_ifname table $net_name
		iptables -t nat -A POSTROUTING -s $net_mask -o $upst_ifname -j MASQUERADE
	fi

	#load rules from rulesets conf files associated with circuit
	rules=($(cat $rst | tr '\n' ' '));	
	for rule in ${rules[@]}; do

		rule_type=$(echo $rule | cut -d '=' -f1);
		rule_data=$(echo $rule | cut -d '=' -f2);

		if [ "$rule_type" == "def_input" ]; then
			if [ "$rule_data" == "drop" ]; then iptables -A FORWARD -o $net_name -j DROP;
			elif  "$rule_data" == "accept" ]; then iptables -A FORWARD -o $net_name -j ACCEPT; fi

		elif [ "$rule_type" == "def_output" ]; then
			if [ "$rule_data" == "drop" ]; then iptables -A FORWARD -i $net_name -j DROP;
			elif [ "$rule_data" == "accept" ]; then iptables -A FORWARD -i $net_name -j ACCEPT; fi

		elif [ "$rule_type" == "allow_out" ]; then

			rule_prt=$(echo $rule_data | cut -d '/' -f1);
			rule_src=$(echo $rule_data | cut -d '/' -f2);
			rule_dst=$(echo $rule_data | cut -d '/' -f3);
			rule_port=$(echo $rule_data | cut -d '/' -f4);

			if [ "$rule_src" == "%net%" ]; then rule_src=$net_mask; fi
			if [ "$rule_dst" == "%any%" ]; then rule_dst='0.0.0.0/0'; fi
			iptables -I FORWARD -i $net_name -o $upst_ifname -p $rule_prt -s $rule_src -d $rule_dst --dport $rule_port -j ACCEPT 

		elif [ "$rule_type" == "deny_out" ]; then
			echo "deny out"
		fi
	done

	#put vlan info into tmp files so host can read them from ssh connection
	if [ ! -d /tmp/nets ]; then mkdir /tmp/nets; fi
	echo "$net_name:$net_id:$net_cidr:$net_mask:2" > /tmp/nets/$net_name.net

	circuit_idx=$((circuit_idx+1));
done

#enable ip forwarding
sysctl -w net.ipv4.ip_forward=1
sysctl -p

#finish initialization
echo "running" > /tmp/status
while [ "$(ip -br a | grep 'usb0')" != "" ]; do sleep 2; done 
sudo systemctl restart privrouter

