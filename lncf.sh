#!/bin/bash
export MAC_VENDOR_DB="oui.txt"

shopt -s lastpipe

die() {
  echo "$0: FATAL: $*" >&2
  exit 1
}


declare -A IP_MAC

LOCAL_IP="$(ip -o -f inet addr show | awk '/scope global/ {print $4}'|head -1)"
IFACE="$(ip -o -f inet addr show | awk '/scope global/ {print $2}'|head -1)"

[ "${#LOCAL_IP}" -eq 0 ] && die "no local network ip found"

echo "finding interface & calculating range for arp-scan"
tmp="${LOCAL_IP%/*}"
ipA="${tmp%%.*}"
tmp="${tmp#$ipA.}"
ipB="${tmp%%.*}"
tmp="${tmp#$ipB.}"
ipC="${tmp%.*}"
ipD="${tmp#*.}"
ip_hex=$[ipA<<24|ipB<<16|ipC<<8|ipD];

net_bits="${LOCAL_IP#*/}"
ip_mask=$[0xffffffff^((1<<(32-net_bits))-1)]
printf "ip mask: %x\n" "$ip_mask"

range_min_hex=$[ip_hex & ip_mask]
range_max_hex=$[ip_hex & ip_mask | (0xffffffff ^ ip_mask)]

#printf "range_min_hex: %x\n" "$range_min_hex"
#printf "range_max_hex: %x\n" "$range_max_hex"

range_min=$(hex2ip "$range_min_hex")
range_max=$(hex2ip "$range_max_hex")

IP_RANGE="$range_min-$range_max"

echo "IFACE: $IFACE"
echo "IP_RANGE: $IP_RANGE"

echo "Doing arp scanning"
arp-scan |while read -r -a line
do
  IP="${line[0]}"
  [[ "$IP" =~ [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3} ]] || continue
  MAC="${line[1]}"
  IP_MAC["${IP}"]="${MAC}"
done

export OUIPREF=""
export IP=""

echo "Calculating vendors, finding open TCP & UDP ports"
for IP in "${!IP_MAC[@]}"
do
  MAC="${IP_MAC[$IP]}"
  OUIPREF="${MAC//:/}"
  OUIPREF="${OUIPREF:0:6}"
  OUIPREF="${OUIPREF^^}"
  VENDOR="$(grep ^"${OUIPREF} " "$MAC_VENDOR_DB")"
  if [ "$VENDOR" = "" ]
  then
    VENDOR="Unknown"
  else
    VENDOR="${VENDOR:22}"
  fi
  TCP_PORTS="$(nmap -sT -Pn "$IP"|awk 'BEGIN {ORS=","} {if ($2 == "open") print gensub("/tcp", "", "g", $1)}')"
  TCP_PORTS="${TCP_PORTS%,}"
  TCP_PORTS="${TCP_PORTS//[^0-9,]/}"
  UDP_PORTS="$(nmap -sU -Pn "$IP"|awk 'BEGIN {ORS=","} {if ($2 == "open") print gensub("/udp", "", "g", $1)}')"
  UDP_PORTS="${UDP_PORTS%,}"
  UCP_PORTS="${UDP_PORTS//[^0-9,]/}"
  echo "$IP $MAC ${VENDOR%% *} $TCP_PORTS $UDP_PORTS"
done
