#!/bin/sh
exec sshpass -p $1 ssh root@$2 'tcpdump -e -i br0 -l not port 22 and src host' $3 'and dst host '$4 `shift 4; echo "${@}"` > /tmp/sniff_data 2>/dev/null
