#!/bin/sh
exec sshpass -p $1 ssh root@$2 'tcpdump -i br0 -s0 -w - not port 22' > $3 2>/dev/null
