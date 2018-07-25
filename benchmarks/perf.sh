#! /bin/bash
interval = $1 #${1:1}
duration_sec = 3600
print "interval: $interval secs, duration: $duration_sec secss"

printf "Memory\t\tDisk\t\tCPU\n"
end=$((SECONDS+duration_sec))
#while [ $SECONDS -lt $end ]; do
while true; do
MEMORY=$(free -m | awk 'NR==2{printf "%.2f%%\t\t,", $3*100/$2 }')
DISK=$(df -h | awk '$NF=="/"{printf "%s\t\t", $5}')
CPU=$(top -bn1 | grep load | awk '{printf "%.2f%%\t\t\n", $(NF-2)}')
echo "$MEMORY$DISK$CPU"
sleep interval
done
