#!/bin/sh

PRE=$(cat /var/lib/cron.md5)
NEW=$(md5sum /etc/crontab)

if [ "$PRE" != "$NEW" ]; then
        md5sum /etc/crontab > /var/lib/cron.md5
        echo "Warning! Crontab" | mail -s "The modified Crontab!" root
fi
