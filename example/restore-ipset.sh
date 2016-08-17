#!/usr/bin/env bash
sqlite3 -separator ' ' requests.db 'SELECT user, ip_addr, access_targets FROM requests WHERE approved = 1' | xargs -L1 /opt/openvpn-bot/update-access.sh
