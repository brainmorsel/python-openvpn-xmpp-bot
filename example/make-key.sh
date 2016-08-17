#!/usr/bin/env bash

user="$1"
key_uuid="$2"

KEYS_PATH=/etc/openvpn/easy-rsa/keys
TARGET_PATH=/var/www/key

if [[ ! -e "${KEYS_PATH}/${user}.key" ]]; then
    cd /etc/openvpn/easy-rsa
    source ./vars
    export EASY_RSA="${EASY_RSA:-.}"
    "$EASY_RSA/pkitool" "$user"
fi


CA_CONTENT="$(grep -FA 1000 -- "-----BEGIN" <${KEYS_PATH}/ca.crt)"
CRT_CONTENT="$(grep -FA 1000 -- "-----BEGIN" ${KEYS_PATH}/${user}.crt)"
KEY_CONTENT="$(grep -FA 1000 -- "-----BEGIN" <${KEYS_PATH}/${user}.key)"

cat >${KEYS_PATH}/${user}.ovpn <<EOF
client
dev tap
proto udp
remote example.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
comp-lzo
verb 3
<ca>
${CA_CONTENT}
</ca>
<cert>
${CRT_CONTENT}
</cert>
<key>
${KEY_CONTENT}
</key>
EOF
chmod 600 ${KEYS_PATH}/${user}.ovpn

zip "${TARGET_PATH}/${user}-${key_uuid}.zip" ${KEYS_PATH}/${user}.*
