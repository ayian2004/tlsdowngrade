#!/bin/sh
MALICIOUS_SERVER="malicious-server.eurodyn.com" # this is actually just a deom web server!

while true
do
    echo "Initiating connection to malicious server $MALICIOUS_SERVER ..."

    # if not reachable, try again
    ping -c1 -W1 $MALICIOUS_SERVER 1>/dev/null 2>&1

    if [ $? -eq 0 ]; then

        echo "Server reachable, performing handshake..."
        ciphers=$(nmap --script ssl-enum-ciphers -p 443 $MALICIOUS_SERVER)
        hasStrongestCipher=$(echo "$ciphers" | grep 'TLS_RSA_WITH_AES_256_CBC_SHA' | wc -l)

        echo "Available ciphers:"
        nmap --script ssl-enum-ciphers -p 443 $MALICIOUS_SERVER | grep -A 3 "TLSv1.2" | cut -c 5-

        if [ "$hasStrongestCipher" -eq "1" ]; then
            echo "Using stronger cipher suite (AES 256)...              <- your downgrade attack failed !"
            echo "Exchanging secret stuff on this very secure channel..."
            echo "Done."
        else
            echo "Using weaker cipher suite (AES 128)..."
            echo "Success !"
        fi
    else
        echo "Server unreachable, retrying soon..."
    fi
    sleep 10
done
