FROM alpine:3.5

COPY scripts /victim
WORKDIR /victim

RUN apk add --no-cache nmap nmap-scripts nmap-nselibs nano iptables

COPY nmap-scripts /usr/share/nmap/scripts

CMD ["/victim/victims-program.sh"]
