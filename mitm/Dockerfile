FROM ubuntu:latest
MAINTAINER Ludovic Barman <ludovic.barman@protonmail.com>

COPY scripts /mitm
WORKDIR /mitm

RUN apt-get update
RUN apt-get install -y --no-install-recommends apt-utils nano iptables python3 python3-pip python3-dev build-essential libnetfilter-queue-dev scapy 

RUN pip3 install --upgrade pip
RUN pip3 install setuptools
RUN pip3 install NetfilterQueue

CMD ["/mitm/stayAlive.sh"]
