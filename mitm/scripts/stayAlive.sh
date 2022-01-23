#!/bin/sh

export TERM=xterm # to use nano in docker

while :
do
  echo "MitM machine is alive..."
  sleep 10
  tree -a
done
