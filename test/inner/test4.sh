#!/bin/bash

for i in `seq $1`
do
  python client.py 159.203.108.48 8891 "$i"
done
