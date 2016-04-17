#!/bin/bash

for i in `seq $1`
do
  python client.py "$2" "$3" "$i" &
done
