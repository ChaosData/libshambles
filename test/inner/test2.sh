#!/bin/bash
echo "starting"
echo -e '\x13BitTorrent protocol olololo1' | nc c.yber.ninja 8891 &
echo -e '\x13BitTorrent protocol olololo2' | nc c.yber.ninja 8891 &
