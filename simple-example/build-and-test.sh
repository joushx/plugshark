#!/bin/bash

# Intended to run for Wireshark 4.4 on Linux

set -e 

# Build the plugin
cargo build

# Copy the plugin to the Wireshark plugin folder
mkdir -p ~/.local/lib/wireshark/plugins/4.4/epan/
cp ./target/debug/libfoo.so ~/.local/lib/wireshark/plugins/4.4/epan/

echo "Plugin copied to ~/.local/lib/wireshark/plugins/4.4/epan/"

# Parse the sample packet
tshark -r ./tests/samples/onepacket.pcap -V
