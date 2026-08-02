#!/usr/bin/env bash

set -e

echo "This script requires https://jpa.kapsi.fi/nanopb/download/ version 0.4.9 to be located in the"
echo "firmware root directory if the following step fails, you should download the correct"
echo "prebuilt binaries for your computer into nanopb-0.4.9"

# the nanopb tool seems to require that the .options file be in the current directory!
cd protobufs
# evil-meshtastic: stage the repo-tracked evil proto into the submodule so it
# compiles alongside the upstream protos (the submodule points at upstream and
# cannot track our file).
cp ../protos/meshtastic/evil_control.proto meshtastic/
cp ../protos/meshtastic/evil_control.options meshtastic/
../nanopb-0.4.9/generator-bin/protoc --experimental_allow_proto3_optional "--nanopb_out=-S.cpp -v:../src/mesh/generated/" -I=../protobufs meshtastic/*.proto
