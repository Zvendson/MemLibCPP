#!/bin/bash
set -e

pushd "$(dirname "$(realpath "$0")")/.." > /dev/null


cmake -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build build

popd > /dev/null