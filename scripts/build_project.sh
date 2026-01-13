#!/bin/bash
set -e

pushd "$(dirname "$(realpath "$0")")/.." > /dev/null

cmake -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON

popd > /dev/null