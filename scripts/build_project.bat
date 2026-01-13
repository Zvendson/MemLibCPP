@ECHO OFF
PUSHD %~dp0\..\

cmake -B build

POPD
PAUSE