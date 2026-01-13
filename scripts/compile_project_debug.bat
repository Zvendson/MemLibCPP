@ECHO OFF
PUSHD %~dp0\..\

cmake --build build --config Debug

POPD

PAUSE