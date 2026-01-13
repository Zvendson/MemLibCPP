@ECHO OFF
PUSHD %~dp0\..\

cmake --build build --config RelWithDebInfo

POPD

PAUSE