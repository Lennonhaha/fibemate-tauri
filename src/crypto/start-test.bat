@echo off
echo Starting PQ-WASM test server...
echo Open http://localhost:3456 in your browser
cd /d "%~dp0"
node test-server.js
pause
