#!/bin/bash

# Set project directories
LIB_DIR="lib"
SRC_DIR="src"
OUT_DIR="out"
BC_JAR="bcprov-jdk18on-1.79.jar"

# Ensure output directory exists
mkdir -p "$OUT_DIR"

# Compile all Java files in the src directory with Bouncy Castle jar
echo "[BASH] Compiling source files..."
javac -d "$OUT_DIR" -cp "$LIB_DIR/$BC_JAR" "$SRC_DIR"/*.java

if [ $? -ne 0 ]; then
  echo "[BASH] Compilation failed. Please check your source files for errors."
  exit 1
fi
echo "[BASH] Compilation successful."

# Run the TestServer in the background
echo "[BASH] Starting TestServer..."
java -cp "$OUT_DIR:$LIB_DIR/$BC_JAR" TestServer &
SERVER_PID=$!

# Wait for the server to initialize
sleep 2

# Run the TestClient
echo "[BASH] Starting TestClient..."
java -cp "$OUT_DIR:$LIB_DIR/$BC_JAR" TestClient

# Kill the TestServer after the client finishes
echo "[BASH] Stopping TestServer..."
kill $SERVER_PID

echo "[BASH] Done."
