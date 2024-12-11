#!/bin/bash

# Define a cleanup function to kill the background processes
cleanup() {
  echo "Stopping the services..."
  kill $SERVER_PID
  exit 0
}

# Set project directories
LIB_DIR="lib"
BC_JAR="bcprov-jdk18on-1.79.jar"
SERV_DIR="TFTPServer"
CLIENT_DIR="TFTPClient"
SRC_DIR="src"

# Trap SIGINT (CTRL+C) and call the cleanup function
trap cleanup SIGINT

cd WorkingTools/TFTP || exit

# Compile all Java files in the src directory with Bouncy Castle jar
echo "[BASH] Compiling source files..."
javac -d "$CLIENT_DIR/$SRC_DIR" -cp "$CLIENT_DIR/$LIB_DIR/$BC_JAR" "$CLIENT_DIR/$SRC_DIR"/*.java
javac -d "$SERV_DIR/$SRC_DIR" -cp "$SERV_DIR/$LIB_DIR/$BC_JAR" "$SERV_DIR/$SRC_DIR"/*.java


echo "Testing the TFTP File sending service."
echo "Will download file server1.jpg from server."
echo "Then will upload file client1.jpg to server."

# Start the TFTP Server in the background on port 1337
cd "$SERV_DIR/$SRC_DIR"
java -cp "../$LIB_DIR/$BC_JAR:." TFTPServer 1337 &
SERVER_PID=$!

sleep 2


# Uses the TFTP Client to download server1.jpg then upload client1.jpg
cd "../../$CLIENT_DIR/$SRC_DIR"
java -cp "../$LIB_DIR/$BC_JAR:." TFTPClient alice@gmail.com password 127.0.0.1 1337 R server1.jpg &

sleep 2

java -cp "../$LIB_DIR/$BC_JAR:." TFTPClient alice@gmail.com password 127.0.0.1 1337 W client1.jpg &


# Wait indefinitely to keep the script running until interrupted
wait
