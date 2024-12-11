#!/bin/bash

# Define a cleanup function to kill the background processes
cleanup() {
  echo "Stopping the services..."
  kill $PROXY_PID $STREAM_PID
  exit 0
}

# Set project directories
LIB_DIR="lib"
BC_JAR="bcprov-jdk18on-1.79.jar"
SERV_DIR="hjStreamServer"
CLIENT_DIR="hjUDPproxy"

# Trap SIGINT (CTRL+C) and call the cleanup function
trap cleanup SIGINT

cd WorkingTools/StreamingService || exit

# Compile all Java files in the src directory with Bouncy Castle jar
echo "[BASH] Compiling source files..."
javac -d "$CLIENT_DIR" -cp "$CLIENT_DIR/$LIB_DIR/$BC_JAR" "$CLIENT_DIR"/*.java
javac -d "$SERV_DIR" -cp "$SERV_DIR/$LIB_DIR/$BC_JAR" "$SERV_DIR"/*.java


echo "Testing the Streaming service."
echo "Will stream to port 1234 on localhost"

# Start the Streaming in the background
cd "$SERV_DIR/"
java -cp "$LIB_DIR/$BC_JAR:." hjStreamServer &
STREAM_PID=$!


# Start the UDP Proxy in the background
cd "../$CLIENT_DIR/"
java -cp "$LIB_DIR/$BC_JAR:." hjUDPproxy alice@gmail.com password 127.0.0.1 1337 movies/cars.dat 9000 127.0.0.1:1234 &
PROXY_PID=$!

# Give the receiver some time to start
sleep 2



# Wait indefinitely to keep the script running until interrupted
wait
