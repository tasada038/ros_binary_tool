#!/bin/bash

# Usage: ./hash_create.sh <binx_file_path> <version> <jetson_ip> <username> <target_directory>
# Example: ./hash_create.sh /path/to/binx_file.binx 1.2.3 192.168.1.100 username /target/directory

# Argument check
if [ $# -ne 5 ]; then
    echo "Usage: $0 <binx_file_path> <version> <jetson_ip> <username> <target_directory>"
    exit 1
fi

# Retrieve arguments
BINX_FILE=$1
VERSION=$2
JETSON_IP=$3
USERNAME=$4
TARGET_DIR=$5

# Get the binx file path and filename
BINX_FILENAME=$(basename "$BINX_FILE")

# Name of the metadata file
METADATA_FILE="${BINX_FILENAME%.binx}_metadata.json"

# Generate MD5 hash
md5sum "$BINX_FILE" > "${BINX_FILENAME%.binx}.md5"
HASH=$(cat "${BINX_FILENAME%.binx}.md5" | awk '{ print $1 }')

# Create metadata file
echo "{
    \"version\": \"$VERSION\",
    \"hash\": \"$HASH\",
    \"description\": \"Bug fixes and performance improvements\"
}" > "$METADATA_FILE"

# Transfer files
scp "$BINX_FILE" "$METADATA_FILE" "${USERNAME}@${JETSON_IP}:${TARGET_DIR}/"

# Completion message
echo "binx file and metadata have been sent to the Jetson SBC."

