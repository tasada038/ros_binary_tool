#!/bin/bash

# Change to the target directory
cd /target/directory

# Check for existing version
if [ -f "current_binx_metadata.json" ]; then
    current_version=$(jq -r '.version' current_binx_metadata.json)
    new_version=$(jq -r '.version' binx_file_metadata.json)
    
    if dpkg --compare-versions "$new_version" "gt" "$current_version"; then
        current_hash=$(md5sum current_binx_file.binx | awk '{ print $1 }')
        new_hash=$(jq -r '.hash' binx_file_metadata.json)
        
        if [ "$new_hash" == "$current_hash" ]; then
            mv current_binx_file.binx backup_binx_file.binx
            mv binx_file.binx current_binx_file.binx
            mv binx_file_metadata.json current_binx_metadata.json
            echo "Update completed."
        else
            echo "Error: Hash mismatch."
        fi
    else
        echo "Current version is up to date."
    fi
else
    mv binx_file.binx current_binx_file.binx
    mv binx_file_metadata.json current_binx_metadata.json
    echo "Initial deployment completed."
fi

