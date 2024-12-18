#!/bin/bash

#~ Student name – Aviv Feldvari
#~ Class code – 7736/26
#~ Student code – s16
#~ Lecturer's name – Erel Regev

# Record the start time of the analysis
analysis_start_time=$(date)
echo "[!] Welcome to my Analyzer project!"
FOLDER="$(pwd)"
package_list=( "bulk_extractor" "foremost")
function INSTALL_DEPENDENCIES(){
    # Install packages from the list
    echo "[*] Checking for missing packages and installing if needed.."
    for package_name in "${package_list[@]}"; do
        dpkg -s "$package_name" >/dev/null 2>&1 || 
        (echo -e "[*] Installing $package_name..." &&
        sudo apt-get install "$package_name" -y >/dev/null 2>&1)
        echo "[#] $package_name installed on remote host."
    done

    # Check if Volatility is already present
    if [ -f "$FOLDER/vol" ]; then
        echo "[#] Volatility executable already present in $FOLDER. Skipping installation."
        return
    fi

    # Set URL and download Volatility standalone executable
    VOLATILITY_URL="https://github.com/volatilityfoundation/volatility/releases/download/2.6.1/volatility_2.6_lin64_standalone.zip"
    VOLATILITY_ZIP="volatility_2.6_lin64_standalone.zip"
    VOLATILITY_DIR="volatility_2.6_lin64_standalone"

    # Download the zip file
    wget "$VOLATILITY_URL" -O "$VOLATILITY_ZIP"

    # Remove any pre-existing folder from a previous run to ensure a clean extraction
    rm -rf "$VOLATILITY_DIR"

    # Unzip with overwrite option (-o) to prevent prompts
    unzip -o "$VOLATILITY_ZIP" -d "$VOLATILITY_DIR"

    # Rename the executable to 'vol' and move it to the target directory
    if mv "$VOLATILITY_DIR/volatility_2.6_lin64_standalone/volatility_2.6_lin64_standalone" "$FOLDER/vol"; then
        echo "[#] Volatility executable moved to $FOLDER as 'vol'."
    else
        echo "[!] Error: Moving Volatility executable failed. Directory conflict may exist."
        exit 1
    fi

    # Cleanup: Remove the extracted directory and zip file
    rm -rf "$VOLATILITY_DIR"
    rm "$VOLATILITY_ZIP"

    echo "[#] Volatility installed successfully as 'vol' in $FOLDER."
}



echo "[*] Checking for root privileges.."
if [ "$(whoami)" != "root" ]; then
	echo "[!] This script must be run as root";
	exit 1
	else 
	echo "[*] Script running as root, Proceeding.."
fi

echo "" 

read -p "[?] Enter the filename: " filename
if [ ! -f "$filename" ]; then
    echo "[!] File not found: $filename"
    exit 1
    else
    echo "[*] File Exists, Proceeding.."
fi


function data() {
    echo "[*] Starting data extraction process..."

    # Get the base name of the file without the extension
    filename_base=$(basename "$filename" .mem)
    output_dir="$FOLDER/$filename_base"
    
	# Check if the output directory already exists and remove it if so
	if [ -d "$output_dir" ]; then
		echo "[*] Removing existing directory: $output_dir"
		rm -rf "$output_dir"
	fi

    # Create output directory based on the filename without extension
    mkdir -p "$output_dir"
    echo "[~] Output directory set to $output_dir"
    sleep 1

    # File Carving with foremost
    echo "[*] Running file carving with 'foremost'..."
    if ! command -v foremost &> /dev/null; then
        echo "[!] Error: foremost is not installed. Please install it first."
        exit 1
    fi
    foremost -i "$filename" -o "$FOLDER/$filename_base/foremost_output"
    echo "[~] File carving complete. Results saved in $FOLDER/$filename_base/foremost_output."
    sleep 1

    # Data Artifact Extraction with bulk_extractor
    echo "[*] Extracting network data and other artifacts with 'bulk_extractor'..."
    bulk_extractor -o "$FOLDER/$filename_base/bulk_output" -E net "$filename"
    echo "[~] Artifact extraction complete. Results saved in $FOLDER/$filename_base/bulk_output."
    sleep 1

    pcap_files=("$FOLDER/$filename_base/bulk_output"/*.pcap)

    if [ -e "${pcap_files[0]}" ]; then
        echo "[*] PCAP files found in the output directory:"
        for pcap in "${pcap_files[@]}"; do
            pcap_size=$(du -h "$pcap" | cut -f1) # Get file size in human-readable format
            echo " - $pcap (Size: $pcap_size)"
        done
    else
        echo "[!] No PCAP files found in the output directory."
    fi

    # Check if network data was extracted
    net_file="$FOLDER/$filename_base/bulk_output/net.txt"

    if [ -f "$net_file" ] && [ -s "$net_file" ]; then
        net_size=$(du -h "$net_file" | cut -f1) # Get file size in human-readable format
        echo "[~] Network traffic data found and saved in: $net_file (Size: $net_size)"
    else
        echo "[!] No network traffic data found in the provided disk image."
    fi
    sleep 1

    # Searching for Human-Readable Data
    echo "[*] Scanning for human-readable data (keywords: password, username, login)..."
    strings "$filename" | grep -E 'password|username|login' > "$FOLDER/$filename_base/human_readable_data.txt"
    echo "[~] Search complete. Results saved in $FOLDER/$filename_base/human_readable_data.txt."
    sleep 1

    # Summarize and Display Extraction Results
    echo
    echo "[~] Data extraction process is complete. Here’s a summary of the results:"
    ls -lh "$output_dir" | awk '{print $9 ": " $5}' | while read line; do echo "$line"; done
}

function analyze_with_volatility() {
    echo "[*] Volatility analysis starting..."
    
    # Check if Volatility executable exists
    if [ ! -f "$FOLDER/vol" ]; then
        echo "[!] Error: Volatility executable not found in $FOLDER."
        exit 1
    fi

    # Check if the file exists
    if [ ! -f "$filename" ]; then
        echo "[!] Error: The specified file '$filename' does not exist."
        exit 1
    fi

    # Check if the file can be analyzed with Volatility
    echo "[*] Checking if the file can be analyzed with Volatility..."
    
    # Use the command to list profiles available
    profiles_output=$("$FOLDER/vol" -f "$filename" imageinfo 2>&1)

    # Check for suggested profiles
    if echo "$profiles_output" | grep -q "Suggested Profile(s)"; then
        # Now check for "No suggestion" in the output
        if echo "$profiles_output" | grep -q "No suggestion"; then
            echo "[!] The file '$filename' does not appear to be a valid memory dump."
            exit 1
        else
            echo "[*] The file '$filename' is a valid memory dump."
            
            # Extract suggested profile, stripping commas and extra spaces
            suggested_profiles=$(echo "$profiles_output" | grep "Suggested Profile(s)" | awk -F ': ' '{print $2}')
            suggested_profile=$(echo "$suggested_profiles" | tr -d ',' | awk '{print $1}') # Choose the first suggested profile
            
            echo "[*] Using profile: $suggested_profile"
            
            # Run Volatility analysis with the selected profile (example with pslist)
            echo "[*] Analyzing processes..."
            "$FOLDER/vol" -f "$filename" --profile="$suggested_profile" pslist > "$FOLDER/$filename_base/process_list.txt" 2>&1

            # Check if process_list.txt exists and is not empty
            if [ -s "$FOLDER/$filename_base/process_list.txt" ]; then
                line_count=$(wc -l < "$FOLDER/$filename_base/process_list.txt")
                if [ "$line_count" -gt 2 ]; then
                    echo "[*] Processes found:"
                    cat "$FOLDER/$filename_base/process_list.txt"
                else
                    echo "[!] No processes found in the analysis."
                fi
            else
                echo "[!] Error: process_list.txt not found or empty."
            fi
        fi
    else
        echo "[!] The file '$filename' cannot be analyzed with Volatility. Output was:"
        echo "$profiles_output"
        exit 1
    fi

    echo "[*] Volatility analysis completed."
}

function display_network_connections() {
    echo "[*] Displaying network connections..."

    # Run netscan with the selected profile and memory file
    network_connections_output=$("$FOLDER/vol" -f "$filename" --profile="$suggested_profile" netscan 2>&1)

    # Check if netscan was successful
    if echo "$network_connections_output" | grep -q "Volatility"; then
        echo "[*] Network connections found:"
        echo "$network_connections_output"
    else
        echo "[!] Failed to retrieve network connections or no connections found."
        echo "$network_connections_output"
    fi

    # Save network connections output to a file
    echo "$network_connections_output" > "$output_dir/network_connections.txt"
    echo "[*] Network connections saved in $output_dir/network_connections.txt"
}

function extract_registry_information() {
    echo "[*] Attempting to extract registry information..."

    # 1: Extract list of registry hives with hivelist
    hivelist_output=$("$FOLDER/vol" -f "$filename" --profile="$suggested_profile" hivelist 2>&1)

    # 2: Check if hivelist was successful
    if echo "$hivelist_output" | grep -q "Virtual"; then
        echo "[*] Registry hive list extracted successfully."

        # Save the hive list to a file
        echo "$hivelist_output" > "$output_dir/registry_hivelist.txt"

        # Initialize or clear the registry information output file
        > "$output_dir/registry_information.txt"

        # 3: Use dumpregistry directly to dump all registries
		reg="$output_dir/registry_dump"
        mkdir -p "$reg"
        dump_command="$FOLDER/vol -f $filename --profile=$suggested_profile dumpregistry --dump-dir=$reg"
        echo "[*] Running dumpregistry command..."
        dump_output=$($dump_command 2>&1)

        # Check if the dump command was successful
        if echo "$dump_output" | grep -q "Writing out registry"; then
            echo "[*] Registry hives dumped successfully."
            echo "$dump_output" | grep "Writing" >> "$output_dir/registry_information.txt"
        else
            echo "[!] Failed to dump registry hives."
        fi

        # Final check if anything was extracted
        if [[ -s "$output_dir/registry_information.txt" ]]; then
            echo "[*] Registry information extraction completed."
        else
            echo "[!] No registry information extracted."
        fi
    else
        echo "[!] Failed to extract registry hive list."
        echo "$hivelist_output"
    fi
}

function save_results_to_report() {
    # Create a report file with the base name of the input filename
    report_file="$FOLDER/$filename_base/report.txt"

    echo "[*] Saving results to report: $report_file"

    # Start writing to the report
    {
        echo "==============================="
        echo "          Analysis Report"
        echo "==============================="
        echo "Filename: $filename"
        echo "Analysis Date: $(date)"
        echo ""

        # Files extracted
        echo "Files Extracted:"
        if [ -d "$FOLDER/$filename_base/foremost_output" ]; then
            echo "Foremost Output:"
            ls "$FOLDER/$filename_base/foremost_output"
        else
            echo "No files extracted by foremost."
        fi

        if [ -d "$FOLDER/$filename_base/bulk_output" ]; then
            echo "Bulk Extractor Output:"
            ls "$FOLDER/$filename_base/bulk_output"
        else
            echo "No files extracted by bulk_extractor."
        fi

        echo ""

        # Processes found
        echo "Processes Found:"
        process_list_output="$FOLDER/$filename_base/process_list.txt"
        if [ -f "$process_list_output" ]; then
            cat "$process_list_output"
        else
            echo "No processes found."
        fi

        echo ""

        # Network connections
        echo "Network Connections:"
        if [ -f "$FOLDER/$filename_base/network_connections.txt" ]; then
            cat "$FOLDER/$filename_base/network_connections.txt"
        else
            echo "No network connections found."
        fi

        echo ""

        # Registry information
        echo "Registry Information:"
        if [ -f "$output_dir/registry_information.txt" ]; then
            if [ -s "$output_dir/registry_information.txt" ]; then
                cat "$output_dir/registry_information.txt"
            else
                echo "No registry information extracted."
            fi
        else
            echo "No registry information extracted."
        fi

        echo "==============================="
    } > "$report_file"

    echo "[*] Report saved successfully."
}


function display_general_statistics() {
    echo "[*] Displaying general statistics..."

    # Record the end time of the analysis
    analysis_end_time=$(date)

    # Count the number of files extracted by foremost
    foremost_output_dir="$output_dir/foremost_output"
    if [ -d "$foremost_output_dir" ]; then
        foremost_file_count=$(find "$foremost_output_dir" -type f | wc -l)
    else
        foremost_file_count=0
    fi

    # Count the number of network artifacts found by bulk_extractor
    bulk_output_dir="$output_dir/bulk_output"
    if [ -d "$bulk_output_dir" ]; then
        bulk_file_count=$(find "$bulk_output_dir" -type f | wc -l)
    else
        bulk_file_count=0
    fi

    # Display the statistics
    echo "Analysis Start Time: $analysis_start_time"
    echo "Analysis End Time: $analysis_end_time"
    echo "Number of Files Extracted by Foremost: $foremost_file_count"
    echo "Number of Artifacts Found by Bulk Extractor: $bulk_file_count"
	sleep 1
    # Save the statistics to a file
    echo "Analysis Start Time: $analysis_start_time" > "$output_dir/general_statistics.txt"
    echo "Analysis End Time: $analysis_end_time" >> "$output_dir/general_statistics.txt"
    echo "Number of Files Extracted by Foremost: $foremost_file_count" >> "$output_dir/general_statistics.txt"
    echo "Number of Artifacts Found by Bulk Extractor: $bulk_file_count" >> "$output_dir/general_statistics.txt"

    echo "[*] General statistics saved in $output_dir/general_statistics.txt"
    sleep 1
}

function EXP() {
    echo "[*] Preparing to export output folder..." # LOG
    cd "$FOLDER" || exit 1  # Ensure the script exits if changing directory fails

    read -p "[?] Do you want to export the results to a zip file? (y/n): " choice
    if [[ "$choice" == "y" || "$choice" == "Y" ]]; then
        # Define the zip file name and path
        save_path="${output_dir##*/}.zip"  # Use only the base name of output_dir for the zip file

        # Check if a zip file with the same name already exists and delete it if so
        if [ -f "$save_path" ]; then
            echo "[*] A zip file with the name $save_path already exists. Deleting it..."
            rm "$save_path"
        fi

        # Check if output_dir exists
        if [ -d "$output_dir" ]; then
            # Zip the contents without including full path structure
            (cd "$output_dir" && zip -r "../$save_path" .) >/dev/null 2>&1

            # Remove the output directory after zipping
            rm -rf "$output_dir"

            echo "Exported successfully to $save_path"
        else
            echo "[!] Output directory does not exist: $output_dir"
        fi
    else
        echo "[*] Export skipped by user."
    fi
}




INSTALL_DEPENDENCIES
data
analyze_with_volatility
display_network_connections
extract_registry_information
save_results_to_report
display_general_statistics
EXP

echo "[!] Thank you for trying out my project!"
