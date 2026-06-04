#!/bin/bash

# Color Codes
RED='\033[0;31m'        # Red
GREEN='\033[0;32m'      # Green
NC='\033[0m'           # No Color (Reset)
BLUE="\e[34m"           # Blue
YELLOW='\033[1;33m'      # Yellow

# Set time stamp and variables
TS=$(date +"%Y-%m-%d_%H-%M-%S")
START_TIME=$(date +%s)
audit_path="/home/kali/project"
mkdir -p "$audit_path"

tools=("binwalk" "bulk_extractor" "foremost" "strings" "exiftool" "voli")
my_strings=("username" "password" "address" "admin" "root" "http://")
voli_plugins=("pstree" "printkey" "pslist" "cmdline" "connscan")

# Check if the script is running as root
function check_root() {
echo -e "${BLUE}=== Automated Windows Forensics Tool ===${NC}"
sleep 1
if [[ $EUID == "0" ]];
    then
        echo -e "The script is running with ${RED}root${NC} privilege"
    else
        echo -e "[!] The script must run with ${RED}root!${NC} exit now. bye bye"
        exit 1
fi
}

# Ask the user for a file and validate it exists
function check_file() {
read -p "Enter file to analyze: " FILE
    if [[ -z "$FILE" ]]
        then
            echo "No file entered"
            exit 1
    fi
    if [[ ! -f "$FILE" ]]
        then
        echo "File does not exist"
        exit 1
    fi
    echo "File found: $FILE"
    FILE_TYPE=$(file -b "$FILE")
    echo "File Type: $FILE_TYPE"
    if [[ "$FILE_TYPE" == "ASCII text" ]]; then
        echo "[!] This looks like a text file, not a memory dump"
    fi

    sleep 2
}

# Checking tools instaltion and install if missing
function install_tools() {
echo -e "${YELLOW}Checking for tools..${NC}"
sleep 1
# Using for loop with a list call object from the list with ${tools[@]}
for tool in "${tools[@]}"; do
    if command -v "$tool" > /dev/null 2>&1 ;
        then
            echo -e "${GREEN}$tool is installed${NC}"
        else
            apt install "$tool" -y > /dev/null 2>&1
    fi
done 
}

# Create directory for output
function output_dir() {
OUTPUT_DIR="$audit_path/analysis_$TS"
mkdir -p "$OUTPUT_DIR"
echo "Output directory created: $OUTPUT_DIR"
}

# Run carving and human-readable extraction tools
function run_carvers() {
mkdir -p "$OUTPUT_DIR/foremost"
foremost "$FILE" -o "$OUTPUT_DIR/foremost" > /dev/null 2>&1
mkdir -p "$OUTPUT_DIR/bulk"
bulk_extractor "$FILE" -o "$OUTPUT_DIR/bulk" > /dev/null 2>&1
mkdir -p "$OUTPUT_DIR/binwalk"
binwalk -e "$FILE" -C "$OUTPUT_DIR/binwalk" > "$OUTPUT_DIR/binwalk.txt" 2>&1
exiftool "$FILE" > "$OUTPUT_DIR/exif_metadata.txt" 2>&1
strings "$FILE" > "$OUTPUT_DIR/strings.txt"
grep -Eai "password|passwd|user(name)?|login|email|apikey|token" "$OUTPUT_DIR/strings.txt" > "$OUTPUT_DIR/human_hits.txt"
echo -e "${GREEN}Carving and strings analysis completed${NC}"
}

# Find pcap files
function find_network_traffic() {
echo -e "${YELLOW}Searching for network traffic artifacts...${NC}"
sleep 2
pcap_files=$(find "$OUTPUT_DIR" -type f \( -iname "*.pcap" -o -iname "*.pcapng" \) 2>/dev/null)

if [[ -z "$pcap_files" ]]; then
    echo "No network traffic files found"
    return 0
fi

echo -e "${GREEN}Network traffic found:${NC}"

while IFS= read -r pcap; do
    size=$(du -h "$pcap" 2>/dev/null | awk '{print $1}')
    echo "PCAP: $pcap (Size: $size)"
done <<< "$pcap_files"
}

# Analyze memory dump with Volatility plugins
function memory_analysis() {
echo -e "${YELLOW}Starting memory analysis...${NC}"
sleep 2

IMAGEINFO=$(voli -f "$FILE" imageinfo 2>/dev/null)
if [[ -z "$IMAGEINFO" ]]; then
    echo "Volatility cannot analyze this file"
    return 0
fi
image=$(echo "$IMAGEINFO" | grep -i "Suggested" | awk '{print $4}' | sed 's/,//g' | head -n 1)
if [[ -z "$image" || "$image" == "No" ]]; then
    echo "The file is not a valid memory image"
    return 0
fi
echo "Detected memory profile: $image"
mkdir -p "$OUTPUT_DIR/voli"

for plug in "${voli_plugins[@]}"; do
    echo "Running plugin: $plug"
    voli -f "$FILE" --profile="$image" "$plug" > "$OUTPUT_DIR/voli/$plug.$TS.txt" 2>&1
done
}

# Creating summary report
function generate_report() {
echo -e "${YELLOW}Generating report...${NC}"

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
REPORT_FILE="$OUTPUT_DIR/report_$TS.txt"

echo "===== FORENSICS ANALYSIS REPORT =====" > "$REPORT_FILE"
echo "Analysis Time: $TS" >> "$REPORT_FILE"
echo "Analysis Duration: ${ELAPSED} seconds" >> "$REPORT_FILE"
echo "Analyzed File: $FILE" >> "$REPORT_FILE"

FILE_SIZE=$(du -h "$FILE" | awk '{print $1}')
echo "File Size: $FILE_SIZE" >> "$REPORT_FILE"
echo "File Type: $FILE_TYPE" >> "$REPORT_FILE"
echo "Output Directory: $OUTPUT_DIR" >> "$REPORT_FILE"

TOTAL_FILES=$(find "$OUTPUT_DIR" -type f | wc -l)
echo "Total Extracted Files: $TOTAL_FILES" >> "$REPORT_FILE"

if [[ -d "$OUTPUT_DIR/voli" ]]; then
    VOLI_FILES=$(find "$OUTPUT_DIR/voli" -type f | wc -l)
    echo "Volatility Output Files: $VOLI_FILES" >> "$REPORT_FILE"
fi
if [[ -f "$OUTPUT_DIR/human_hits.txt" ]]; then
    HUMAN_HITS=$(wc -l < "$OUTPUT_DIR/human_hits.txt")
    echo "Human Readable Hits: $HUMAN_HITS" >> "$REPORT_FILE"
fi
echo -e "${GREEN}Report created: $REPORT_FILE${NC}"
}

# Compress the analysis results into a ZIP archive
function zip_results() {
echo -e "${YELLOW}Creating archive...${NC}"
ARCHIVE_NAME="analysis_$TS.zip"
zip -r "$ARCHIVE_NAME" "$OUTPUT_DIR" > /dev/null 2>&1
echo -e "${GREEN}Archive created: $ARCHIVE_NAME${NC}"
}

check_root
check_file
install_tools
output_dir
run_carvers
find_network_traffic
memory_analysis
generate_report
zip_results