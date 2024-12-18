# Windows Forensics - Analyzer

**Author**: Aviv Feldvari

## Project Description
The Windows Forensics Analyzer is a comprehensive script designed to assist in forensic investigations by:
- Verifying user privileges to ensure proper permissions for forensic tasks.
- Analyzing memory or disk images provided by the user.
- Extracting valuable data while maintaining organized and secure output.
- Generating detailed summaries and reports for further investigation.

## Functionality
### Project's Mission
The mission of this project is to:
- Validate user permissions for secure and effective analysis.
- Automatically manage dependencies and required forensic tools.
- Extract and analyze data from memory or disk images.
- Provide structured reports summarizing extracted data and findings.

## Script Sections

### User Verification
- The script ensures it is executed with root privileges to guarantee the necessary permissions for installation and analysis tasks.

### File Input Handling
- Users are prompted to specify a filename for the memory or disk image to be analyzed.
- The script verifies the existence of the specified file to prevent processing errors.

### Dependency Management
- The script checks for the presence of required forensic tools, including:
  - `bulk_extractor`
  - `foremost`
- If any tools are missing, the script attempts to install them and provides error messages if installations fail.

### Data Extraction
- The script uses data carvers such as `foremost` and `bulk_extractor` to extract:
  - File artifacts
  - Metadata
- Results are saved in a structured output directory. Existing directories with the same name are overwritten to ensure clarity and organization.

### Network Data Extraction
- The script identifies and highlights network traffic artifacts found in the memory or disk image, displaying their locations and sizes for quick user reference.

### Human-Readable Data Search
- The script scans for human-readable data, focusing on sensitive information such as usernames and passwords, saving the results for further analysis.

### Carved Data Results Summary
- Upon completing the data carving process, a summary of extracted results is provided. This includes:
  - File sizes
  - Types of recovered data
- Users can quickly evaluate the effectiveness of the recovery process.

### Memory Analysis with Volatility
- The script integrates Volatility for advanced memory analysis, extracting details such as:
  - Running processes
  - Active network connections
- The script ensures compatibility with the specified memory image.

### Registry Information Extraction
- The script extracts registry information from the memory image, offering insights into system configurations and potential artifacts.

### Result Reporting
- At the conclusion of the analysis, the script compiles:
  - Extracted files
  - Summaries of findings
- These are saved in a structured report for easy reference.

### Statistics and Zip Export
- The script provides general statistics about the analysis process, including:
  - Duration of analysis
  - Number of files extracted
- Users can choose to compress the results and reports into a zip file for convenient storage and sharing.

## How to Run the Script
1. Ensure the script has executable permissions:
   "chmod +x analyzer.sh" 

2. Run the script
  "./analyzer.sh"

3. Follow the instructions
