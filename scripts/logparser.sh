#!/bin/bash

# Define constants

######### FILL IN THE FOLLOWING VARIABLES #########

FILE="<ADD LOG PREFIX FILE LOCATION>"  # Assuming this is your input log file
PREFIX="<ADD PREFIX MANUALLY HERE>" # Add the prefix for the report
EMAIL="<ADD EMAIL HERE>" # Add the email address where you want to send the report

###################################################

### OTHER VARIABLES ###
CISCOLLECTOR_VERSION="2.0"
REPORT_FILE="klouddbshield_report.html"  # This will be the generated report

CISCOLLECTOR_PATH=$(which ciscollector)
# Check if ciscollector is installed
if [ -z "$CISCOLLECTOR_PATH" ]; then
  echo "Error: ciscollector is not installed."
  exit 1
fi

# Check the version of ciscollector
INSTALLED_VERSION=$($CISCOLLECTOR_PATH --version | grep -oP '\d+\.\d+')
# installed version must be higher than 2.0
if [ $(echo "$INSTALLED_VERSION >= $CISCOLLECTOR_VERSION" | bc) -eq 0 ]; then
  echo "Error: ciscollector version must be higher than " $CISCOLLECTOR_VERSION
  exit 1
fi


# Check if mailx is installed
if ! command -v mailx &> /dev/null; then
  echo "Error: mailx is not installed."
  exit 1
fi

# Check if input file exists
# Check if any files match the pattern
if ls $log_path 1> /dev/null 2>&1; then
  echo "Log files found at $log_path"
else
  echo "No log files found at $log_path"
  exit 1
fi
# Run the ciscollector command to generate the report
# ciscollector -logparser inactive_users -prefix "$PREFIX" -file-path "$FILE"
ciscollector -logparser inactive_users -prefix "$PREFIX" -file-path "$FILE"
if [ $? -ne 0 ]; then
  echo "Error: Failed to run ciscollector."
  exit 1
fi

# Check if the report file was created
if [ ! -f "$REPORT_FILE" ]; then
  echo "Error: Report file $REPORT_FILE was not generated."
  exit 1
fi

# Send the email with the report.html attached
GENERATED_TIME=$(date '+%Y-%m-%d %H:%M:%S')
#echo "Report generated at $GENERATED_TIME" | mailx -s "CISCollector Report" -A "$REPORT_FILE" $EMAIL
#echo "Report generated at $GENERATED_TIME" | mailx -a "Content-Type: text/html" -s "Ciscollector Report" $EMAIL < $REPORT_FILE
mailx -a "Content-Type: text/html" -s "Ciscollector Report generated at $GENERATED_TIME" $EMAIL < "$REPORT_FILE"

if [ $? -eq 0 ]; then
  echo "Report sent successfully to $EMAIL at $GENERATED_TIME. "
else
  echo "Error: Failed to send the report."
fi

# change name of the report file to include the date
mv $REPORT_FILE $REPORT_FILE.$(date +%Y-%m-%d_%H-%M-%S).html
