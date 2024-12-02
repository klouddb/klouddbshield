import os
import subprocess
import smtplib
import glob
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime

# Define constants

######### FILL IN THE FOLLOWING VARIABLES #########
FILE = "<ADD FILE LOCATION HERE>"  # Assuming this is your input log file
PREFIX = "<ADD PREFIX HERE>"  # Add the prefix for the report
EMAIL = "<ADD YOUR EMAIL ID HERE>"  # Add the email address where you want to send the report
###################################################

### OTHER VARIABLES ###
CISCOLLECTOR_VERSION = "2.0"
REPORT_FILE = "klouddbshield_report.html"  # This will be the generated report

def check_installation(command):
    """Check if a command is installed and return its path."""
    result = subprocess.run(['which', command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout.strip()

def check_ciscollector_version():
    """Check if ciscollector is installed and its version."""
    ciscollector_path = check_installation("ciscollector")
    if not ciscollector_path:
        print("Error: ciscollector is not installed.")
        return False

    result = subprocess.run([ciscollector_path, "--version"], stdout=subprocess.PIPE, text=True)
    installed_version = result.stdout.strip()

    # installed_version ends with version=dev or greater than 2.0
    # if installed_version.endswith("version=dev") or installed_version < CISCOLLECTOR_VERSION:
    #     print(f"Error: ciscollector version {installed_version} is not supported. Please install version {CISCOLLECTOR_VERSION}.")
    #     return False

    return True

def check_file_exists(file_path):
    """check if it is file path or regex for files"""
    # Use glob to find all files matching the pattern
    log_files = glob.glob(file_path)

    if log_files:
        print(f"Log files found: {log_files}")
        return True
    else:
        print(f"No log files found at {os.path.dirname(log_path)}")
        return False

def run_ciscollector():
    """Run the ciscollector command."""
    result = subprocess.run(['ciscollector', '-logparser', 'inactive_users', '-prefix', PREFIX, '-file-path', FILE], stderr=subprocess.PIPE)
    if result.returncode != 0:
        print("Error: Failed to run ciscollector.")
        return False
    return True

def check_report_exists():
    """Check if the report file exists."""
    if not os.path.isfile(REPORT_FILE):
        print(f"Error: Report file {REPORT_FILE} was not generated.")
        return False
    return True

def send_email(report_file, email):
    """Send the report as an email."""
    generated_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Set up the email
    msg = MIMEMultipart()
    msg['From'] = "<YOUR EMAIL>"
    msg['To'] = email
    msg['Subject'] = f"Ciscollector Report generated at {generated_time}"

    with open(report_file, 'r') as f:
        html_report = f.read()

    msg.attach(MIMEText(html_report, 'html'))

    # Set up the server (using localhost as the SMTP server)
    try:
        server = smtplib.SMTP('localhost')
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print(f"Report sent successfully to {email} at {generated_time}.")
    except Exception as e:
        print(f"Error: Failed to send the report. {str(e)}")

def rename_report():
    # Get the current timestamp in the desired format
    timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

    # Construct the new file name with the timestamp
    new_report_file = f"{REPORT_FILE}.{timestamp}.html"

    # Rename the file
    os.rename(REPORT_FILE, new_report_file)

    print(f"Renamed {REPORT_FILE} to {new_report_file}")

def main():
    # Check if ciscollector is installed and has the right version
    if not check_ciscollector_version():
        return

    # Check if the input file exists
    if not check_file_exists(FILE):
        return

    # Run ciscollector command
    if not run_ciscollector():
        return

    # Check if the report file was generated
    if not check_report_exists():
        return

    # Send the email with the report attached
    send_email(REPORT_FILE, EMAIL)

    # Rename the report file
    rename_report()

if __name__ == "__main__":
    main()
