# -*- coding: utf-8 -*-
"""
Meds_tracker allows multiple users to track the medications they are taking and 
sends an email notification when the number of days left of medications is 10. 
The initial file has the account name, name of the medication, number of pills per boxes available,
number of medications taken a day and when the available pills per medication were started.
Upon reaching 0 days, the program updates the file with the current date for the start date value 
and the countdown starts again.
"""

import os
import json
import logging
import base64
import pandas as pd
import io
import dropbox
from dropbox.exceptions import ApiError, HttpError
import jmespath
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
from googleapiclient.discovery import build
from google.cloud import secretmanager
from io import BytesIO

# Read the Dropbox token from a file in your GitHub repo
# App credentials
APP_KEY =os.getenv("DROPBOX_APP_KEY")
APP_SECRET = os.getenv("DROPBOX_APP_SECRET")
REFRESH_TOKEN = os.getenv("DROPBOX_REFRESH_TOKEN")

if not all([APP_KEY, APP_SECRET, REFRESH_TOKEN]):
    print("Missing environment variables!")
    exit(1)

# Use the refresh token to get a new access token
try:
    dbx = dropbox.Dropbox(
        oauth2_refresh_token=str(REFRESH_TOKEN),
        app_key=str(APP_KEY),
        app_secret=str(APP_SECRET)
    )
    access_token = dbx._oauth2_access_token
    #print(f"New access token: {access_token}")
except Exception as e:
    print(f"Error: {e}")
    
# Setting up logging
# Path to the file in Dropbox
log_file= 'meds_tracker.log'

DROPBOX_FILE_PATH_log = f"/{log_file}"

if access_token:
    print('it is doing')
    dbx = dropbox.Dropbox(access_token)
    print('access token done')
try:
    metadata, res = dbx.files_download("/meds_tracker.log")
    print('getting log')
    with open(log_file, "wb") as f:
        f.write(res.content)
    print("Existing log file downloaded from Dropbox.")
except dropbox.exceptions.ApiError:
    print("No previous log found. Starting fresh.")
    with open(log_file, "wb") as f:
         f.write(b"")  # Empty log file created


    
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt='%d-%m-%Y %H:%M',
    handlers=[
        logging.FileHandler(log_file, mode="a"),  # Append to log
        logging.StreamHandler(),
    ],
)

logging.info("NEW SCRIPT RUN STARTED.")

# Secure OAuth2 Scopes (Least Privilege)
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

SECRET_NAME = "GMAIL_TOKEN"  # The name of your secret in Google Cloud
PROJECT_ID = "medstracker-452518"


def get_secret():
    """Retrieve refresh token from Google Cloud Secret Manager."""
    try:
        client = secretmanager.SecretManagerServiceClient()
        secret_path = f"projects/{PROJECT_ID}/secrets/{SECRET_NAME}/versions/latest"
        response = client.access_secret_version(request={"name": secret_path})
        secret_data = response.payload.data.decode("UTF-8")
        if not secret_data:
            logging.warning("Retrieved secret is empty.")
        return secret_data
    except Exception as e:
        logging.error(f"Failed to retrieve secret: {e}")
        raise
   
def update_secret(new_token):
    """Update the refresh token in Google Cloud Secret Manager."""
    if not new_token:
       logging.warning("Attempted to update secret with an empty token.")
       return

    try:
       client = secretmanager.SecretManagerServiceClient()
       parent = f"projects/{PROJECT_ID}/secrets/{SECRET_NAME}"
       client.add_secret_version(
           request={"parent": parent, "payload": {"data": new_token.encode("UTF-8")}}
       )
       logging.info("🔄 Refresh token updated in Secret Manager.")
    except Exception as e:
       logging.error(f"Failed to update secret: {e}")
       raise
   
#Path to your service account JSON key file
SERVICE_ACCOUNT_FILE = os.getenv("GOOGLE_SERVICE_KEY")
if not SERVICE_ACCOUNT_JSON:
    logging.error("SERVICE_ACCOUNT_JSON environment variable is not set.")
else:
    logging.info("SERVICE_ACCOUNT_JSON retrieved successfully.")
# Define your OAuth2 scopes
SCOPES = ["https://www.googleapis.com/auth/gmail.send"]

def get_credentials():
    """Authenticate using a service account JSON key file."""
    try:
        creds = service_account.Credentials.from_service_account_file(
            SERVICE_ACCOUNT_FILE, scopes=SCOPES
        )
        logging.info("Service account credentials created successfully.")
        return creds
    except Exception as e:
        logging.error(f"Failed to create service account credentials: {e}")
        raise

def build_gmail_service(creds):
    """Build the Gmail API service using the provided credentials."""
    try:
        service = build("gmail", "v1", credentials=creds)
        logging.info("Gmail API service built successfully.")
        return service
    except Exception as e:
        logging.error(f"Failed to build Gmail API service: {e}")
        raise



# Validate email addresses to prevent header injection
def is_valid_email(email):
    import re
    return re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", email) is not None

# Secure function to send email
def send_email(email, subject, body):
    if not is_valid_email(email):
        logging.warning(f"Invalid email: {email}")
        return
    
    # Getting sender email
    try:
        # Parse the sender JSON
        sender_email = os.getenv("SENDER")
    except json.JSONDecodeError as e:
        logging.error(f"Failed to parse sender JSON: {e}")
        raise
        
    msg = MIMEText(body)
    msg["to"] = email
    msg["subject"] = subject
    msg["from"] = sender_email

    # Encode message
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode()
    message = {"raw": raw}
    
    creds = get_credentials()
    service = build_gmail_service(creds)
    try:
        service.users().messages().send(userId="me", body=message).execute()
        logging.info(f"✅ Email sent successfully to {email}")
    except Exception as e:
        logging.error(f"❌ Failed to send email to {email}: {e}")

#Get the credentials to prepare to send emails and keep the token refreshed
#creds = get_credentials()

# Download file into memory
DROPBOX_FILE_PATH_meds = "/meds.csv"
try:
    # Download the file from Dropbox
    _, res = dbx.files_download(DROPBOX_FILE_PATH_meds)
    logging.info(f"✅ Successfully downloaded file: {DROPBOX_FILE_PATH_meds}")

    # Load the file content into a BytesIO object
    csv_data = io.BytesIO(res.content)

    # Read medication data securely
    try:
        data = pd.read_csv(csv_data)
        logging.info("✅ Successfully loaded CSV data into DataFrame.")
    except pd.errors.EmptyDataError:
        logging.error("❌ The CSV file is empty.")
        exit(1)
    except pd.errors.ParserError:
        logging.error("❌ The CSV file is malformed or cannot be parsed.")
        exit(1)
    except Exception as e:
        logging.error(f"❌ An unexpected error occurred while reading the CSV file: {e}")
        exit(1)
    finally:
        # Ensure the BytesIO object is closed
        csv_data.close()

except ApiError as e:
    logging.error(f"❌ Dropbox API error: {e}")
    exit(1)
except HttpError as e:
    logging.error(f"❌ HTTP error while downloading file: {e}")
    exit(1)
except Exception as e:
    logging.error(f"❌ An unexpected error occurred: {e}")
    exit(1)


# Calculate medication end date
data["start_date"] = pd.to_datetime(data["start_date"], format="%d-%m-%Y")
today = pd.Timestamp.today().normalize()
pills_taken = (today - data["start_date"]).dt.days.astype(int)


accounts_json = os.getenv("ACCOUNTS")
if not accounts_json:
    logging.warning("ACCOUNTS environment variable is not set.")
    
try:
    # Parse the token JSON
    accounts_info = json.loads(accounts_json)
except json.JSONDecodeError as e:
    logging.error(f"Failed to parse accounts JSON: {e}")
    raise


# Check remaining pills and send reminders
for index, row in data.iterrows():
    remaining_days = int((row["N_pills"] - pills_taken[index])/row['pills_per_day'])
    
    if remaining_days == 10:
        email = jmespath.search(f"Accounts[?name == '{row['Acc_name']}'].email",accounts_info)
        if is_valid_email(email[0]):
            body = f"Reminder: You have only {remaining_days} days left for {row['Med_name']}."
            send_email(email[0], f"Medication Reminder: {row['Med_name']}", body)
        else:
            logging.warning(f"Skipping invalid email: {email}")
    else:
        logging.info(f"Medication {row['Med_name']} has {remaining_days} days left—no reminder needed.")
    if remaining_days == 0:
        data.loc[index,'start_date'] = today
        logging.info(f"{row['Med_name']} has been changed")
        print((f"{row['Med_name']} has been changed"))
        
#Make sure start_date is in the correct format
data['start_date'] = data['start_date'].dt.strftime("%d-%m-%Y")

#rewriting the  meds file to dropbox
try:
    # Convert DataFrame to CSV in memory
    csv_buffer = BytesIO()
    data.to_csv(csv_buffer, index=False)
    csv_buffer.seek(0)
    dbx.files_upload(csv_buffer.getvalue(), DROPBOX_FILE_PATH_meds , mode=dropbox.files.WriteMode("overwrite"))
    logging.info('Meds updated correctly')
except dropbox.exceptions.ApiError as e:
        logging.error(f"Dropbox API error: {e}")
        
        # If the error contains a detailed response, log that too
        if isinstance(e.error, dropbox.files.UploadError):
            logging.error(f"UploadError details: {e.error}")
            
except dropbox.exceptions.AuthError:
        logging.critical("Authentication failed. Check your access token.")
        
except dropbox.exceptions.HttpError as e:
        logging.error(f"HTTP error occurred: {e}")
except Exception as e:
        logging.exception(f"An unexpected error occurred: {e}")
        
# updating log file to dropbox
with open(log_file, "rb") as f:
     dbx.files_upload(f.read(), f"/{log_file}", mode=dropbox.files.WriteMode("overwrite"))
     logging.info("Updated log file uploaded to Dropbox.")

