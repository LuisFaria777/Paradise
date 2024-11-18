
from django.conf import settings
from twilio.rest import Client
import os
from dotenv import load_dotenv
from email import message

load_dotenv()



phone_number = os.getenv("PHONE_NUMBER")
account_sid = os.getenv("TWILIO_ACCOUNT_SID")
auth_token = os.getenv("TWILIO_AUTH_TOKEN")
verify_sid = os.getenv ("VERIFY_SID")

client = Client(account_sid, auth_token)

otp_verification = client.verify.services(verify_sid).verifications.create(
    to=phone_number, channel="sms"
)

print(otp_verification.status)
otp_code = input("Please enter the OTP send to you: ")

otp_vcheck = client.verify.services(verify_sid).verification_checks.create(
    to=phone_number, code=otp_code
)

print(otp_vcheck.status)