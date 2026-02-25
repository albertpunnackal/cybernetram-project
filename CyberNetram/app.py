import os
import hashlib
import requests
import random  # Added for shuffling
from flask import Flask, render_template, request, jsonify
from zxcvbn import zxcvbn

app = Flask(__name__)

# --- CONFIGURATION ---
VT_API_KEY = 'YOUR_VIRUSTOTAL_API_KEY_HERE' 

# --- INTERNAL THREAT DATABASE ---
LOCAL_MALWARE_DB = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Test Virus (Signature A)",
    "44d88612fea8a8f36de82e1278abb02f": "EICAR Test Virus (Signature B)",
    "3395856ce81f2b7382dee72602f798b642f14140": "EICAR Test Virus (Signature C)",
    # --- Custom Demo Files ---
    "d45c5ca9fb33e79a34d520fa0903f3049608364bfc2a62b8b7c1971e0d716b2b": "WannaCry Ransomware (Demo)",
    "67f97f267c6d061185ba99e3a86709475069c68f166aa8f80cb506986dec0d61": "Zeus Banking Trojan (Demo)"
}

# --- PHISHING SIMULATOR DATA (High Fidelity - 25 Scenarios) ---
EMAILS = [
    {
        "id": 1,
        "sender_name": "Netflix Support",
        "sender_email": "billing@netfllx-update.com",
        "subject": "Action Required: Payment Declined",
        "body_top": "Dear Customer,<br><br>We were unable to process your latest subscription payment. To avoid service interruption, please update your billing details immediately.",
        "link_text": "Update Payment Here",
        "real_link": "http://billing-update-netfllx.com/login",
        "body_bottom": "Thank you,<br>The Netflix Team",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "This is a classic urgency scam. Look closely at the sender email: 'netfllx' uses an 'L' instead of an 'I'. This is called a Homoglyph attack.",
        "tips": "Always hover over links without clicking to see the true destination."
    },
    {
        "id": 2,
        "sender_name": "HR Department",
        "sender_email": "hr@mycompany.com",
        "subject": "Updated 2024 Holiday Schedule",
        "body_top": "Hi Team,<br><br>Please find the updated company holiday schedule for the upcoming year attached below. Let your managers know if you have any overlapping PTO requests.",
        "link_text": "Download Q3_Handbook.pdf",
        "real_link": "https://internal.mycompany.com/docs/q3-handbook",
        "body_bottom": "Best,<br>Human Resources",
        "type": "safe",
        "critical_zones": [],
        "explanation": "This is a legitimate email. The sender matches the internal company domain, and the link points to the internal intranet securely.",
        "tips": "Internal emails usually come from your exact company domain without urgency."
    },
    {
        "id": 3,
        "sender_name": "IT Helpdesk",
        "sender_email": "admin@company-support-portal.net",
        "subject": "URGENT: Password Expiry Notification",
        "body_top": "Your Office365 password will expire in exactly 2 hours.",
        "link_text": "Verify Password Now",
        "real_link": "http://it-support-portal.net/login-auth-verify",
        "body_bottom": "If you do not retain your current password via the link above, you will be locked out of your workstation.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "IT departments rarely threaten lockouts with 2-hour notices. The sender domain is fake (.net), and the link points to an insecure (http) login portal.",
        "tips": "IT will never ask you to click a link to reset a password unexpectedly."
    },
    {
        "id": 4,
        "sender_name": "GeekSquad Billing",
        "sender_email": "auto-renew@geeksquad-billing-alerts.com",
        "subject": "Invoice #88392: Auto-Renewal Processed",
        "body_top": "Thank you for your business!<br><br>Your annual GeekSquad Advanced Protection subscription has been successfully auto-renewed for <strong>$399.99</strong>.",
        "link_text": "Cancel Subscription & Refund",
        "real_link": "http://refund-geeksquad-auth.com/cancel",
        "body_bottom": "If you did not authorize this charge, you have 24 hours to cancel the transaction by clicking the link above.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "This is a 'Fake Invoice' scam. They charge a high amount to induce panic, hoping you'll click the refund link to hand over your credit card details.",
        "tips": "Never click refund links in emails. Log in to your actual bank account to check for charges."
    },
    {
        "id": 5,
        "sender_name": "CEO (Private)",
        "sender_email": "ceo.name.private@gmail.com",
        "subject": "Urgent Request - Confidential",
        "body_top": "Are you available right now?<br><br>I am stuck in a board meeting and cannot take calls. I need you to handle an urgent task for a client presentation.",
        "link_text": "Reply Immediately",
        "real_link": "mailto:ceo.name.private@gmail.com",
        "body_bottom": "I need you to purchase 5x $100 Apple Gift Cards immediately. I will reimburse you by the end of the day.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-body"],
        "explanation": "This is Business Email Compromise (BEC) or 'CEO Fraud'. Executives never ask employees to buy gift cards using a personal Gmail address.",
        "tips": "If a request involves money or gift cards, verify it by calling the person directly."
    },
    {
        "id": 6,
        "sender_name": "Google Security",
        "sender_email": "no-reply@accounts.google.com",
        "subject": "Security alert: New sign-in on Mac",
        "body_top": "Your Google Account was just signed in to from a new Mac device.<br><br><strong>Location:</strong> Seattle, WA, USA<br><strong>Time:</strong> Just now",
        "link_text": "Check activity",
        "real_link": "https://myaccount.google.com/notifications",
        "body_bottom": "If this was you, you don't need to do anything. If not, we'll help you secure your account.",
        "type": "safe",
        "critical_zones": [],
        "explanation": "This is a legitimate Google Security alert. The sender email perfectly matches Google's official domain, and the link points securely to myaccount.google.com.",
        "tips": "Legitimate alerts point directly to the service's official domain (https)."
    },
    {
        "id": 7,
        "sender_name": "FedEx Delivery",
        "sender_email": "tracking@fedex-express-info.net",
        "subject": "Final Notice: Package Undelivered",
        "body_top": "We attempted to deliver your package #TRK882194 but no one was home.",
        "link_text": "Schedule Re-Delivery ($1.99 Fee)",
        "real_link": "http://fedex-redelivery-fees.com/pay",
        "body_bottom": "If you do not schedule a re-delivery within 12 hours, the package will be returned to the sender.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "FedEx emails come from fedex.com, not a .net domain. Scammers use tiny fees ($1.99) to trick you into entering your credit card information.",
        "tips": "Copy the tracking number and paste it into the official FedEx website manually."
    },
    {
        "id": 8,
        "sender_name": "Project Manager",
        "sender_email": "pm@mycompany.com",
        "subject": "Meeting Notes: Sprint Review",
        "body_top": "Here are the notes from today's meeting. Action items are highlighted in yellow.",
        "link_text": "View Notes on Intranet",
        "real_link": "https://intranet.mycompany.com/sprint-notes",
        "body_bottom": "See you at the standup tomorrow.",
        "type": "safe",
        "critical_zones": [],
        "explanation": "Legitimate communication from a known colleague with a correct, secure internal intranet link.",
        "tips": "Internal emails usually have a predictable tone and come from correct internal addresses."
    },
    {
        "id": 9,
        "sender_name": "LinkedIn Security",
        "sender_email": "security@linkedin-alerts.com",
        "subject": "Security Alert: New Login from Beijing",
        "body_top": "We detected a login from Beijing, China. If this wasn't you, secure your account immediately.<br><br>IP Address: 192.168.x.x",
        "link_text": "Secure My Account",
        "real_link": "http://linkedin-verify-login.com",
        "body_bottom": "Failure to verify will result in account suspension.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "The domain 'linkedin-alerts.com' is fake. Real alerts come from 'linkedin.com'. The link is also unencrypted.",
        "tips": "Enable 2FA on your social accounts. If you get an alert, login via the official app, not the email link."
    },
    {
        "id": 10,
        "sender_name": "Microsoft Teams",
        "sender_email": "noreply@teams-voice-mail.xyz",
        "subject": "You have a new voicemail (0:35s)",
        "body_top": "You missed an audio call from 'Management Office'. A voicemail has been recorded.",
        "link_text": "▶ Listen to Voicemail",
        "real_link": "http://credential-harvester.com/login",
        "body_bottom": "Message stored on cloud server 44A.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "Teams emails come from microsoft.com. The '.xyz' domain is cheap and commonly used by scammers. The link points to a credential harvester.",
        "tips": "Do not click 'Play' in emails. Open the actual Teams application to check for missed calls."
    },
    {
        "id": 11,
        "sender_name": "Google Drive",
        "sender_email": "drive-shares-noreply@google.com",
        "subject": "Document Shared with You",
        "body_top": "John Doe shared a document: <strong>'Q4 Financials.xlsx'</strong> with you.",
        "link_text": "Open in Sheets",
        "real_link": "https://docs.google.com/spreadsheets/d/1BxiMVs0X",
        "body_bottom": "Google Drive: Keep everything. Share anything.",
        "type": "safe",
        "critical_zones": [],
        "explanation": "This is a real Google Docs notification. The sender is google.com and the link securely points to docs.google.com.",
        "tips": "Check the sender carefully. Google notifications come from google.com, not gmail.com."
    },
    {
        "id": 12,
        "sender_name": "Bank of America",
        "sender_email": "alerts@bofa-security-check.info",
        "subject": "Unauthorized Login Attempt",
        "body_top": "We detected a login to your account from IP 192.168.1.1 (Moscow). Was this you?<br><br>Your account has been frozen for your protection. Please verify your identity.",
        "link_text": "No, Secure Account",
        "real_link": "http://bofa-verify-identity.com",
        "body_bottom": "Bank of America Security Team",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "Banks do not use '.info' domains. They also won't freeze an account via an email link; they ask you to call them. The link is unencrypted (http).",
        "tips": "Never trust geolocation alerts blindly. Open the banking app directly."
    },
    {
        "id": 13,
        "sender_name": "DocuSign Service",
        "sender_email": "docs@docusign-files-secure.net",
        "subject": "Completed: NDA_Agreement_v2.pdf",
        "body_top": "A document has been shared with you for signature. Please review and sign immediately to proceed with the contract.",
        "link_text": "Review Document",
        "real_link": "http://credential-stealer.xyz/login",
        "body_bottom": "Powered by DocuSign",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "DocuSign emails come from @docusign.com. The sender domain here is fake, and the link leads to a credential stealer.",
        "tips": "Hover over the 'Review' button. If it doesn't go to docusign.com, do not click it."
    },
    {
        "id": 14,
        "sender_name": "IRS Tax Portal",
        "sender_email": "refunds@irs-gov-portal.org",
        "subject": "Eligible for Tax Refund - Claim Now",
        "body_top": "Dear Taxpayer,<br><br>After reviewing your recent tax returns, we have determined that you are eligible for a refund of $1,450.00.",
        "link_text": "Claim Your Refund",
        "real_link": "http://irs-refund-claim.com",
        "body_bottom": "Please submit your banking details via the secure portal above to process your claim.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "The IRS does not initiate contact with taxpayers by email. The domain '.org' is fake (IRS uses .gov).",
        "tips": "Government agencies will always use a .gov email address."
    },
    {
        "id": 15,
        "sender_name": "Zoom Meetings",
        "sender_email": "invites@zoom-video-call.com",
        "subject": "Meeting Started: Q1 Strategy Review",
        "body_top": "Your team is waiting for you in the meeting room. You are late.<br><br>Meeting ID: 882-112-992",
        "link_text": "Join Meeting Now",
        "real_link": "http://malware-download.com/zoom_installer.exe",
        "body_bottom": "Ensure your microphone is connected.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "The urgency ('You are late') makes you panic. Crucially, the link downloads an .exe (malware) file instead of launching the web portal.",
        "tips": "Don't click links to join meetings if you weren't expecting one. Paste the ID into the app."
    },
    {
        "id": 16,
        "sender_name": "Amazon Orders",
        "sender_email": "auto-confirm@amazon.com",
        "subject": "Your Order Confirmation - #114-928374-1029",
        "body_top": "Hello,<br><br>Thank you for shopping with us. We'll send a confirmation when your item ships.<br><br><strong>Item:</strong> Echo Dot (5th Gen)",
        "link_text": "View or Manage Order",
        "real_link": "https://www.amazon.com/orders",
        "body_bottom": "Amazon.com Services LLC",
        "type": "safe",
        "critical_zones": [],
        "explanation": "This is a legitimate order confirmation. The email is from amazon.com, and the link securely points to amazon.com.",
        "tips": "Check your actual Amazon app to verify if an order was placed."
    },
    {
        "id": 17,
        "sender_name": "MetaMask Wallet",
        "sender_email": "security@metamask-verify.io",
        "subject": "KYC Verification Required",
        "body_top": "Dear User,<br><br>To comply with new financial regulations, you must verify your wallet identity. Failure to verify within 48 hours will result in a suspension of your funds.",
        "link_text": "Verify Wallet (Enter Seed Phrase)",
        "real_link": "http://metamask-seed-verify.com",
        "body_bottom": "Thank you for cooperating.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "MetaMask is a non-custodial wallet and never asks for your Seed Phrase. Entering a seed phrase into a link gives hackers full access to your crypto.",
        "tips": "Never, ever type your Seed Phrase into a website."
    },
    {
        "id": 18,
        "sender_name": "Company IT",
        "sender_email": "updates@mycompany.com",
        "subject": "Mandatory System Update Scheduled",
        "body_top": "Hello everyone,<br><br>IT will be pushing a mandatory Windows update to all workstations tonight at 11:00 PM. Please leave your computers turned on.",
        "link_text": "Read the IT Policy",
        "real_link": "https://internal.mycompany.com/it-policy",
        "body_bottom": "No action is required on your part. Thanks, IT Operations",
        "type": "safe",
        "critical_zones": [],
        "explanation": "A standard, safe internal announcement. Notice there are no malicious links, no attachments to download, and no credentials requested.",
        "tips": "Routine IT notices rarely require you to click external links."
    },
    {
        "id": 19,
        "sender_name": "Dropbox Share",
        "sender_email": "no-reply@dropbox-file-share.com",
        "subject": "Project_Specs_Final.zip shared with you",
        "body_top": "A file <strong>'Project_Specs_Final.zip'</strong> (2.4 GB) has been shared with you via Dropbox.",
        "link_text": "Download File",
        "real_link": "http://malware-dropper.com/download.zip",
        "body_bottom": "Link expires in 24 hours.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "Dropbox uses 'dropbox.com'. The file extension .zip in the URL preview is a massive red flag, as zips are frequently used to hide malware.",
        "tips": "Be highly suspicious of .zip or .rar files shared from unknown addresses."
    },
    {
        "id": 20,
        "sender_name": "Red Cross Donations",
        "sender_email": "help@redcross-relief-fund.org",
        "subject": "Urgent: Earthquake Relief Fund",
        "body_top": "Thousands have been displaced by the recent disaster. They need your help now.<br><br>Please donate to our emergency relief fund to provide food and shelter.",
        "link_text": "Donate via Cryptocurrency",
        "real_link": "http://crypto-scam-donations.com/pay",
        "body_bottom": "Every dollar counts.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "Scammers prey on disasters. Legitimate charities rarely ask for anonymous cryptocurrency donations via sketchy unencrypted domains.",
        "tips": "Only donate by visiting the charity's official website directly."
    },
    {
        "id": 21,
        "sender_name": "City Traffic Dept",
        "sender_email": "citations@city-gov-traffic.com",
        "subject": "Notice of Traffic Violation",
        "body_top": "Vehicle registered in your name was caught running a red light.<br><br>Fine Amount: $150.00. Please view the photographic evidence and pay the fine within 15 days.",
        "link_text": "View Camera Evidence",
        "real_link": "http://traffic-fine-payment.com/evidence.exe",
        "body_bottom": "Failure to pay will result in a suspended license.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "Government domains end in .gov, not .com. Crucially, the link attempts to download an '.exe' file pretending to be 'evidence'—this is malware.",
        "tips": "An image or video should never be an .exe file. This is an immediate malware threat."
    },
    {
        "id": 22,
        "sender_name": "Spotify",
        "sender_email": "no-reply@spotify.com",
        "subject": "Your Year in Review is Here!",
        "body_top": "<h2>Spotify Wrapped</h2><br>It's that time of year again! See your top artists, songs, and genres from the past 12 months.",
        "link_text": "See Your Wrapped",
        "real_link": "https://open.spotify.com/wrapped",
        "body_bottom": "Keep listening!",
        "type": "safe",
        "critical_zones": [],
        "explanation": "Legitimate marketing email. Sender domain matches, URL is secure and points to the official app domain, and there are no demands for credentials.",
        "tips": "Marketing emails from real brands rarely use high-pressure tactics."
    },
    {
        "id": 23,
        "sender_name": "McAfee Antivirus",
        "sender_email": "alerts@mcafee-protection-status.com",
        "subject": "WARNING: PC is Infected (5 Viruses)",
        "body_top": "<h2 style='color: red;'>CRITICAL SYSTEM ALERT</h2><br>Your subscription has expired, and your PC has contracted 5 Trojans!",
        "link_text": "Renew Now (50% Off)",
        "real_link": "http://fake-antivirus-renewal.com/pay",
        "body_bottom": "Click below to instantly renew your protection and clean your PC before data loss occurs.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link", "zone-body"],
        "explanation": "Fake Antivirus scams use extreme fear to make you pay for useless software. Genuine antivirus software alerts you via desktop pop-ups, not emails.",
        "tips": "Never buy security software from an alarming email. Open your Antivirus app directly."
    },
    {
        "id": 24,
        "sender_name": "HR Layoffs",
        "sender_email": "hr-admin@mycompany-updates.com",
        "subject": "CONFIDENTIAL: Upcoming Restructuring",
        "body_top": "Please review the attached list of departments impacted by the upcoming Q4 restructuring and layoffs.",
        "link_text": "Download Q4_Impact_List.xlsx",
        "real_link": "http://malware-server.com/Layoff_List.xlsx",
        "body_bottom": "Keep this strictly confidential.",
        "type": "phishing",
        "critical_zones": ["zone-sender", "zone-link"],
        "explanation": "Attackers use highly emotional topics (layoffs, bonuses) so employees click the attachment without checking the URL or the slightly altered sender domain.",
        "tips": "High-emotion emails are designed to bypass your logical thinking. Always verify."
    },
    {
        "id": 25,
        "sender_name": "Apple Support",
        "sender_email": "appleid@id.apple.com",
        "subject": "Your receipt from Apple.",
        "body_top": "<strong>Receipt</strong><br>Billed To: Apple ID<br>Order ID: MZY22883<br>Item: iCloud+ 50GB Storage<br>Price: $0.99",
        "link_text": "Visit Apple Support",
        "real_link": "https://support.apple.com/billing",
        "body_bottom": "If you have any questions, click the link above.",
        "type": "safe",
        "critical_zones": [],
        "explanation": "This is a legitimate receipt. The domain is correct, the amounts are normal, and the support link securely directs to the official Apple domain.",
        "tips": "Real receipts don't ask for your password to view them."
    }
]

# --- QUIZ DATABASE ---
FULL_QUIZ_DB = [
    {"q": "What is the most secure way to protect your WhatsApp?", "options": ["Hide profile pic", "Enable 2FA (PIN)", "Block unknowns", "Delete app"], "answer": "Enable 2FA (PIN)"},
    {"q": "You receive a message: 'You won a lottery! Click here.' This is:", "options": ["A lucky day", "Phishing/Smishing", "A system error", "Real"], "answer": "Phishing/Smishing"},
    {"q": "What does the 'S' in HTTPS stand for?", "options": ["Super", "Secure", "System", "Standard"], "answer": "Secure"},
    {"q": "A hacker locks your files and demands money. This is:", "options": ["Spyware", "Adware", "Ransomware", "Malware"], "answer": "Ransomware"},
    {"q": "Which password is the strongest?", "options": ["Password123", "Monkey2024", "Tr!n3tr@_Secur3$", "JohnDoe"], "answer": "Tr!n3tr@_Secur3$"},
    {"q": "Public Wi-Fi (e.g., at a cafe) is:", "options": ["Safe", "Insecure", "Faster", "Private"], "answer": "Insecure"},
    {"q": "A friend sends a weird link on Instagram. You should:", "options": ["Click it", "Verify with them first", "Share it", "Like it"], "answer": "Verify with them first"},
    {"q": "What is 2FA?", "options": ["Two passwords", "Password + Code/Token", "Biometrics only", "Sharing accounts"], "answer": "Password + Code/Token"},
    {"q": "Before selling an old phone, you must:", "options": ["Delete photos", "Factory Reset", "Remove SIM", "Nothing"], "answer": "Factory Reset"},
    {"q": "If you suspect malware, first step:", "options": ["Disconnect Internet", "Email Hacker", "Restart PC", "Wait"], "answer": "Disconnect Internet"},
    {"q": "What is 'Shoulder Surfing'?", "options": ["Surfing online", "Looking at someone's screen", "Hacking Wi-Fi", "Phishing"], "answer": "Looking at someone's screen"},
    {"q": "A VPN protects you by:", "options": ["Making internet faster", "Encrypting your traffic", "Blocking ads", "Stopping viruses"], "answer": "Encrypting your traffic"},
    {"q": "What is 'Social Engineering'?", "options": ["Building social apps", "Manipulating people", "Hacking servers", "Coding"], "answer": "Manipulating people"},
    {"q": "Incognito Mode makes you invisible to:", "options": ["The Internet Provider", "Hackers", "Your Browser History", "The Government"], "answer": "Your Browser History"},
    {"q": "Why should you update software?", "options": ["To get new icons", "To patch security holes", "To slow down PC", "No reason"], "answer": "To patch security holes"},
    {"q": "What is a 'Firewall'?", "options": ["A physical wall", "Network security system", "Antivirus software", "A virus"], "answer": "Network security system"},
    {"q": "Someone calls pretending to be your bank asking for OTP. You:", "options": ["Give it", "Hang up", "Ask for name", "Email them"], "answer": "Hang up"},
    {"q": "Is it safe to use the same password everywhere?", "options": ["Yes", "No", "Only for social media", "Maybe"], "answer": "No"},
    {"q": "What is a 'Keylogger'?", "options": ["A lock", "Software that records typing", "A password manager", "An admin"], "answer": "Software that records typing"},
    {"q": "Clicking 'Unsubscribe' in a spam email can:", "options": ["Stop spam", "Confirm your email is active", "Delete account", "Block sender"], "answer": "Confirm your email is active"}
]

# --- ROUTES ---

@app.route('/')
def home():
    return render_template('dashboard.html')

@app.route('/inbox')
def inbox():
    return render_template('inbox.html', emails=EMAILS)

# EVIDENCE ANALYSIS ENGINE
@app.route('/analyze_evidence', methods=['POST'])
def analyze_evidence():
    data = request.json
    email_id = int(data.get('email_id'))
    selected_zones = data.get('selected_zones') 
    user_verdict = data.get('verdict') 
    
    email = next(e for e in EMAILS if e["id"] == email_id)
    
    verdict_correct = (user_verdict == email['type'])
    correct_zones = email['critical_zones']
    evidence_correct = False
    
    if len(selected_zones) > 0:
        if email['type'] == 'safe':
            evidence_correct = True
        else:
            evidence_correct = any(zone in correct_zones for zone in selected_zones)
    elif email['type'] == 'safe' and verdict_correct:
        evidence_correct = True
    
    success = False
    title = ""
    msg = ""
    
    if verdict_correct and evidence_correct:
        success = True
        title = "EXCELLENT WORK!"
        msg = f"You correctly identified this as {user_verdict.upper()} and found the key indicators."
    elif verdict_correct and not evidence_correct:
        success = True
        title = "LUCKY GUESS?"
        if email['type'] == 'safe':
             msg = f"You were right that it's safe, but you didn't click the validation points (Sender/Link)."
        else:
             msg = f"You got the verdict right ({user_verdict}), but you didn't click the correct evidence zones."
    else:
        success = False
        title = "INCORRECT ANALYSIS"
        msg = f"This email was actually {email['type'].upper()}. Review the indicators below."

    return jsonify({
        "success": success,
        "title": title,
        "msg": msg,
        "explanation": email['explanation'],
        "tips": email['tips'],
        "correct_zones": email['critical_zones'] 
    })

@app.route('/scan', methods=['GET', 'POST'])
def scan_file():
    result = None
    if request.method == 'POST':
        if 'file' not in request.files: return "No file"
        file = request.files['file']
        if file.filename == '': return "No selected file"
            
        sha256 = hashlib.sha256()
        for chunk in iter(lambda: file.read(4096), b""):
            sha256.update(chunk)
        file_hash = sha256.hexdigest()
        
        if file_hash in LOCAL_MALWARE_DB:
            result = {"status": "local_found", "hash": file_hash, "source": "INTERNAL DATABASE", "malware_name": LOCAL_MALWARE_DB[file_hash], "msg": "CRITICAL THREAT DETECTED BY LOCAL SIGNATURE."}
        else:
            try:
                url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
                headers = {"x-apikey": VT_API_KEY}
                response = requests.get(url, headers=headers)
                
                if response.status_code == 200:
                    data = response.json()['data']['attributes']['last_analysis_stats']
                    result = {"stats": data, "hash": file_hash, "status": "api_found", "source": "VIRUSTOTAL CLOUD"}
                elif response.status_code == 404:
                    result = {"status": "clean", "msg": "File not found in Local or Cloud DB (Likely Safe).", "hash": file_hash}
                else:
                    result = {"status": "error", "msg": f"API Error: {response.status_code}"}
            except Exception as e:
                result = {"status": "error", "msg": "Local Scan Clean. Could not connect to Cloud API."}
            
    return render_template('scan.html', result=result)

@app.route('/password', methods=['GET', 'POST'])
def password_check():
    audit = None
    if request.method == 'POST':
        pwd = request.form['password']
        try:
            # 1. Calculate Entropy
            stats = zxcvbn(pwd)
            
            # 2. SHA-1 Hashing for k-Anonymity API
            sha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest().upper()
            prefix, suffix = sha1[:5], sha1[5:]
            
            # 3. Safe API Request with Timeout and User-Agent
            headers = {'User-Agent': 'CyberNetram-Project-Dev'}
            res = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", headers=headers, timeout=5)
            
            leaked_count = 0
            if res.status_code == 200:
                for line in res.text.splitlines():
                    h, count = line.split(':')
                    if h == suffix:
                        leaked_count = int(count)
                        break
            
            audit = {
                "score": stats['score'], 
                "crack_time": stats['crack_times_display'].get('offline_slow_hashing_1e4_per_second', 'Unknown'), 
                "leaks": leaked_count, 
                "feedback": stats['feedback']['suggestions']
            }
            
        except requests.exceptions.RequestException:
            # If the internet is down or API blocks the request
            audit = {
                "score": stats['score'] if 'stats' in locals() else 0,
                "crack_time": "Offline Mode",
                "leaks": 0,
                "feedback": ["Could not connect to Breach Database. Entropy calculated locally."]
            }
        except Exception as e:
            # Catch any other crashes
            print(f"Password Error: {e}")
            audit = {
                "score": 0, "crack_time": "Error", "leaks": 0, 
                "feedback": ["An internal error occurred while processing the password."]
            }

    return render_template('password.html', audit=audit)

@app.route('/learn')
def learn():
    return render_template('learn.html')

# --- QUIZ ROUTE (UPDATED) ---
@app.route('/quiz')
def quiz():
    # Randomly select 10 questions from the full database each time
    daily_questions = random.sample(FULL_QUIZ_DB, 10)
    return render_template('quiz.html', questions=daily_questions)

if __name__ == '__main__':
    app.run(debug=True)