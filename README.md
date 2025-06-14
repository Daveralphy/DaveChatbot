# Dave Chatbot: Your Personalized AI Assistant

Dave Chatbot is a Python-based web application built with Flask, designed to provide a personalized chat experience. It integrates with the Gemini AI model for conversational capabilities and uses AWS DynamoDB for user management and chat history persistence, while loading its persona from AWS S3. This README covers setting up the application for local development and deploying it to an AWS EC2 instance with Nginx and Let's Encrypt for a secure, production-ready environment.

---

## 🚀 Features
- Interactive Chat Interface: A clean web-based interface for conversing with the AI.
- User Authentication: Secure registration and login functionalities leveraging AWS DynamoDB.
- Persistent Chat History: Maintains conversation context for logged-in users, stored in AWS DynamoDB.
- Persona Customization: The chatbot's personality is loaded dynamically from a persona.json file stored in AWS S3.
- Gemini AI Integration: Utilizes Google's Gemini 1.5 Flash model for natural language understanding and generation.
- Secure Deployment: Deployed on AWS EC2 with Nginx as a reverse proxy and HTTPS via Let's Encrypt.
- Persistent Service: Runs as a systemd service, ensuring continuous operation even after SSH disconnects or server reboots.

---

## 📁 Project Structure
- DaveChatbot
  - app.py - The main Flask application file, handling routes, API calls, and business logic.
  - templates/ - Contains Jinja2 HTML templates for the web interface (e.g., index.html, profile.html).
    - index.html - The main chat interface page, with User profile display, settings page and Information about the chatbot
  - static/ - Stores static assets like CSS stylesheets and JavaScript files.
    - style.css - The primary stylesheet for the application's design.
  - persona.json - Defines the chatbot's initial personality and conversational style.
  - requirements.txt - Lists all Python package dependencies required for the project.
  - README.md - This documentation file.

---

## Setup Instructions
1. Clone the repository:
`git clone https://github.com/Daveralphy/DaveChatbot.git`
2. Navigate to the project directory:
`cd DaveChatbot`
3. Create and activate a virtual environment:
`python3 -m venv venv`
`source venv/bin/activate` - On Windows: `venv\Scripts\activate`
4. Install dependencies:
`pip install -r requirements.txt`
5. Create and configure your .env file:
In the root directory of the project, create a new file named .env (note the leading dot).
6. Paste the following into your .env file:
```
FLASK_SECRET_KEY="YOUR_UNIQUE_FLASK_SECRET_KEY_HERE"
GEMINI_API_KEY="YOUR_GEMINI_API_KEY_HERE"
S3_BUCKET_NAME="YOUR_S3_BUCKET_NAME"
USERS_TABLE_NAME="YOUR_USERS_TABLE_NAME"
CHAT_HISTORY_TABLE_NAME="YOUR_CHAT_HISTORY_TABLE_NAME"
```
  - FLASK_SECRET_KEY: Generate a strong, random string (e.g., using python3 -c 'import os; print(os.urandom(24).hex())').
  - GEMINI_API_KEY: Obtain this from the Google AI Studio.
  - S3_BUCKET_NAME: The name of your S3 bucket where persona.json is stored.
  - USERS_TABLE_NAME: The name of your DynamoDB table for user data.
  - CHAT_HISTORY_TABLE_NAME: The name of your DynamoDB table for chat history.
Important: Keep your .env file secure and do not share it or commit it to version control.
7. Prepare persona.json: Ensure you have a persona.json file in your project root containing the initial persona data for the chatbot.
  - Example persona.json content (this file should also be uploaded to your S3 bucket under the key persona.json):
```
[
  {
    "role": "user",
    "parts": ["Introduce yourself."]
  },
  {
    "role": "model",
    "parts": ["Hello! I am Dave, a friendly AI assistant created by Raphael Daveal. I'm here to chat and help you with any questions you might have."]
  }
]
```
---

## Usage (Local Development)
To run the application locally for development and testing: `python3 app.py`

Access your local app in your browser at http://127.0.0.1:5000.

## 🚀 Deployment to AWS EC2 (Production)
This section details the steps to deploy your Dave Chatbot application to an AWS EC2 instance, configuring it to run persistently and securely with HTTPS.

### Architecture Overview
1. EC2 Instance: A virtual server hosting the application.
2. Gunicorn: A WSGI HTTP server that runs the Flask application.
3. Systemd: Manages the Gunicorn process, ensuring it runs persistently and restarts automatically.
4. Nginx: A high-performance web server acting as a reverse proxy, handling incoming HTTP/HTTPS requests, serving static files directly, and forwarding dynamic requests to Gunicorn via a Unix socket.
5. Let's Encrypt (Certbot): Provides free SSL/TLS certificates for HTTPS encryption.
6. Security Groups: AWS firewall rules controlling network traffic to the EC2 instance.
7. IAM Role: Provides the EC2 instance with secure permissions to access AWS S3 and DynamoDB.

### Deployment Steps
1. EC2 Instance Setup (Initial)
  - Launch EC2 Instance: Launch an Ubuntu Server AMI (e.g., Ubuntu Server 22.04 LTS) in your preferred AWS Region (e.g., eu-north-1).
  - Key Pair: Create or select an existing .pem key pair (e.g., DaveBot.pem). Keep its private key secure and set permissions to chmod 400 DaveBot.pem locally.
  - Security Group: Create a security group (e.g., dave-chatbot-sg) with inbound rules for:
  - SSH (Port 22): My IP or Anywhere IPv4 (for initial setup, restrict later).
  - HTTP (Port 80): Anywhere IPv4 (0.0.0.0/0)
  - HTTPS (Port 443): Anywhere IPv4 (0.0.0.0/0)
  - Custom TCP (Port 8000): Anywhere IPv4 (0.0.0.0/0) - This was for initial testing, and can be removed from the security group after HTTPS is configured.
2. Connect to EC2 Instance
Open your WSL/Linux terminal and connect using SSH: `ssh -i "~/.ssh/your_key.pem" username@YOUR_EC2_PUBLIC_IPV4_ADDRESS`
Replace YOUR_EC2_PUBLIC_IPV4_ADDRESS with your EC2 instance's public IP (e.g., 16.171.160.202).
3. Install Server Software
Once connected to your EC2 instance:
`sudo apt update -y`
`sudo apt upgrade -y`
`sudo apt install -y python3-pip python3-venv git nginx`
4. Clone Your Application
`cd ~`
`git clone YOUR_GITHUB_REPOSITORY_URL_HERE`
`cd DaveChatbot`
5. Set Up Python Environment & Dependencies on EC2
`python3 -m venv venv`
`source venv/bin/activate`
`pip install -r requirements.txt`
`pip install gunicorn` # Ensure gunicorn is in venv, even if in requirements.txt
6. Create .env File on EC2
Since your local .env is not in Git, you need to recreate it directly on the EC2 instance:
`nano .env`
Paste the same content as your local .env file, ensuring correct keys/names. Save and exit nano (Ctrl + X, Y, Enter).
7. Create and Attach IAM Role. Your EC2 instance needs permissions to interact with AWS services.
  - Create IAM Role:
    - Go to AWS Console > IAM > Roles > Create role.
    - Trusted entity: AWS service > EC2.
    - Permissions: Attach AmazonS3ReadOnlyAccess, AmazonDynamoDBFullAccess, CloudWatchLogsFullAccess.
    - Role name: DaveChatbotEC2Role (or similar).
    - Attach Role to EC2 Instance:
    - Go to AWS Console > EC2 > Instances.
    - Select your DaveBot instance.
    - Actions > Security > Modify IAM role.
    - Select DaveChatbotEC2Role and Save.
8. Configure Systemd for Gunicorn (Persistent Running)
  - Stop any running Gunicorn (if started manually):
`sudo pkill gunicorn`
  - Create the systemd service file:
`sudo nano /etc/systemd/system/davechatbot.service`
  - Paste the following content:
```
[Unit]
Description=Gunicorn instance for Dave Chatbot
After=network.target

[Service]
User=ubuntu
Group=www-data
WorkingDirectory=/home/ubuntu/DaveChatbot
ExecStart=/home/ubuntu/DaveChatbot/venv/bin/gunicorn --workers 3 --bind unix:/home/ubuntu/DaveChatbot/davechatbot.sock app:app
Restart=always

[Install]
WantedBy=multi-user.target
```
Save and exit nano.

Reload systemd, enable, and start the service:
`sudo systemctl daemon-reload`
`sudo systemctl enable davechatbot`
`sudo systemctl start davechatbot`
`sudo systemctl status davechatbot` # Verify active (running)
9. Configure Nginx for Reverse Proxy & HTTPS
Create Nginx site configuration:
`sudo nano /etc/nginx/sites-available/davechatbot`
10. Paste the following. Important: Replace chatwithdave.ddns.net with your actual domain name.
```
server {
    listen 80;
    server_name chatwithdave.ddns.net;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl;
    server_name chatwithdave.ddns.net;

    # These paths will be created by Certbot later
    ssl_certificate /etc/letsencrypt/live/chatwithdave.ddns.net/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/chatwithdave.ddns.net/privkey.pem;

    # Include recommended SSL settings from Certbot
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    # Static files location
    location /static {
        alias /home/ubuntu/DaveChatbot/static/; # NOTE THE TRAILING SLASH
        expires 30d;
        add_header Cache-Control "public, no-transform";
    }

    # Proxy to Gunicorn via Unix socket
    location / {
        proxy_pass http://unix:/home/ubuntu/DaveChatbot/davechatbot.sock:/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        include proxy_params;
    }
}
```
Save and exit nano.
11. Enable the Nginx site and remove default:
`sudo ln -s /etc/nginx/sites-available/davechatbot /etc/nginx/sites-enabled/`
`sudo rm /etc/nginx/sites-enabled/default`
12. Set correct permissions for Nginx to access directories:
`sudo chmod o+x /home`
`sudo chmod o+x /home/ubuntu`
`sudo chmod -R 755 /home/ubuntu/DaveChatbot/` # Ensure Nginx user can read all files
13. Obtain SSL Certificate with Certbot:
`sudo certbot --nginx -d chatwithdave.ddns.net`
Follow the prompts (email, agree to ToS, EFF donation opt-in). Crucially, choose option 2 to redirect HTTP to HTTPS when prompted. Certbot automatically attempts to configure Nginx for SSL.
14. Test Nginx configuration and restart:
15. Final Access
Your Dave Chatbot should now be accessible and secure at:
https://chatwithdave.ddns.net or whichever DNS name you use.

## License
All copyright observed. This program should not be used without my permission or for any business purpose without first consulting the programmer at the WhatsApp number below.

## Contact
For questions or collaboration, please reach out via the GitHub repo or contact me on WhatsApp via wa.me/2347032580065
