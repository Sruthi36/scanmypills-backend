📌 ScanMyPills Backend
🚀 Project Overview
ScanMyPills Backend is a Flask-based REST API that powers the ScanMyPills mobile application. It enables users to manage medicines, identify tablets, and receive timely reminders through a secure and efficient backend system.

The system integrates AI-based features like OCR for extracting medicine details and supports complete medicine lifecycle management including storage, tracking, and notifications.

🎯 Features
🔐 User Authentication & Authorization
Secure login and registration using JWT-based authentication.

💊 Medicine Management
Add, update, delete, and view medicine details including expiry, dosage, and manufacturer.

🔍 Medicine Identification
Identify medicines using stored data and assist in recognizing loose tablets.

🧠 OCR-Based Extraction
Extract medicine details such as name and expiry date from package images using Tesseract OCR.

⏰ Reminder & Notification System
Schedule dosage reminders and receive alerts for medicine intake and expiry.

🖼️ Image Upload & Storage
Upload and manage medicine images securely.

🛠️ Tech Stack
Backend Framework: Flask (Python)

Database: MySQL

Authentication: JWT (JSON Web Tokens)

Image Processing: OpenCV

OCR: Tesseract

Mail Service: Flask-Mail

Environment Management: python-dotenv

📂 Project Structure
scanmypillsBackend/
│
├── app.py                # Main application file
├── requirements.txt     # Python dependencies
├── setup_db.sql         # Database schema
├── .gitignore           # Ignored files
├── .env                 # Environment variables (not pushed)
│
├── uploads/             # Uploaded images (ignored)
├── venv/                # Virtual environment (ignored)
⚙️ Setup Instructions
1️⃣ Clone the Repository
git clone https://github.com/your-username/scanmypills-backend.git
cd scanmypills-backend
2️⃣ Create Virtual Environment
python -m venv venv
venv\Scripts\activate
3️⃣ Install Dependencies
pip install -r requirements.txt
4️⃣ Setup Environment Variables
Create a .env file and add:

SECRET_KEY=your_secret_key
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
DB_HOST=localhost
DB_USER=root
DB_PASSWORD=
DB_NAME=scanmypills
5️⃣ Install Tesseract OCR
Download and install from:
https://github.com/tesseract-ocr/tesseract

Then add path in code (if required):

pytesseract.pytesseract.tesseract_cmd = r'C:\Program Files\Tesseract-OCR\tesseract.exe'
6️⃣ Run the Application
python app.py
🔐 Security Practices
Sensitive data is stored in .env and not pushed to GitHub

Passwords are securely hashed

JWT tokens are used for protected routes

File uploads are validated and secured

🧪 Testing
Authentication APIs tested for login/register flows

Medicine CRUD operations verified

OCR extraction tested with real medicine strips

Reminder scheduling tested for accuracy

📈 Future Enhancements
AI-based image recognition for loose tablet identification

Cloud deployment (Render / AWS)

Push notifications for reminders

Multi-user family medicine tracking

👩‍💻 Author
Mannuru Sruthi
ScanMyPills Project
