# Attendance Logger - Capstone Project

## 📌 Overview

Attendance Logger is a web-based application built using Flask that allows teachers or administrators to:

- Register and manage student details
- Mark daily attendance by semester
- View and download attendance reports
- Securely handle user login and password recovery via OTP

This project serves as a full-stack **capstone project** demonstrating backend logic, frontend forms, database design, and secure user management.

---

## 🧠 Features

- 🔐 User registration and login
- 🧾 Student registration with full academic & personal info
- 📅 Attendance marking with logic to avoid duplicate marking
- 📊 Attendance dashboard showing present/today stats
- 📁 Attendance reports (filter by roll number, name, date, semester)
- 📄 PDF export for attendance data
- 🔑 Forgot password + OTP email verification system
- 🌓 Dark-mode-inspired UI with Bootstrap styling

---

## ⚙️ Tech Stack

- **Backend**: Flask, SQLAlchemy, Flask-Mail, FPDF
- **Database**: SQLite
- **Frontend**: HTML5, CSS3, Bootstrap, Jinja2
- **Others**: Gmail SMTP (for OTPs), bcrypt (for password hashing)

---

## 🚀 Setup Instructions

1. **Clone the repo**
   ```bash
   git clone https://github.com/byteephantom/Capstone-Project-Web.git
   cd Capstone-Project-Web
2. **Create a virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # For Windows: venv\Scripts\activate
3. **Install required libraries**
   ```bash
   pip install -r requirements.txt
4. **Configure environment variables (if needed)**
   - Replace the hardcoded Gmail credentials in app.py with environment variables for better security.
5. **Run the app**
   ```bash
   python app.py


## Screenshots
<img width="1887" height="1019" alt="image" src="https://github.com/user-attachments/assets/f792cbaa-f54b-4404-8351-bad1d29af435" />
<img width="1905" height="986" alt="Screenshot 2025-06-23 203139" src="https://github.com/user-attachments/assets/7e459149-60a1-4c54-bebb-67315ea33b3a" />
<img width="1793" height="929" alt="Screenshot 2025-06-25 074723" src="https://github.com/user-attachments/assets/8c4618f3-679a-48cc-9af0-c3e6f1e8ac92" />
<img width="1870" height="1020" alt="image" src="https://github.com/user-attachments/assets/60708d2c-8b22-4ac6-9ea0-7374b548bd70" />

## 📬 Contact
- Made by Ayush Kumar and Ayush Kumar (https://github.com/strongayush) — feel free to connect or raise issues.

## 📜 LICENSE
---- This project is part of a capstone submission and is not licensed for production use.
