# PhishLens

AI-Assisted Phishing Investigation & Threat Analysis Platform

---

## Overview

PhishLens is a SOC-oriented phishing investigation platform designed to analyze suspicious email files and generate analyst-style investigation reports.

The platform combines:
- phishing detection
- email header analysis
- IOC extraction
- URL reputation analysis
- psychological phishing intent analysis
- threat scoring
- investigation history tracking

---

## Features

### Email Analysis
- Parses real `.eml` email files
- Extracts sender, receiver, and subject
- Reads and analyzes email body content

### Threat Detection
- Phishing keyword detection
- Suspicious URL detection
- URL reputation analysis
- Suspicious domain detection

### Header Analysis
- SPF failure detection
- Reply-To mismatch detection
- Return-Path anomaly detection
- Suspicious sender pattern analysis

### AI Behavioral Analysis
- Urgency manipulation detection
- Credential harvesting analysis
- Fear-based pressure detection
- Authority impersonation detection

### IOC Extraction
- Extracts domains
- Extracts URLs
- Extracts email addresses

### Investigation Workflow
- Analyst-style phishing reports
- Investigation history storage
- Threat classification
- Confidence scoring
- Recommended response actions
- Report export support

---

## Screenshots

Add your project screenshots here.

Example:
- Dashboard UI
- Investigation Report
- Investigation History

---

## Tech Stack

### Frontend
- HTML
- CSS
- JavaScript

### Backend
- Python
- FastAPI

---

## Project Structure

```text
PhishLens/
│
├── backend/
│   ├── storage/
│   ├── main.py
│   └── requirements.txt
│
├── frontend/
│   ├── css/
│   ├── js/
│   ├── index.html
│   └── phishing_test.eml
│
└── README.md
```

---

## Run Backend

```bash
cd backend
uvicorn main:app --reload
```

---

## Run Frontend

```bash
cd frontend
python -m http.server 5500
```

---

## Access Frontend

```text
http://127.0.0.1:5500
```

---

## Future Improvements

- VirusTotal integration
- NLP-based phishing analysis
- Database integration
- Authentication system
- Docker deployment
- SIEM integrations
- Cloud deployment

---

## Author

Bhaviya Talwar
