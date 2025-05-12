# VulnTrace

<div align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Flask-2.0+-red.svg" alt="Flask 2.0+">
  <img src="https://img.shields.io/badge/PostgreSQL-Required-blue.svg" alt="PostgreSQL">
</div>

<p align="center">
  <b>A modern web vulnerability scanner built with Python and Flask</b>
</p>

---

## 🔍 Features

- **Comprehensive Vulnerability Detection**: Identifies SQL injections, XSS, CSRF, open redirects, and security header issues
- **Web Crawler**: Automatically discovers and scans URLs across a target website
- **Detailed Reports**: Provides severity levels, impact descriptions, and remediation advice
- **Scan History**: Stores all scan results in a database for future reference
- **Interactive UI**: Modern interface with real-time scanning feedback
- **Low False Positive Rate**: Advanced detection algorithms minimize false positives

## 🖼️ Screenshots

(Insert screenshots here)

## 🚀 Installation

### Prerequisites

- Python 3.8 or higher
- PostgreSQL database

### Step 1: Clone the repository
```bash
git clone https://github.com/0xnull0/vulntrace.git
cd vulntrace
```

### Step 2: Set up a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

### Step 3: Install dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Set up the database
1. Create a PostgreSQL database for VulnTrace
2. Set the environment variable for your database connection:
```bash
export DATABASE_URL=postgresql://username:password@localhost:5432/vulntrace
```

### Step 5: Run the application
```bash
gunicorn --bind 0.0.0.0:5000 main:app
```

### Step 6: Access the application
Open your browser and navigate to `http://localhost:5000`

## 📚 Usage

1. Enter the target URL in the scan form
2. Select the scan type (basic or full)
3. Adjust depth and timeout parameters if needed
4. Click "Start Scan" and wait for the results
5. Review the detailed vulnerability report
6. Access scan history to compare with previous results

## 🛠️ Technologies Used

- **Backend**: Python, Flask, SQLAlchemy
- **Frontend**: Bootstrap, JavaScript, CSS
- **Database**: PostgreSQL
- **Web Parsing**: BeautifulSoup4
- **Networking**: Requests

## ⚠️ Disclaimer

VulnTrace is designed for security professionals and ethical hackers. Only use this tool on systems you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👨‍💻 Creator

Created by [0xnull0](https://github.com/0xnull0)

## 📊 Development Roadmap

- [ ] Add API endpoints for integration with other tools
- [ ] Implement scheduled scans
- [ ] Add authentication for multi-user support
- [ ] Create PDF export for reports
- [ ] Add more vulnerability checks
