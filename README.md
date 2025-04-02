Password Strength Analyzer with AI
An intelligent tool that evaluates password security beyond basic metrics, using ML and GenAI to predict vulnerability and suggest robust alternatives.

🔍 Overview
Traditional password checkers focus only on length and special characters. Our tool:

Predicts time-to-crack using brute force/dictionary/hybrid attacks

Flags patterns (dates, keyboard walks, leet speak)

Generates AI-powered suggestions (e.g., "Summer2024" → "5uMM3r#2024*Q")

Cross-references 10M+ breached passwords (RockYou dataset)

Built for developers, enterprises, and security-conscious users.

🚀 Features
Feature	Description
Entropy Analysis	Calculates bits of entropy to measure unpredictability
Crack-Time Estimation	Estimates time-to-crack for common attack methods
AI Suggestions	GPT-2 powered improvements with explanations
Pattern Detection	Identifies weak structures (e.g., "2024", "qwerty")
API Ready	Flask backend for easy integration
⚙️ Tech Stack
Backend: Python, Flask

ML/GenAI: Scikit-learn, Transformers (GPT-2), NearestNeighbors

Data: RockYou dataset, TF-IDF vectorization

Frontend: HTML/CSS/JS (Minimalist Flask-rendered UI)

🛠️ Installation
Prerequisites
Python 3.8+

Git

Steps
Clone the repo:

bash
Copy
git clone https://github.com/yourusername/password-analyzer.git  
cd password-analyzer  
Install dependencies:

bash
Copy
pip install Flask scikit-learn transformers numpy pandas joblib python-dateutil   
Download the RockYou dataset (place in data/rockyou.txt).
https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

Run the app:

bash
Copy
python app.py
Open http://localhost:8000 in your browser.

📂 Project Structure
password-analyzer/  
├── app.py                  # Flask web server  
├── password_analyzer.py    # Core analysis logic  
├── models/                 # Trained ML models  
│   ├── nn_model.joblib     # Similarity model  
│   └── vectorizer.joblib   # TF-IDF vectorizer  
🤖 How It Works
Input: User submits a password via web UI or API.

Analysis:

Checks against common passwords

Calculates entropy and patterns

Estimates crack time

Output: Returns strength score, vulnerabilities, and AI suggestions.

Architecture Diagram

📊 Performance Metrics
Password	Entropy (bits)	Time-to-Crack	Strength Score
password123	18	<1 second	10
Xq2$9z!L	68	5 years	95
🌐 API Usage
bash
Copy
POST /analyze  
Body: {"password": "Summer2024"}  

Response:  
{  
  "strength_score": 45,  
  "time_to_crack": "3 hours (dictionary attack)",  
  "suggestions": ["5uMM3r#2024*Q", "Summer!Tide$2024"],  
  "vulnerabilities": ["Common phrase", "Low entropy (28 bits)"]  
}  
📜 License
MIT License - See LICENSE.

Acknowledgments
RockYou dataset for breached passwords

Hugging Face for GPT-2 model

Flask community

🔗 Links
