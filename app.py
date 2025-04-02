from flask import Flask, request, jsonify, render_template_string
from password_analyzer import analyzer
import os
import logging

app = Flask(__name__)

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>AI Password Strength Analyzer</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
            line-height: 1.6;
        }
        .password-input {
            width: 100%;
            padding: 10px;
            font-size: 16px;
            margin-bottom: 10px;
        }
        .analyze-btn {
            background-color: #4CAF50;
            color: white;
            padding: 10px 15px;
            border: none;
            cursor: pointer;
            font-size: 16px;
        }
        .result-section {
            margin-top: 30px;
            border-top: 1px solid #ddd;
            padding-top: 20px;
        }
        .strength-meter {
            height: 20px;
            background-color: #f1f1f1;
            margin: 10px 0;
            border-radius: 5px;
            overflow: hidden;
        }
        .strength-bar {
            height: 100%;
            width: 0%;
            background-color: #4CAF50;
            transition: width 0.5s;
        }
        .vulnerability {
            color: #d32f2f;
            margin: 5px 0;
        }
        .suggestion {
            background-color: #e8f5e9;
            padding: 10px;
            border-radius: 5px;
            margin: 5px 0;
        }
        .metric {
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <h1>AI Password Strength Analyzer</h1>
    <p>Enter a password to analyze its strength and get AI-powered suggestions for improvement:</p>
    
    <input type="password" id="passwordInput" class="password-input" placeholder="Enter your password">
    <button onclick="analyzePassword()" class="analyze-btn">Analyze Password</button>
    
    <div id="results" class="result-section" style="display: none;">
        <h2>Analysis Results</h2>
        
        <div class="metric">
            <h3>Strength Score: <span id="strengthScore">0</span>/100</h3>
            <div class="strength-meter">
                <div id="strengthBar" class="strength-bar"></div>
            </div>
        </div>
        
        <div class="metric">
            <h3>Estimated Time to Crack</h3>
            <p id="timeToCrack">-</p>
        </div>
        
        <div class="metric">
            <h3>Password Metrics</h3>
            <p>Length: <span id="pwdLength">0</span> characters</p>
            <p>Contains uppercase: <span id="hasUpper">No</span></p>
            <p>Contains lowercase: <span id="hasLower">No</span></p>
            <p>Contains numbers: <span id="hasDigit">No</span></p>
            <p>Contains special characters: <span id="hasSpecial">No</span></p>
            <p>Entropy: <span id="entropy">0</span> bits</p>
        </div>
        
        <div class="metric">
            <h3>Detected Vulnerabilities</h3>
            <div id="vulnerabilities"></div>
        </div>
        
        <div class="metric">
            <h3>Detected Patterns</h3>
            <div id="patterns"></div>
        </div>
        
        <div class="metric">
            <h3>AI-Powered Suggestions</h3>
            <div id="suggestions"></div>
        </div>
    </div>
    
    <script>
        function analyzePassword() {
            const password = document.getElementById('passwordInput').value;
            if (!password) {
                alert('Please enter a password');
                return;
            }
            
            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password: password })
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                document.getElementById('results').style.display = 'block';
                
                // Update strength score
                document.getElementById('strengthScore').textContent = data.strength_score;
                document.getElementById('strengthBar').style.width = data.strength_score + '%';
                document.getElementById('strengthBar').style.backgroundColor = 
                    data.strength_score > 75 ? '#4CAF50' : 
                    data.strength_score > 50 ? '#FFC107' : '#F44336';
                
                // Update basic metrics
                document.getElementById('pwdLength').textContent = data.length;
                document.getElementById('hasUpper').textContent = data.has_upper ? 'Yes' : 'No';
                document.getElementById('hasLower').textContent = data.has_lower ? 'Yes' : 'No';
                document.getElementById('hasDigit').textContent = data.has_digit ? 'Yes' : 'No';
                document.getElementById('hasSpecial').textContent = data.has_special ? 'Yes' : 'No';
                document.getElementById('entropy').textContent = data.entropy;
                document.getElementById('timeToCrack').textContent = data.time_to_crack;
                
                // Update vulnerabilities
                const vulnContainer = document.getElementById('vulnerabilities');
                vulnContainer.innerHTML = data.vulnerabilities.length > 0 ? 
                    data.vulnerabilities.map(v => `<p class="vulnerability">⚠ ${v}</p>`).join('') : 
                    '<p>No significant vulnerabilities detected</p>';
                
                // Update patterns
                const patternsContainer = document.getElementById('patterns');
                patternsContainer.innerHTML = data.patterns.map(p => `<p>🔍 ${p}</p>`).join('');
                
                // Update suggestions
                const suggestionsContainer = document.getElementById('suggestions');
                suggestionsContainer.innerHTML = data.suggestions.map(s => 
                    `<div class="suggestion">💡 ${s}</div>`
                ).join('');
            })
            .catch(error => {
                console.error('Error:', error);
                alert('Error analyzing password: ' + error.message);
            });
        }
    </script>
</body>
</html>
"""

@app.route('/')
def home():
    logger.debug("Rendering password analyzer page")
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    logger.debug("Analyze endpoint hit")
    try:
        data = request.get_json()
        if not data or 'password' not in data:
            logger.warning("No password provided")
            return jsonify({'error': 'No password provided'}), 400
        
        password = data['password']
        logger.debug(f"Analyzing password (length: {len(password)})")
        
        analysis = analyzer.analyze_password(password)
        logger.debug(f"Analysis completed with score: {analysis.get('strength_score')}")
        
        if 'error' in analysis:
            logger.error(f"Analysis error: {analysis['error']}")
            return jsonify({'error': analysis['error']}), 400
        
        return jsonify({
            'strength_score': analysis.get('strength_score', 0),
            'length': analysis.get('length', 0),
            'has_upper': analysis.get('has_upper', False),
            'has_lower': analysis.get('has_lower', False),
            'has_digit': analysis.get('has_digit', False),
            'has_special': analysis.get('has_special', False),
            'entropy': analysis.get('entropy', 0),
            'is_common': analysis.get('is_common', False),
            'patterns': analysis.get('patterns', []),
            'similar_passwords': analysis.get('similar_passwords', []),
            'time_to_crack': analysis.get('time_to_crack', ''),
            'vulnerabilities': analysis.get('vulnerabilities', []),
            'suggestions': analysis.get('suggestions', []),
            'explanation': analysis.get('explanation', '')
        })
        
    except Exception as e:
        logger.exception("Unexpected error in analyze endpoint")
        return jsonify({'error': 'Internal server error', 'details': str(e)}), 500

if __name__ == '__main__':
    logger.info("Starting server on port 8000")
    app.run(debug=True, host='0.0.0.0', port=8000)