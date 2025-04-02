import numpy as np
import re
import pandas as pd
import math
import hashlib
import joblib
from pathlib import Path
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from transformers import pipeline as hf_pipeline
from collections import Counter
import warnings
import logging
from datetime import datetime

warnings.filterwarnings('ignore')

class AdvancedPasswordAnalyzer:
    def __init__(self, dataset_path=r'C:\Users\Skandesh Maadhav\Desktop\password-analyzer\rockyou.txt\rockyou.txt', model_save_path=r'C:\Users\Skandesh Maadhav\Desktop\password-analyzer\passw\models', device="cpu"):
        # Initialize logging
        logging.basicConfig(
            filename='password_analyzer.log',
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        self.dataset_path = dataset_path
        self.model_save_path = model_save_path
        Path(self.model_save_path).mkdir(parents=True, exist_ok=True)
        
        # Initialize components
        self.common_passwords = set()
        self.nn_model = None
        self.strength_model = None
        self.vectorizer = None
        self.sample_passwords = []
        
        # LLM components (initialized lazily when needed)
        self.llm_generator = None
        self.llm_initialized = False
        
        # Load or prepare models
        self._prepare_models()

    def _init_llm(self):
        """Initialize LLM components only when needed"""
        if not self.llm_initialized:
            try:
                self.llm_generator = hf_pipeline(
                    "text-generation",
                    model="gpt2",
                    device=-1  # Use CPU
                )
                self.llm_initialized = True
                self.logger.info("LLM components initialized successfully")
            except Exception as e:
                self.logger.error(f"Failed to initialize LLM components: {str(e)}")
                self.llm_generator = None
                self.llm_initialized = False

    def _prepare_models(self):
        """Load or train all necessary models"""
        try:
            self._load_models()
            self.logger.info("Models loaded successfully")
        except Exception as e:
            self.logger.warning(f"Failed to load models: {str(e)}. Training new models.")
            self._train_models()
    
    def _load_models(self):
        """Load pre-trained models from disk"""
        self.vectorizer = joblib.load(f'{self.model_save_path}/vectorizer.joblib')
        self.nn_model = joblib.load(f'{self.model_save_path}/nn_model.joblib')
        self.strength_model = joblib.load(f'{self.model_save_path}/strength_model.joblib')
        self.common_passwords = joblib.load(f'{self.model_save_path}/common_passwords.joblib')
        self.sample_passwords = list(self.common_passwords)[:10000]
    
    def _train_models(self):
        """Train and save all models with enhanced features"""
        df = self._load_and_preprocess_data()
        self._train_similarity_model(df)
        self._train_strength_classifier(df)
        self._save_models()
        self.sample_passwords = list(self.common_passwords)[:10000]
    
    def _load_and_preprocess_data(self):
        """Load and preprocess the password dataset with basic validation"""
        try:
            with open(self.dataset_path, 'r', encoding='latin-1', errors='replace') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            if not passwords:
                raise ValueError("Dataset is empty")
                
            # Filter passwords by basic complexity
            passwords = [pwd for pwd in passwords if 4 <= len(pwd) <= 64]
            
            password_counts = Counter(passwords)
            max_common = min(100000, len(password_counts) // 10)
            self.common_passwords = set(pwd for pwd, _ in password_counts.most_common(max_common))
            
            # Create balanced dataset
            weak_passwords = [pwd for pwd in passwords if pwd in self.common_passwords]
            strong_passwords = [pwd for pwd in passwords if pwd not in self.common_passwords]
            
            min_samples = min(len(weak_passwords), len(strong_passwords))
            df_weak = pd.DataFrame({'password': weak_passwords[:min_samples], 'strength': 0})
            df_strong = pd.DataFrame({'password': strong_passwords[:min_samples], 'strength': 1})
            
            return pd.concat([df_weak, df_strong]).sample(frac=1).reset_index(drop=True)
            
        except Exception as e:
            self.logger.error(f"Error loading dataset: {str(e)}")
            # Provide minimal fallback dataset
            return pd.DataFrame({
                'password': ['password', '123456', 'qwerty', 'StrongP@ssw0rd!2023'],
                'strength': [0, 0, 0, 1]
            })
    
    def _train_similarity_model(self, df):
        """Train the nearest neighbors model"""
        self.vectorizer = TfidfVectorizer(
            analyzer='char',
            ngram_range=(1, 3),
            min_df=0.001,
            max_df=0.5
        )
        
        sample_passwords = df['password'].sample(n=min(50000, len(df)))
        X = self.vectorizer.fit_transform(sample_passwords)
        
        self.nn_model = NearestNeighbors(
            n_neighbors=5,
            metric='cosine',
            algorithm='brute',
            n_jobs=-1
        )
        self.nn_model.fit(X)
    
    def _train_strength_classifier(self, df):
        """Train the password strength classifier"""
        # Feature engineering
        df['length'] = df['password'].apply(len)
        df['has_upper'] = df['password'].apply(lambda x: any(c.isupper() for c in x))
        df['has_lower'] = df['password'].apply(lambda x: any(c.islower() for c in x))
        df['has_digit'] = df['password'].apply(lambda x: any(c.isdigit() for c in x))
        df['has_special'] = df['password'].apply(lambda x: any(not c.isalnum() for c in x))
        df['entropy'] = df['password'].apply(self._calculate_entropy)
        
        # Train classifier
        feature_cols = ['length', 'has_upper', 'has_lower', 'has_digit', 'has_special', 'entropy']
        X = df[feature_cols]
        y = df['strength']
        
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y)
        
        self.strength_model = Pipeline([
            ('classifier', RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            ))
        ])
        
        self.strength_model.fit(X_train, y_train)
        
        # Log evaluation metrics
        train_score = self.strength_model.score(X_train, y_train)
        test_score = self.strength_model.score(X_test, y_test)
        self.logger.info(f"Model trained. Train accuracy: {train_score:.2f}, Test accuracy: {test_score:.2f}")
    
    def _save_models(self):
        """Save all trained models to disk"""
        joblib.dump(self.vectorizer, f'{self.model_save_path}/vectorizer.joblib')
        joblib.dump(self.nn_model, f'{self.model_save_path}/nn_model.joblib')
        joblib.dump(self.strength_model, f'{self.model_save_path}/strength_model.joblib')
        joblib.dump(self.common_passwords, f'{self.model_save_path}/common_passwords.joblib')
    
    def analyze_password(self, password):
        """Analyze a password with comprehensive error handling"""
        if not password:
            return {"error": "Password cannot be empty"}
        
        if len(password) > 128:
            return {"error": "Password too long (max 128 characters)"}
        
        try:
            # Basic analysis
            basic_metrics = self._basic_analysis(password)
            patterns = self._detect_patterns(password)
            
            # Get strength score
            features = [
                basic_metrics['length'],
                basic_metrics['has_upper'],
                basic_metrics['has_lower'],
                basic_metrics['has_digit'],
                basic_metrics['has_special'],
                basic_metrics['entropy']
            ]
            
            try:
                strength_prob = self.strength_model.predict_proba([features])[0][1]
                strength_score = int(strength_prob * 100)
            except Exception as e:
                self.logger.warning(f"Strength prediction failed: {str(e)}")
                strength_score = self._fallback_strength_score(password)
            
            # Similar passwords
            try:
                similar_passwords = self._find_similar_passwords(password)
            except Exception as e:
                self.logger.warning(f"Similar passwords failed: {str(e)}")
                similar_passwords = ["Error finding similar passwords"]
            
            # Time estimates
            try:
                time_to_crack = self._estimate_crack_time(password)
            except Exception as e:
                self.logger.warning(f"Time estimation failed: {str(e)}")
                time_to_crack = {"error": "Time estimation failed"}
            
            # Format time to crack as a simple string
            if isinstance(time_to_crack, dict):
                time_str = ", ".join([f"{k}: {v}" for k, v in time_to_crack.items()])
            else:
                time_str = str(time_to_crack)
            
            # Vulnerability analysis
            vulnerabilities = self._identify_vulnerabilities(
                password=password,
                is_common=basic_metrics['is_common'],
                patterns=patterns,
                similar_passwords=similar_passwords,
                length=basic_metrics['length'],
                entropy=basic_metrics['entropy']
            )
            
            # Generate suggestions (with LLM if available)
            suggestions = self._generate_suggestions(password, vulnerabilities)
            
            # Generate explanation (with LLM if available)
            explanation = self._generate_explanation(
                password=password,
                strength_score=strength_score,
                vulnerabilities=vulnerabilities
            )
            
            # Prepare final result
            return {
                "strength_score": strength_score,
                "length": basic_metrics['length'],
                "has_upper": basic_metrics['has_upper'],
                "has_lower": basic_metrics['has_lower'],
                "has_digit": basic_metrics['has_digit'],
                "has_special": basic_metrics['has_special'],
                "entropy": basic_metrics['entropy'],
                "is_common": basic_metrics['is_common'],
                "patterns": patterns,
                "similar_passwords": similar_passwords[:3],
                "time_to_crack": time_str,
                "vulnerabilities": vulnerabilities,
                "suggestions": suggestions[:3],
                "explanation": explanation
            }
            
        except Exception as e:
            self.logger.error(f"Error analyzing password: {str(e)}", exc_info=True)
            return {
                "error": "An error occurred during analysis",
                "details": str(e)
            }

    def _basic_analysis(self, password):
        """Perform basic password analysis"""
        return {
            'length': len(password),
            'has_upper': any(c.isupper() for c in password),
            'has_lower': any(c.islower() for c in password),
            'has_digit': any(c.isdigit() for c in password),
            'has_special': any(not c.isalnum() for c in password),
            'entropy': self._calculate_entropy(password),
            'is_common': password.lower() in self.common_passwords
        }
    
    def _calculate_entropy(self, password):
        """Calculate the entropy of a password in bits"""
        if not password:
            return 0
            
        char_set = 0
        if any(c.islower() for c in password):
            char_set += 26
        if any(c.isupper() for c in password):
            char_set += 26
        if any(c.isdigit() for c in password):
            char_set += 10
        if any(not c.isalnum() for c in password):
            char_set += 32
            
        entropy = len(password) * math.log2(char_set) if char_set > 0 else 0
        return round(entropy, 2)
    
    def _detect_patterns(self, password):
        """Detect common patterns in passwords"""
        patterns = []
        lower_pwd = password.lower()
        
        # Keyboard patterns
        keyboard_patterns = [
            'qwerty', 'asdfgh', 'zxcvbn', '123456', '654321',
            '1qaz2wsx', '1q2w3e4r', 'qazwsx', 'password', 'admin'
        ]
        for pattern in keyboard_patterns:
            if pattern in lower_pwd:
                patterns.append(f'Keyboard pattern: {pattern}')
        
        # Date patterns
        if re.search(r'\d{4}$', password):
            patterns.append('Ends with 4 digits (possible year)')
        
        # Common substitutions (leet speak)
        leet_subs = {
            'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
        }
        simple_leet = any(
            c in leet_subs and leet_subs[c] in lower_pwd
            for c in lower_pwd
        )
        if simple_leet:
            patterns.append('Simple leet speak substitutions')
        
        return patterns if patterns else ['No obvious patterns detected']
    
    def _find_similar_passwords(self, password):
        """Find similar passwords in the dataset"""
        if not self.vectorizer or not self.nn_model or not self.sample_passwords:
            return ['Similar password model not available']
            
        try:
            X = self.vectorizer.transform([password])
            distances, indices = self.nn_model.kneighbors(X)
            
            similar = []
            for i, dist in zip(indices[0], distances[0]):
                if dist < 0.7 and i < len(self.sample_passwords):
                    similar.append(self.sample_passwords[i])
            
            return similar[:3] if similar else ['No similar passwords found']
        except Exception as e:
            self.logger.warning(f"Error finding similar passwords: {str(e)}")
            return ['Error finding similar passwords']
    
    def _estimate_crack_time(self, password):
        """Estimate time required to crack the password"""
        entropy = self._calculate_entropy(password)
        
        if not password or entropy == 0:
            return {'bruteforce': 'instant', 'dictionary': 'instant', 'hybrid': 'instant'}
        
        # Base estimates
        estimates = {
            "bruteforce": self._calculate_bruteforce_time(entropy),
            "dictionary": self._calculate_dictionary_time(password),
            "hybrid": self._calculate_hybrid_time(password, entropy)
        }
        
        return estimates
    
    def _calculate_bruteforce_time(self, entropy):
        """Estimate bruteforce cracking time"""
        seconds = (2 ** entropy) / 1e9  # 1 billion guesses/sec
        return self._format_time(seconds)
    
    def _calculate_dictionary_time(self, password):
        """Estimate dictionary attack time"""
        if password.lower() in self.common_passwords:
            return "instant"
        return "minutes to hours" if len(password) < 10 else "hours to days"
    
    def _calculate_hybrid_time(self, password, entropy):
        """Estimate hybrid attack time"""
        base_time = self._calculate_dictionary_time(password)
        if base_time == "instant":
            return "instant"
        return self._format_time((2 ** (entropy * 0.5)) / 1e6)  # Reduced entropy for hybrid
    
    def _format_time(self, seconds):
        """Convert seconds to human-readable time"""
        if seconds < 1: return "less than a second"
        if seconds < 60: return f"{int(seconds)} seconds"
        if seconds < 3600: return f"{int(seconds/60)} minutes"
        if seconds < 86400: return f"{int(seconds/3600)} hours"
        if seconds < 31536000: return f"{int(seconds/86400)} days"
        return f"{int(seconds/31536000)} years"
    
    def _identify_vulnerabilities(self, password, is_common, patterns, similar_passwords, length, entropy):
        """Identify potential vulnerabilities in the password"""
        vulnerabilities = []
        
        if is_common:
            vulnerabilities.append("Password is in common password lists")
        
        if length < 8:
            vulnerabilities.append("Password is too short (less than 8 characters)")
        elif length < 12:
            vulnerabilities.append("Password could be longer (12+ characters recommended)")
        
        if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
            vulnerabilities.append("Password doesn't use mixed case")
        
        if not any(c.isdigit() for c in password):
            vulnerabilities.append("Password doesn't contain numbers")
        
        if not any(not c.isalnum() for c in password):
            vulnerabilities.append("Password doesn't contain special characters")
        
        if entropy < 30:
            vulnerabilities.append(f"Password entropy is low ({entropy} bits)")
        
        if patterns and 'No obvious patterns' not in patterns[0]:
            vulnerabilities.append(f"Password contains predictable patterns: {', '.join(patterns[:3])}")
        
        if similar_passwords and 'No similar passwords' not in similar_passwords[0]:
            if not similar_passwords[0].startswith('Error'):
                vulnerabilities.append(f"Password is similar to known weak passwords: {', '.join(similar_passwords[:3])}")
        
        return vulnerabilities if vulnerabilities else ["No obvious vulnerabilities detected"]
    
    def _generate_suggestions(self, password, vulnerabilities):
        """Generate password improvement suggestions with optional LLM enhancement"""
        # First generate basic suggestions
        suggestions = self._generate_basic_suggestions(password, vulnerabilities)
        
        # Try to enhance with LLM if available
        if len(suggestions) < 3:
            try:
                self._init_llm()
                if self.llm_generator:
                    llm_suggestions = self._generate_llm_suggestions(password, vulnerabilities)
                    suggestions.extend(s for s in llm_suggestions if s not in suggestions)
            except Exception as e:
                self.logger.warning(f"LLM suggestion generation failed: {str(e)}")
        
        # Ensure we have at least 3 suggestions
        while len(suggestions) < 3:
            suggestions.append(self._get_fallback_suggestion())
        
        return suggestions[:3]

    def _generate_basic_suggestions(self, password, vulnerabilities):
        """Generate basic pattern-based suggestions"""
        suggestions = []
        
        # Length suggestions
        if any("short" in v.lower() or "longer" in v.lower() for v in vulnerabilities):
            suggestions.append(f"Increase length to 12+ characters: {password + 'XyZ!123'}")
        
        # Special character suggestions
        if any("special" in v.lower() for v in vulnerabilities):
            modified = password[:4] + '@' + password[4:-2] + '#' + password[-2:]
            suggestions.append(f"Add special characters: {modified}")
        
        # Leet speak suggestions
        leet_map = {'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'}
        leet_pwd = ''.join(leet_map.get(c.lower(), c) for c in password)
        if leet_pwd != password:
            suggestions.append(f"Use leet speak substitutions: {leet_pwd}")
        
        return suggestions

    def _generate_llm_suggestions(self, password, vulnerabilities):
        """Generate LLM-powered password improvement suggestions"""
        if not self.llm_generator:
            return []
        
        prompt = f"""Generate 3 strong password suggestions based on these weaknesses:
Password: {password}
Weaknesses: {', '.join(vulnerabilities)}
Suggestions:
1. """
        
        try:
            response = self.llm_generator(
                prompt,
                max_new_tokens=150,
                temperature=0.7,
                num_return_sequences=1,
                do_sample=True
            )
            
            # Parse the response to extract suggestions
            text = response[0]['generated_text']
            suggestions = []
            
            # Extract numbered suggestions
            for line in text.split('\n'):
                if re.match(r'^\d+\.', line):
                    suggestion = re.sub(r'^\d+\.\s*', '', line).strip()
                    if suggestion:
                        suggestions.append(suggestion)
                        if len(suggestions) >= 3:
                            break
            
            return suggestions
        except Exception as e:
            self.logger.warning(f"LLM suggestion generation failed: {str(e)}")
            return []

    def _generate_explanation(self, password, strength_score, vulnerabilities):
        """Generate explanation with optional LLM enhancement"""
        # Basic explanation
        explanation = f"This password scored {strength_score}/100. "
        
        if strength_score < 50:
            explanation += "It's weak and should be changed immediately. "
        elif strength_score < 75:
            explanation += "It could be stronger. "
        else:
            explanation += "It's reasonably strong. "
        
        if vulnerabilities:
            explanation += "Main vulnerabilities: " + ", ".join(v.lower() for v in vulnerabilities[:3]) + ". "
        
        # Try to enhance with LLM if available
        try:
            self._init_llm()
            if self.llm_generator:
                llm_explanation = self._generate_llm_explanation(password, strength_score, vulnerabilities)
                if llm_explanation:
                    explanation = llm_explanation
        except Exception as e:
            self.logger.warning(f"LLM explanation generation failed: {str(e)}")
        
        return explanation

    def _generate_llm_explanation(self, password, strength_score, vulnerabilities):
        """Generate LLM-powered explanation"""
        if not self.llm_generator:
            return ""
        
        prompt = f"""Explain this password's security in simple terms:
Password: {password}
Strength Score: {strength_score}/100
Vulnerabilities: {', '.join(vulnerabilities)}
Explanation: """
        
        try:
            response = self.llm_generator(
                prompt,
                max_new_tokens=100,
                temperature=0.5,
                num_return_sequences=1,
                do_sample=True
            )
            
            # Extract the explanation part
            text = response[0]['generated_text']
            explanation = text.split("Explanation:")[-1].strip()
            
            # Clean up any weird formatting
            explanation = re.sub(r'\s+', ' ', explanation)  # Remove extra whitespace
            explanation = explanation.split('.')[0] + '.'  # Take just the first sentence
            
            return explanation
        except Exception as e:
            self.logger.warning(f"LLM explanation generation failed: {str(e)}")
            return ""

    def _get_fallback_suggestion(self):
        """Get a fallback suggestion when others fail"""
        suggestions = [
            "Combine multiple random words with numbers/symbols",
            "Use a memorable phrase with mixed characters",
            "Consider using a password manager"
        ]
        return suggestions[len(suggestions) % 3]

    def _fallback_strength_score(self, password):
        """Fallback strength score calculation"""
        score = 0
        score += min(30, len(password) * 2)  # Length
        score += 10 if any(c.isupper() for c in password) else 0
        score += 10 if any(c.islower() for c in password) else 0
        score += 10 if any(c.isdigit() for c in password) else 0
        score += 10 if any(not c.isalnum() for c in password) else 0
        return min(100, score)

# Create analyzer instance when module is imported
analyzer = AdvancedPasswordAnalyzer(
    dataset_path=r'C:\Users\Skandesh Maadhav\Desktop\password-analyzer\rockyou.txt\rockyou.txt',
    model_save_path=r'C:\Users\Skandesh Maadhav\Desktop\password-analyzer\passw\models',
    device="cpu"
)
