# 🛡️ Phishing Website Detection using Machine Learning

Detect malicious phishing websites using a robust machine learning model deployed via a sleek Flask web interface.

![Python](https://img.shields.io/badge/Python-3.8-blue)
![Flask](https://img.shields.io/badge/Flask-Backend-lightgrey)
![Machine Learning](https://img.shields.io/badge/ML-Classification-green)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

---

## 📌 Overview

Phishing attacks are one of the most common and dangerous cybersecurity threats today. They trick users into revealing sensitive information like passwords, card numbers, and personal data. This project aims to detect such phishing URLs using advanced machine learning techniques, offering real-time prediction through a user-friendly web app.

---

## ❗ Importance

🔒 **Cybersecurity Impact**: Phishing is responsible for 90% of data breaches worldwide.  
💡 **Traditional Methods Fail**: Blacklists become outdated quickly and can't detect new domains.  
🤖 **Machine Learning Advantage**: Pattern recognition, adaptability, and automation make ML a powerful defense.

---

## 🎯 Goal

To build an intelligent phishing detection system that:
- Accurately classifies URLs as **Legitimate** or **Phishing**
- Provides a clean and intuitive **Flask-based web app** for end-users
- Leverages **10+ ML models** for performance benchmarking
- Uses the **best-performing model** in deployment

---

## 🧠 Machine Learning Models Used

We trained and tested 10 classification algorithms to determine the best-performing model based on accuracy, F1-score, precision, and recall.

| Model                    | Accuracy | F1 Score | Recall | Precision |
|--------------------------|----------|----------|--------|-----------|
| 🎯 Gradient Boosting     | **0.974** | **0.977** | 0.994  | 0.986     |
| CatBoost Classifier      | 0.972    | 0.975    | 0.994  | 0.989     |
| XGBoost Classifier       | 0.969    | 0.973    | 0.993  | 0.984     |
| Multi-layer Perceptron   | 0.969    | 0.973    | 0.995  | 0.981     |
| Random Forest            | 0.967    | 0.971    | 0.993  | 0.990     |
| SVM                      | 0.964    | 0.968    | 0.980  | 0.965     |
| Decision Tree            | 0.960    | 0.964    | 0.991  | 0.993     |
| K-Nearest Neighbors      | 0.956    | 0.961    | 0.991  | 0.989     |
| Logistic Regression      | 0.934    | 0.941    | 0.943  | 0.927     |
| Naive Bayes              | 0.605    | 0.454    | 0.292  | **0.997**  |

> ✅ **Final Model Deployed:** Gradient Boosting Classifier (Highest Accuracy & Balanced Metrics)

---

## ⚙️ Tech Stack

| Layer             | Technology                 |
|------------------|----------------------------|
| Programming Lang | Python 3.8                 |
| Web Framework    | Flask                      |
| ML Libraries     | Scikit-learn, CatBoost, XGBoost |
| Frontend         | HTML, CSS                  |
| Deployment       | Localhost (Heroku Ready)   |

---

## 🧩 Features Extracted from URL

- Length of URL  
- Use of HTTPS  
- Number of subdomains  
- Presence of IP address  
- Use of special characters  
- Domain age & expiration  

These features were processed in `feature.py` for real-time analysis.

---

## 🖥️ Web App Functionality

1. User enters any URL into the form
2. Features are auto-extracted and passed to the ML model
3. The trained model predicts **Phishing** or **Legitimate**
4. Result is displayed with a clear and styled output

---

## 🗂️ Project Structure

```
Phishing-Website-Detection/
├── app.py                         # Flask App
├── feature.py                     # Feature extraction from URL
├── phishing.csv                   # Cleaned dataset
├── requirements.txt               # Dependencies
├── Procfile                       # Heroku deployment support
├── test-url.txt                   # Sample test URLs
├── pickle/
│   └── model.pkl                  # Final ML model
├── static/
│   ├── styles.css                 # Web styling
│   └── img/                       # Icons & images
├── templates/
│   └── index.html                 # HTML frontend
```

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yourusername/phishing-website-detection.git
cd phishing-website-detection
```

### 2️⃣ Install Requirements

```bash
pip install -r requirements.txt
```

### 3️⃣ Run the Web App

```bash
python app.py
```

Visit `http://127.0.0.1:5000` in your browser.

---

## 🌐 (Optional) Deploy on Heroku

1. Create Heroku App
```bash
heroku create phishing-detector-app
```

2. Push Code
```bash
git push heroku main
```

3. Visit your live app

---

## 🌟 Highlights

- 📊 Compared 10 machine learning models
- ⚖️ Gradient Boosting Classifier gave best results
- 🔐 Secured real-time detection using URL features
- 🧠 No manual feature labeling – automatic extraction
- 🖼️ Clean UI built with HTML/CSS + Flask
- 🚀 Ready for Heroku deployment

---


## 👩‍💻 Author

**Manvitha Reddy Katika**  
🎓 B.Tech | 📊 Machine Learning & AI Enthusiast | 💡 Aspiring Data Scientist  
📬 [LinkedIn](https://www.linkedin.com/in/manvitha-reddyk)  
📧 manvithareddy711@gmail.com

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

---

⭐️ If you liked this project, **please give it a star** to support open-source efforts!

