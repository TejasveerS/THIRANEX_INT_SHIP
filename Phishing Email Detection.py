import pandas as pd
import re
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from sklearn.naive_bayes import MultinomialNB

# ----------- LOAD DATASET -----------
# Replace with your dataset file path
# Dataset format: columns = ['text', 'label']
# label: 0 = Safe, 1 = Phishing

data = pd.read_csv("emails.csv")

# ----------- BASIC DATA CLEANING -----------
data = data.dropna()

# ----------- FEATURE ENGINEERING -----------
def extract_features(text):
    text = text.lower()

    # Count URLs
    url_count = len(re.findall(r'http[s]?://', text))

    # Count suspicious words
    suspicious_words = ['bank', 'verify', 'password', 'urgent', 'click', 'login']
    suspicious_count = sum(word in text for word in suspicious_words)

    return text, url_count, suspicious_count

processed_text = []
url_counts = []
suspicious_counts = []

for email in data['text']:
    t, u, s = extract_features(email)
    processed_text.append(t)
    url_counts.append(u)
    suspicious_counts.append(s)

data['processed_text'] = processed_text
data['url_count'] = url_counts
data['suspicious_count'] = suspicious_counts

# ----------- TEXT VECTORIZATION -----------
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_text = vectorizer.fit_transform(data['processed_text'])

# Combine text features with numeric features
import numpy as np
X_extra = np.array(data[['url_count', 'suspicious_count']])
X = np.hstack((X_text.toarray(), X_extra))

y = data['label']

# ----------- TRAIN / TEST SPLIT -----------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# ----------- MODEL TRAINING -----------
model = MultinomialNB()
model.fit(X_train, y_train)

# ----------- PREDICTION -----------
y_pred = model.predict(X_test)

# ----------- EVALUATION -----------
print("\n✅ Model Evaluation:\n")

accuracy = accuracy_score(y_test, y_pred)
print(f"Accuracy: {accuracy:.4f}\n")

print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# ----------- TEST CUSTOM EMAIL -----------
def predict_email(email):
    t, u, s = extract_features(email)

    text_vec = vectorizer.transform([t]).toarray()
    extra_features = np.array([[u, s]])

    final_input = np.hstack((text_vec, extra_features))

    prediction = model.predict(final_input)[0]

    return "Phishing" if prediction == 1 else "Safe"


# Example test
test_email = input("\nEnter an email to check: ")
result = predict_email(test_email)

print(f"\n✅ Prediction: {result}")
``