import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

from feature import extract_features

# Load dataset
data = pd.read_csv("dataset.csv")

# Extract features
X = data['url'].apply(extract_features).tolist()

# Labels
y = data['label']

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2
)

# Train model
model = RandomForestClassifier()

model.fit(X_train, y_train)

# Save model
joblib.dump(model, "phishing_model.pkl")

print("Model Trained Successfully")