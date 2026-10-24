import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import make_pipeline
import joblib

print("Loading dataset...")
df = pd.read_csv("dataset.csv")
pipeline = make_pipeline(
    TfidfVectorizer(token_pattern=r'(?u)\b[\w.-]+\b'), 
    RandomForestClassifier(n_estimators=100, random_state=42)
)

print("Training Random Forest model on behavioral data...")
pipeline.fit(df['log_text'], df['label'])
joblib.dump(pipeline, 'malware_model.pkl')
print("Model successfully saved as 'malware_model.pkl'.")