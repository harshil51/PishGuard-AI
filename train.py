import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import GradientBoostingClassifier
from sklearn import metrics
import pickle
import os

def train():
    print("Loading dataset: phishing.csv ...")
    data = pd.read_csv("phishing.csv")

    if 'Index' in data.columns:
        data = data.drop(['Index'], axis=1)

    X = data.drop(["class"], axis=1)
    y = data["class"]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    print(f"Dataset Split: {X_train.shape[0]} training samples, {X_test.shape[0]} test samples across {X_train.shape[1]} features.")

    print("Training GradientBoostingClassifier (max_depth=4, learning_rate=0.7)...")
    gbc = GradientBoostingClassifier(max_depth=4, learning_rate=0.7, random_state=42)
    gbc.fit(X_train, y_train)

    y_pred = gbc.predict(X_test)
    acc = metrics.accuracy_score(y_test, y_pred)
    f1 = metrics.f1_score(y_test, y_pred)
    precision = metrics.precision_score(y_test, y_pred)
    recall = metrics.recall_score(y_test, y_pred)

    print("\n--- Model Evaluation Results ---")
    print(f"Test Accuracy : {acc * 100:.2f}%")
    print(f"F1 Score      : {f1:.4f}")
    print(f"Precision     : {precision:.4f}")
    print(f"Recall        : {recall:.4f}")

    os.makedirs("pickle", exist_ok=True)
    model_path = os.path.join("pickle", "model.pkl")
    with open(model_path, "wb") as f:
        pickle.dump(gbc, f)
    print(f"\nTrained model successfully serialized and saved to: {model_path}")

if __name__ == "__main__":
    train()
