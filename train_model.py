import pandas as pd
from sklearn.model_selection import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
import pickle
import os

print("Loading the 48-feature dataset...")
try:
    data = pd.read_csv('phishing_data.csv')
except FileNotFoundError:
    print("\nError: 'phishing_data.csv' not found.")
    exit()

X = data.iloc[:, :-1]
y_raw = data.iloc[:, -1]


y = y_raw.astype(str).map({"b'0'": 1, "0": 1, "b'1'": 0, "1": 0})

if y.isnull().any():
    print("Error mapping labels. Unique values:", y_raw.unique())
    exit()

print(f"Dataset loaded with {X.shape[1]} features.")


print("Splitting data and training with XGBoost...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = XGBClassifier(random_state=42)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nSmarter Model (XGBoost) Accuracy on Test Set: {accuracy * 100:.2f}%")


if not os.path.exists('pickle'):
    os.makedirs('pickle')

print("Saving the upgraded model to 'pickle/model.pkl'...")
with open('pickle/model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("\nModel upgrade and training complete!")