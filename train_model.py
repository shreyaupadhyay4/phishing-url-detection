import pandas as pd
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, confusion_matrix
import matplotlib.pyplot as plt
import os

DATASET_PATH = "PhiUSIIL_Phishing_URL_Dataset.csv"

# create static folder if not exists
os.makedirs("static", exist_ok=True)

# Load dataset
if not os.path.exists(DATASET_PATH):
    raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

df = pd.read_csv(DATASET_PATH)

# Clean column names
df.columns = df.columns.str.strip()

# Drop Index column if exists
if 'Index' in df.columns:
    df.drop(columns=['Index'], inplace=True)

# Features and label
target_column = "class" if "class" in df.columns else "label"
if target_column not in df.columns:
    raise KeyError("Dataset must contain either a 'class' or 'label' column.")

y = df[target_column]
X = df.drop(columns=[target_column])
X = X.select_dtypes(include=["number", "bool"])
if X.empty:
    raise ValueError("No numeric feature columns found for training.")

# Normalize pandas dtypes before scikit-learn slices the data. This avoids
# pandas dtype promotion errors on newer Python/pandas builds.
X = X.astype("float64")

# Split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Predict
y_pred = model.predict(X_test)

# Accuracy
acc = accuracy_score(y_test, y_pred)
print("Accuracy:", acc)

# Save model
pickle.dump(model, open("model.pkl", "wb"))

# ===== GRAPH =====

# Accuracy graph
plt.bar(["Accuracy"], [acc * 100])
plt.title("Model Accuracy")
plt.savefig("static/accuracy_graph.png")
plt.close()

# Confusion matrix
cm = confusion_matrix(y_test, y_pred)

plt.imshow(cm, cmap='Blues')
plt.title("Confusion Matrix")
plt.savefig("static/confusion_matrix.png")
plt.close()

print(f"Model trained successfully using {DATASET_PATH}")
