import pandas as pd
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, confusion_matrix

from co_all import rf_model, xgb_model

# 1. Load the dataset
print("Reading the dataset...")
#df = pd.read_csv(r'D:\RanPrg\Ma2022.csv')
df = pd.read_csv(r'D:\RanPrg\monitoring\Ma2022.csv')
print("Dataset read successfully")
print(df['Class'].value_counts())

# 2. Split features (X) and target (Y)
X = df.iloc[:, [2, 3]].to_numpy()
Y_raw = df['Class'].to_numpy()

# Encode string labels (Benign/Malware) into numbers (0 and 1)
encoder = LabelEncoder()
Y = encoder.fit_transform(Y_raw)

# 3. Split data into training and testing sets
X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=0.25, random_state=0)

# 4. Configure XGBoost parameters for binary classification
params = {
    "objective": "binary:logistic",
    "eval_metric": "logloss",
    "learning_rate": 0.1,
    "max_depth": 5,
    "verbosity": 0
}

# Convert data to DMatrix format required by XGBoost
dtrain = xgb.DMatrix(X_train, label=y_train)
dvalid = xgb.DMatrix(X_test, label=y_test)

# 5. Train the model
print("Training XGBoost model...")
bst = xgb.train(params, dtrain, num_boost_round=100, evals=[(dvalid, "valid")])

# 6. Predict and evaluate
preds = bst.predict(dvalid)
predictions = [1 if p > 0.5 else 0 for p in preds]

print("Confusion Matrix:\n", confusion_matrix(y_test, predictions))
print("Accuracy Score:", accuracy_score(y_test, predictions))
import joblib

# After successfully training the models (e.g., rf_model and xgb_model):
joblib.dump(rf_model, "random_forest_model.pkl")
joblib.dump(xgb_model, "xgboost_model.pkl")
print("[*] Models saved successfully as .pkl files!")