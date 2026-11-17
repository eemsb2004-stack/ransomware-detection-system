import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import confusion_matrix, accuracy_score

from co_all import rf_model

from co_all import xgb_model

# 1. Importing the dataset
print("Reading the dataset...")
datasets = pd.read_csv(r'D:\RanPrg\monitoring\Ma2022.csv')
print("Dataset read successfully")
print(datasets['Class'].value_counts())

# 2. Splitting the dataset into features (X) and target (Y)
print("Splitting the dataset into the Training set and Test set...")
X = datasets.iloc[:, [2, 3]].to_numpy()
Y = datasets['Class'].to_numpy()

# 3. Splitting the dataset into Training and Test sets
X_Train, X_Test, Y_Train, Y_Test = train_test_split(X, Y, test_size=0.25, random_state=0)

# 4. Feature Scaling
sc_X = StandardScaler()
X_Train = sc_X.fit_transform(X_Train)
X_Test = sc_X.transform(X_Test)

# 5. Fitting the Random Forest Classifier into the Training set
classifier = RandomForestClassifier(n_estimators=200, criterion='entropy', random_state=0)
classifier.fit(X_Train, Y_Train)

# 6. Predicting the Test set results
Y_Pred = classifier.predict(X_Test)

# 7. Making the Confusion Matrix and evaluating accuracy
cm = confusion_matrix(Y_Test, Y_Pred)
print("Confusion Matrix:\n", cm)
print("Accuracy Score:", accuracy_score(Y_Test, Y_Pred))
import joblib
rf_model
# After successfully training the models (e.g., rf_model and xgb_model):
joblib.dump(rf_model, "random_forest_model.pkl")
joblib.dump(xgb_model, "xgboost_model.pkl")
print("[*] Models saved successfully as .pkl files!")