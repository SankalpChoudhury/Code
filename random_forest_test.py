import numpy as np
import pandas as pd
import pickle
import time
import os

from random_forest import RandomForest

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
Dataset = os.path.join(BASE_DIR, "dataset_Upload.csv")

def accuracy(y_true, y_pred):
    accuracy = np.sum(y_true == y_pred) / len(y_true)
    return round(accuracy, 4)

# Load with pandas for better error handling and column management
df = pd.read_csv(Dataset, encoding='unicode_escape')

# We only want the 16 features + 1 result
# The features are columns 1 to 16, result is column 17 (0-indexed)
# Drop any rows with NaN values just in case
df = df.dropna(subset=df.columns[1:18])

data = df.iloc[:, 1:18].values.astype(np.int32)
X = data[:, 0:16]
y = data[:, 16]

# Timer start
start_time = time.time()

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=3)

classifier = RandomForest(n_trees=21, max_depth=6)

classifier.train(X_train, y_train)
y_pred = classifier.prediction(X_test)
acc = accuracy(y_test, y_pred) * 100
print (f"Random Forest Accuracy: {acc}")

# Save accuracy to file for the web app to read
with open('accuracy.txt', 'w') as f:
    f.write(str(acc))

# pickle
pickle.dump(classifier, open('model_RF.pkl','wb'))