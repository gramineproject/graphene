import os
import xgboost as xgb
import pandas as pd
import numpy as np
import os

xgb_params = {
    'max_depth': 3,
    'eta': 0.3,
    'objective': 'multi:softprob',
    'num_class': 3
}

def xgboost_fit(x_train, y_train):
    dtrain  = xgb.DMatrix(x_train, label=y_train)
    model   = xgb.train(xgb_params, dtrain)
    return model

def xgb_predict_of_data(model, test):
    dtest = xgb.DMatrix(test)
    return model.predict(dtest)

def read_dataset_internal(filename):
    print("Reading:", filename)
    if not os.path.exists(filename):
        err_str = f"No such file: {filename}"
        print(err_str)
        raise Exception(err_str)

    print("Reading data")
    data = pd.read_csv(filename, header=None)
    print("Reading succeed")
    return data

def read_dataset():
    name_train = 'data/iris_train.csv'
    name_test = 'data/iris_test.csv'
    train = read_dataset_internal(name_train)
    train_X, train_y = train[train.columns[:-1]], train.iloc[:,-1:]
    test = read_dataset_internal(name_test)
    test_X, test_y = test[test.columns[:-1]], test.iloc[:,-1:]

    return train_X, train_y, test_X, test_y

def main():
    train_X, train_y, test_X, test_y = read_dataset()

    model           = xgboost_fit(train_X, train_y)
    test_result     = xgb_predict_of_data(model, test_X)

    test_result = np.argmax(test_result, axis=1)
    accuracy = np.sum(test_result == test_y.to_numpy().reshape(-1)) / test_result.shape[0]
    print("Accuracy:", accuracy)
    print("Example succeed!!")

if __name__ == "__main__":
    main()
