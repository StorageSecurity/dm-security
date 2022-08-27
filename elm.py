import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import mean_squared_error


def plot(prediction, true):
    fig = plt.figure()
    ax = fig.add_subplot(111)
    ax.plot(range(len(prediction)), prediction, color='b', marker='*')
    ax.plot(range(len(true)), true, color='r')
    plt.legend(['prediction', 'true'])
    plt.show()


class ELM():
    def __init__(self, input_nums, hidden_nums, output_nums):
        self.input_nums = input_nums
        self.hidden_nums = hidden_nums
        self.output_nums = output_nums
        self.is_inited = False

        # 隐层权重矩阵
        self.W = np.array([[np.random.uniform(-1, 1)
                          for _ in range(self.hidden_nums)] for i in range(self.input_nums)])
        # 隐层偏置项
        self.bias = np.array([np.random.uniform(-1, 1)
                             for _ in range(self.hidden_nums)])
        # 输出层权重
        self.beta = np.zeros(shape=[self.hidden_nums, self.output_nums])
        # (H^{T}H)^{-1}
        self.P = np.zeros(shape=[self.hidden_nums, self.hidden_nums])

    def predict(self, x):
        return np.dot(self.activation(np.dot(x, self.W) + self.bias), self.beta)

    def init_train(self, x, target):
        # output matrix
        H = self.activation(np.dot(x, self.W) + self.bias)
        HT = np.transpose(H)
        HTH = np.dot(HT, H)
        self.P = np.linalg.inv(HTH)
        pHT = np.dot(self.P, HT)
        self.beta = np.dot(pHT, target)
        self.is_inited = True

    def seq_train(self, x, target):
        batch_size = x.shape[0]
        H = self.activation(np.dot(x, self.W) + self.bias)
        HT = np.transpose(H)
        I = np.eye(batch_size)
        Hp = np.dot(H, self.P)
        HpHT = np.dot(Hp, HT)
        temp = np.linalg.inv(I + HpHT)
        pHT = np.dot(self.P, HT)
        self.P -= np.dot(np.dot(pHT, temp), Hp)
        pHT = np.dot(self.P, HT)
        Hbeta = np.dot(H, self.beta)
        self.beta += np.dot(pHT, target - Hbeta)

    def activation(self, x):
        return 1 / (1 + np.exp(-x))


if __name__ == '__main__':
    # 000001 2014-2017
    df = pd.read_csv('000001_Daily.csv')
    window_size = 5
    scaler = MinMaxScaler()
    data = np.reshape(df['Close'].values, newshape=(-1, 1))
    data = np.reshape(scaler.fit_transform(data), newshape=(-1, ))
    X = []
    Y = []
    for i in range(len(data) - window_size):
        X.append(data[i: i + window_size])
        Y.append(data[i + window_size])
    all_X = np.array(X)
    all_Y = np.array(Y)
    train_X = all_X[:500, :]
    train_Y = all_Y[:500]

    test_X = all_X[500:, :]
    test_Y = all_Y[500:]

    oselm = ELM(input_nums=5, hidden_nums=64, output_nums=1)
    oselm.init_train(train_X, train_Y)

    prediction_list = []
    Y_list = []
    for X, Y in zip(test_X, test_Y):
        prediction = oselm.predict(X)
        prediction_list.append(prediction)
        Y_list.append(Y)
    prediction_arr = np.reshape(np.array(prediction_list), newshape=(-1, 1))
    true_arr = np.reshape(np.array(Y_list), newshape=(-1, 1))
    prediction_scaled_arr = scaler.inverse_transform(prediction_arr)
    true_scaled_arr = scaler.inverse_transform(true_arr)
    plot(prediction_scaled_arr, true_scaled_arr)
    print('RMSE of ELM', np.sqrt(mean_squared_error(
        prediction_scaled_arr, true_scaled_arr)))

    prediction_list = []
    Y_list = []
    for X, Y in zip(test_X, test_Y):
        prediction = oselm.predict(X)
        prediction_list.append(prediction)
        Y_list.append(Y)
        oselm.seq_train(X[np.newaxis, :], Y)
    prediction_arr = np.reshape(np.array(prediction_list), newshape=(-1, 1))
    true_arr = np.reshape(np.array(Y_list), newshape=(-1, 1))
    prediction_scaled_arr = scaler.inverse_transform(prediction_arr)
    true_scaled_arr = scaler.inverse_transform(true_arr)
    plot(prediction_scaled_arr, true_scaled_arr)
    print('RMSE of OS-ELM',
          np.sqrt(mean_squared_error(prediction_scaled_arr, true_scaled_arr)))
