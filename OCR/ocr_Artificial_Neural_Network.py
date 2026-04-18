import numpy as np

class OCRNeuralNetwork:

    def __init__(self, hidden_nodes):
        self.hidden_nodes = hidden_nodes
        self.lr = 0.1

        self.theta1 = np.random.uniform(-0.5, 0.5, (hidden_nodes, 400))
        self.theta2 = np.random.uniform(-0.5, 0.5, (10, hidden_nodes))

        self.b1 = np.zeros((hidden_nodes, 1))
        self.b2 = np.zeros((10, 1))
    
    def sigmoid(self, x):
        return 1 / (1 + np.exp(-x))
    
    def sigmoid_deriv(self, x):
        return x *(1 -x)
    
    def train(self, data_array):
        for data in data_array:
            x = np.array(data["y0"]).reshape(400, 1)

            # forward
            z1 = np.dot(self.theta1, x) + self.b1
            a1 = self.sigmoid(z1)

            z2 = np.dot(self.theta2, a1) + self.b2
            a2 = self.sigmoid(z2)

            # expected
            y = np.zeros((10, 1))
            y[data["label"]] = 1

            # error
            error_output = y - a2
            error_hidden = np.dot(self.theta2.T, error_output) * self.sigmoid_deriv(a1)

            # update
            self.theta2 += self.lr * np.dot(error_output, a1.T)
            self.theta1 += self.lr * np.dot(error_hidden, x.T)

            self.b2 += self.lr * error_output
            self.b1 += self.lr * error_hidden

    def predict(self, image):
        x = np.array(image).reshape(400, 1)

        a1 = self.sigmoid(np.dot(self.theta1, x) + self.b1)
        a2 = self.sigmoid(np.dot(self.theta2, a1) + self.b2)
        
        return np.argmax(a2)