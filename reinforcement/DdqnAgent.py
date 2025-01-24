from tensorflow import keras
import numpy as np
import random
from Util import Util

from collections import deque

from tensorflow.python.keras.saving.save import load_model


class DoubleDeepQNetwork():

    # Initializes the Double Deep Q-Network (DDQN) agent with the specified configuration and environment.
    # Sets up hyperparameters like epsilon for exploration, gamma for discounting, and batch size for training.
    # Initializes the neural network models for both the primary and target Q-networks.
    # If prefilled actions are provided, they are loaded for controlled execution.
    def __init__(self, config, env, http_client, is_controlled, is_prefilled_actions):
        self.ACTIONS = None
        self.config = config
        self.env = env
        self.http_client = http_client
        self.is_controlled = is_controlled
        self.is_prefilled_actions = is_prefilled_actions
        self.nS = self.env.INPUT_SHAPE
        self.nA = self.env.OUTPUT_SHAPE
        self.gamma = 0.85
        self.epsilon = 1.0
        self.epsilon_min = 0.01
        # Experimentation Epsilon decay Values:
        #  50 episode X  50 step ==> 2500 ==> 0.998
        #  50 episode X 100 step ==> 5000 ==> 0.999
        self.epsilon_decay = config.epsilon_decay
        self.learning_rate = 0.01
        # self.tau = 0.125 # TODO: Possible future improvement
        self.batch_size = 8
        self.memory_size = 2500
        self.memory = deque(maxlen=self.memory_size)
        self.update_target_each = 10 # steps

        # model is updated instantly
        # target_model updated after each batch
        self.model = self.build_model()
        self.model_target = self.build_model()
        self.update_target_from_model()  # Update weights
        self.loss = []
        self.episode_loss = []

        if is_prefilled_actions:
            self.prefilled_actions = self.read_lines_from_file(config.prefilled_actions_file)
            print("<------> Actions are prefilled:")
            for prefilled_action in self.prefilled_actions:
                print(f"---------> {prefilled_action}")

    @DeprecationWarning
    # Reads a list of actions from a specified file.
    # Each action is expected to be defined on a separate line, and empty lines are ignored.
    def read_lines_from_file(self, file_path):
        with open(file_path, 'r') as file:
            lines = [line.strip() for line in file.readlines() if line.strip()]
            return lines

    # Constructs the neural network model for the DDQN agent using Keras.
    # The model consists of multiple dense layers with ReLU and Sigmoid activations for non-linear transformations.
    # The final layer uses a linear activation since it represents Q-values for each possible action.
    # The model is compiled using Mean Squared Error loss and the Adam optimizer for backpropagation.
    def build_model(self):
        model = keras.Sequential()
        model.add(keras.layers.Dense(self.nS, input_dim=self.nS, activation='relu'))  # [Input] -> Layer 1
        model.add(keras.layers.Dense(2 * self.nS, activation='relu'))
        model.add(keras.layers.Dense(4*(self.nS + self.nA)+2, activation='relu'))
        model.add(keras.layers.Dense(2*self.nS+2, activation='sigmoid'))
        model.add(keras.layers.Dense(self.nA, activation='linear'))  # Layer 5 -> [output]
        #   Size has to match the output (different actions)
        #   Linear activation on the last layer
        model.compile(loss='mean_squared_error',  # Loss function: Mean Squared Error
                      optimizer=keras.optimizers.Adam(lr=self.learning_rate))  # Optimizer: Adam (Feel free to check other options)
        return model

    # Copies the weights from the primary model to the target model.
    # The target model is used for more stable training updates.
    def update_target_from_model(self):
        # Update the target model from the base model
        self.model_target.set_weights(self.model.get_weights())
        print(f'<------> Target Model Updated')

    # Selects an action based on the current state and the exploration-exploitation trade-off.
    # If a random number is below epsilon, the agent explores a random action.
    # Otherwise, it uses the model to predict the best action.
    # Returns the selected action and a flag indicating if the action was predicted.
    def action(self, step, state):
        print('<--------------------------------------------------------->\n\n')
        if self.is_controlled:
            return self.do_controlled_prompt()
        if self.is_prefilled_actions:
            return self.do_action_from_prefilled(step)
        # return self.nA - 1 # TODO: Testing purposes only, always take no action
        if np.random.rand() <= self.epsilon:
            action = random.randrange(self.nA)  # Explore
            print(f'<------> Taking action randomly: {action}')
            return action, False
        action_vals = self.model.predict(np.reshape(state, [1, self.nS]))
        # Exploit: Use the NN to predict the correct action from this state
        #   action_vals [0] ==> because the output shape is (1, 9) meaning one line and 12 column
        #   so to get the probabilities of taking each of the 9 actions we use the first line (index 0)
        action = np.argmax(action_vals[0])
        print(f'<------> Taking action with predict: {action}')
        return action, True

    @DeprecationWarning
    def do_controlled_prompt(self):
        action = -1
        while self.is_controlled and action < 0:
            print("Avilable actions:")
            for i in range(len(self.ACTIONS)):
                ACTION = self.ACTIONS[i]
                ACTIONS_splitted = ACTION.split(':')
                if ACTIONS_splitted[0] == "redirect":
                    current_switches, dst_switch = self.get_controlled_redirect_action_with_dist(ACTIONS_splitted)
                    print(f" - {i}: {ACTION} (redirect from {current_switches} to {dst_switch})")
                else:
                    print(f" - {i}: {ACTION}")
            action = int(input("Enter action index:"))
            if 0 <= action < self.nA:
                return action, True
            print(f'<------> Action ({action}) is not recognised, please try again!')
            action = -1

    @DeprecationWarning
    # Executes a predefined action from a list of prefilled actions loaded from a file.
    # If no valid action is provided for the current step, a default "Do Nothing" action is taken.
    def do_action_from_prefilled(self, step):
        custom_action = self.get_step_index_action_or_nothing(step)
        action = -1
        if custom_action == Util.nothing_action():
            action = len(self.ACTIONS) - 1
        else:
            if custom_action.startswith("bw"):
                action = self.ACTIONS.index(custom_action)
            elif custom_action.startswith("redirect"):
                custom_action_splitted = custom_action.split(':')
                host_name = custom_action_splitted[1]
                dst_switch = custom_action_splitted[3]
                custom_action_parsed = Util.redirect_action(host_name, dst_switch)
                print(f'---------> {custom_action} corresponds to {custom_action_parsed}')
                action = self.ACTIONS.index(custom_action_parsed)
        if action == -1:
            action = len(self.ACTIONS) - 1
        print(f'<------> Taking action with prefilled: {action}')
        return action, True

    def get_step_index_action_or_nothing(self, step):
        step_index = step - 1
        custom_action = Util.nothing_action()
        if step_index < len(self.prefilled_actions):
            custom_action = self.prefilled_actions[step_index]
        return custom_action

    # Parses a redirect action to extract the host and destination switch involved.
    # Returns the host name and destination switch as a tuple for further processing.
    def get_controlled_redirect_action_with_dist(self, ACTIONS_splitted):
        host_name = ACTIONS_splitted[1]
        dst_switch = ACTIONS_splitted[3]
        return (host_name, dst_switch)

    # For testing purposes:
    # Selects the best action from the model predictions without exploration.
    # Used during testing or evaluation to purely exploit the learned policy.
    def test_action(self, state):  # Exploit
        action_vals = self.model.predict(np.reshape(state, [1, self.nS]))
        return np.argmax(action_vals[0])

    # Stores an experience tuple (state, action, reward, next state, done) into the replay memory.
    # The memory is used for experience replay during training.
    def store(self, state, action, reward, nstate, done):
        # Store the experience in memory
        self.memory.append((state, action, reward, nstate, done))

    # Trains the model using a random batch of experiences from the replay memory.
    # Each experience is processed to compute the target Q-value using the Bellman equation.
    # The model is trained using the generated batch, and epsilon is decayed after each iteration.
    # Double DQN is implemented here by using the target model for stable Q-value estimation.
    def experience_replay(self, batch_size):
        # Execute the experience replay
        # each element of memory is cur_state, action, reward, new_state, done(after each step)
        minibatch = random.sample(self.memory, batch_size)  # Randomly sample from memory

        # Convert to numpy for speed by vectorization
        x = []
        y = []
        minibatch_array = np.array(minibatch)
        st = np.zeros((0, self.nS))  # States
        nst = np.zeros((0, self.nS))  # Next States
        for i in range(len(minibatch_array)):  # Creating the state and next state np arrays
            st = np.append(st, minibatch_array[i, 0].reshape(1, self.nS), axis=0)
            nst = np.append(nst, minibatch_array[i, 3].reshape(1, self.nS), axis=0)
        st_predict = self.model.predict(st)  # Here is the speedup! I can predict on the ENTIRE batch
        nst_predict = self.model.predict(nst)
        nst_predict_target = self.model_target.predict(nst)  # Predict from the TARGET
        index = 0
        for state, action, reward, nstate, done in minibatch:
            x.append(state)
            # Predict from state
            nst_action_predict_target = nst_predict_target[index]
            nst_action_predict_model = nst_predict[index]
            if done == True:  # Terminal: Just assign reward much like {* (not done) - QB[state][action]}
                target = reward
            else:  # Non terminal
                print(f"<------> reward: {reward} and future reward: {nst_action_predict_target[np.argmax(nst_action_predict_model)]}")
                target = reward + self.gamma * nst_action_predict_target[
                    np.argmax(nst_action_predict_model)]  # Using Q to get T is Double DQN
            target_f = st_predict[index]
            target_f[action] = target
            y.append(target_f)
            index += 1
        # Reshape for Keras Fit
        x_reshape = np.array(x).reshape(batch_size, self.nS)
        y_reshape = np.array(y)
        epoch_count = 1
        hist = self.model.fit(x_reshape, y_reshape, epochs=epoch_count, verbose=0)
        # Graph Losses
        for i in range(epoch_count):
            self.loss.append(hist.history['loss'][i])
            self.episode_loss.append(hist.history['loss'][i])
        # Decay Epsilon
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
            print("<------> New Epsilon value: " + str(self.epsilon))

    def save_model(self, filename):
        self.model_target.save(filename)

    def load_model(self, filename):
        self.model_target = load_model(filename)

    def set_actions(self, ACTIONS):
        self.ACTIONS = ACTIONS