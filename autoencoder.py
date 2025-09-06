#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 24 15:10:44 2019
@author: hananhindy
"""
from tensorflow.keras.layers import Input, Dense, Dropout
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.regularizers import l2, l1, l1_l2
from tensorflow.keras.utils import get_custom_objects
from tensorflow.keras.saving import register_keras_serializable
import tensorflow.keras.backend as K
import tensorflow as tf

@register_keras_serializable()
def mse(y_true, y_pred):
    return tf.reduce_mean(tf.square(y_true - y_pred), axis=-1)

class autoencoder:
    def __init__(self, num_features, verbose=True, mse_threshold=0.5, archi="U15,D,U9,D,U6,D,U9,D,U15", reg='l2', l1_value=0.1, l2_value=0.001, dropout=0.05, loss='mse'):
        self.mse_threshold = mse_threshold
        
        input_ = Input(shape=(num_features,))
        
        regularisation = l2(l2_value)
        if reg == 'l1':
            regularisation = l1(l1_value)
        elif reg == 'l1l2':
            regularisation = l1_l2(l1=l1_value, l2=l2_value)
        
        layers = archi.split(',')
        previous = input_
        for l in layers:
            if l[0] == 'U':
                layer_value = int(l[1:])
                current = Dense(units=layer_value, use_bias=True, kernel_regularizer=regularisation, kernel_initializer='uniform')(previous)
                previous = current
            elif l[0] == 'D':
                current = Dropout(dropout)(previous)
                previous = current
        
        output = Dense(units=num_features, activation='linear')(previous)
        self.model = Model(input_, output)
        
        if loss == 'mae':
            self.model.compile(loss=self.mae_loss, optimizer=Adam(learning_rate=0.001), metrics=[self.accuracy])
        else:
            self.model.compile(loss='mse', optimizer=Adam(learning_rate=0.001), metrics=[self.accuracy, mse])
        
        if verbose:
            self.model.summary()
    
    @register_keras_serializable()
    def accuracy(self, y_true, y_pred):
        mse = tf.reduce_mean(tf.square(y_true - y_pred), axis=1)
        return tf.reduce_mean(tf.cast(mse < self.mse_threshold, tf.float32))
    
    @register_keras_serializable()
    def mae_loss(self, y_true, y_pred):
        return K.mean(K.abs(y_pred - y_true), axis=1)

def build_autoencoder(num_features, verbose=True, mse_threshold=0.5, archi="U15,D,U9,D,U6,D,U9,D,U15", reg='l2', l1_value=0.1, l2_value=0.001, dropout=0.05, loss='mse'):
    return autoencoder(
        num_features=num_features,
        verbose=verbose,
        mse_threshold=mse_threshold,
        archi=archi,
        reg=reg,
        l1_value=l1_value,
        l2_value=l2_value,
        dropout=dropout,
        loss=loss
    ).model

def load_model(model_path):
    get_custom_objects().update({
        'accuracy': autoencoder.accuracy,
        'mae_loss': autoencoder.mae_loss,
        'mse': mse
    })
    return tf.keras.models.load_model(model_path)