#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Oct 24 15:10:44 2019

@author: hananhindy
"""
from sklearn.svm import OneClassSVM

class oneclass_svm:
    def __init__(self, nu_value, kernel = 'rbf', verbose=True):
        self.model = OneClassSVM(nu=nu_value, kernel= kernel, gamma = 'scale', verbose=verbose)   
import joblib

def load_model(model_path):
    return joblib.load(model_path)
import pickle
from sklearn.svm import OneClassSVM

def train_model(X, model_path='trained_models/ocsvm_model.pkl'):
    print("[DEBUG] Training One-Class SVM model...")
    model = OneClassSVM(gamma='auto', kernel='rbf', nu=0.05)
    model.fit(X)

    # Save the model
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f"[+] One-Class SVM model saved to {model_path}")

         