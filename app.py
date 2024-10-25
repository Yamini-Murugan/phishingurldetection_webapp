# Flask utils
import keras
import pickle
import sklearn
import requests
import numpy as np
import pandas as pd
import tensorflow as tf
from urlfeatureextraction import *
from flask import Flask, request, render_template
from tensorflow.keras.models import load_model

#all feature of url
feature_names = ['Domain', 'Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection', 
    'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record', 'Web_Traffic', 
    'Domain_Age', 'Domain_End','IframeRedirection','StatusBarCust','DisableRightClick','WebsiteForwarding',
    'LinksPointingToPage', 'GoogleIndex']


#loading saved model
bilstm_model = load_model('./saved_model/bilstm_model.h5')

#flask app config
application = Flask(__name__)

app=application


#flask routing
@app.route('/')
def index(): 
  return render_template('index.html')

@app.route('/homepage')
def homepage(): 
  return render_template('index.html')


@app.route('/servicepage')
def servicepage(): 
  return render_template('services.html')



@app.route('/urldetection', methods=['POST'])
def urldetection():
  url = request.form["url"]
  datalist = urlfeature_extractor(url)
  dataframe = pd.DataFrame([datalist], columns= feature_names)
  #print(dataframe)
  dataframe.drop(['Domain'], axis='columns', inplace=True)
  dataframe = np.array(dataframe)
  dataframe = np.expand_dims(dataframe, axis=2)
  print(dataframe)
  ypred = bilstm_model.predict(dataframe)
  ypred = np.argmax(ypred,axis=1)
  outputres = ypred[0]

  if outputres == 1:
    outputres = "ALERT URL DETECTED AS PHISHING !"

  else:
    outputres = "URL DETECTED AS SAFE !"
  
  return render_template('services.html', res2 = outputres, inpurl = url)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)




