#! /bin/bash/env python3

"""
The point of this script is to push out any postive virus scans 
and to alert me via pushbullet notifications that would be sent
directly to my mobile device 
"""
__author__ = """Reuben deVries"""
__version__ = """0.1"""
__date__ = """Feburary 14th, 2021"""

# importing built-in python modules
import base64
import json
import logging
import os

# importing 3rd party python modules
import requests

# a function to start the logging process
def start_logging():
    # basic logging config - note where the log is stored, the time the event occured and the message.
    logging.basicConfig(filename="/home/reuben/daily-virus-scan.log", 
        format="%(asctime)s %(messages)s", 
        filemode="w",
        level=logging.WARN)
    logger = logging.getLogger() #starting the logging
    return logger #returning the logger so we can pass it to other functions.

# a function to do a daily virus scan on 
def daily_virus_scan(logger):
    # Adding some variables for the function to work
    logger()
    results = os.popen("clamscan -r --gen-json /home/").read()
    return results
    #virus_count = int(result) # transforming the number of viruses found to an int so we can compare it
    #if virus_count > 0: # hopefully returns a 0, but if greater then 0 then it's going to return a virus count.
    #    return virus_count

# a function that will send a notification to my phone via pushbullet api.
def notify_me(logger, results): # inputs the virus count from below.
    # Adding some variables for the function to work.
    """calling a OS environment variable that I've stored locally, ideally
    I would like to find a better or more secure way to handle this 
    environment variable."""
    logger()
    api = os.getenv("API")
    api_b64 = base64.b64decode(api) 
    api_decode = api_b64.decode(encoding="utf-8")
    hostname = os.uname()[1] # Lets me know the hostname of the computer where the virus infection was found.
    title = "Daily Clamscan Results on {0}".format(hostname) # The title of the message in the Pushbullet API Post.
    data_send = {"type": "note", "title": title, "body": results} # What gets sent to Pushbullet API
    resp = requests.post('https://api.pushbullet.com/v2/pushes', data=json.dumps(data_send),
    headers={'Authorization': 'Bearer ' + api_decode, 'Content-Type': 'application/json'})
    status_code = resp.status_code   
    if status_code != 200:
        raise Exception("Something went wrong")

if __name__ == "__main__":
    logger = start_logging
    results = daily_virus_scan(logger)
    notify_me(logger, results)

#TODO list:

# Find a more secure way to handle the OS environment variable.
# add some proper error handling in the all of the functions