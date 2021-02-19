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
import subprocess
import sys

# importing 3rd party python modules
import requests

# a function to start the logging process
def start_logging():
    # basic logging config - note where the log is stored, the time the event occured and the message.
    logging.basicConfig(filename="/var/log/weekly-virus-scan.log", 
        format="%(asctime)s %(messages)s", 
        filemode="w")
    logger = logging.getLogger() #starting the logging
    logger.setLevel(logging.WARN) # setting it to the warn level
    return logger #returning the logger so we can pass it to other functions.

# a function to do a daily virus scan on 
def daily_virus_scan(logger):
    # Adding some variables for the function to work
    output = subprocess.check_output(["clamscan","-r","-i", "--stdout","/"])
    results = output.decode(encoding="utf-8") # subprocess check_output returns in byte format need to decode to string
    result = results.split("\n")[-5][-1] # spliting the string so I only get the numbered result back.
    virus_count = int(result) # transforming the number of viruses found from a string value to an int so it can be compared.
    if virus_count > 0: # hopefully returns a 0, but if greater then 0 then it's going to return a virus count.
        return virus_count
    else:
        sys.exit()

# a function that will send a notification to my phone via pushbullet api.
def virus_infection_notify_me(logger, virus): # inputs the virus count from below.
    # Adding some variables for the function to work.
    """calling a OS environment variable that I've stored locally, ideally
    I would like to find a better or more secure way to handle this 
    environment variable."""
    api = os.getenv("API")
    api_b64 = base64.b64decode(api) 
    api_decode = api_b64.decode(encoding="utf-8")
    hostname = os.uname()[1] # Lets me know the hostname of the computer where the virus infection was found.
    script_name = "the weekly scan of your entire Computer" # Let's me know the script that ran when the virus infection was found
    title = "Virus Found" # The title of the message in the Pushbullet API Post.
    message = """A virus threat has been found on {0}. while running {1}.\r\n 
    Please do an appropriate scan on this computer, and rectify 
    immediately!\r\n""".format(hostname, script_name) # body of the message in the Pushbullet API Post.
    data_send = {"type": "note", "title": title, "body": message} # What gets sent to Pushbullet API
    resp = requests.post('https://api.pushbullet.com/v2/pushes', data=json.dumps(data_send),
    headers={'Authorization': 'Bearer ' + api_decode, 'Content-Type': 'application/json'})    
    status_code = resp.status_code
    if status_code != 200:
        print(status_code)
        raise Exception("Something went wrong")
    else:
        return
if __name__ == "__main__":
    logger = start_logging()
    virus = daily_virus_scan(logger)
    if virus > 0:
        virus_infection_notify_me(logger, virus)
    else:
        sys.exit()

#TODO list:

# Find a more secure way to handle the OS environment variable.
# add some proper error handling in the all of the functions