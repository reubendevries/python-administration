#! /bin/bash/env python3

"""
The point of this script is to push out any postive virus scans 
and to alert me via pushbullet notifications that would be sent
directly to my mobile device 
"""
__author__ = """Reuben deVries"""
__version__ = """0.1"""
__date__ = """June 30, 2021"""

# importing built-in python modules
from logging import basicConfig, getLogger
from os import uname
from subprocess import run

# importing 3rd party python modules
from requests import post

# a function to start the logging process
def start_logging():
    """basic logging config - note where the log is stored, the time the event occured and the message."""
    basicConfig(filename="/home/reuben/virus-scan.log", 
        format="%(asctime)s %(messages)s", 
        filemode="w",
        level="WARN")
    # starting the logger
    logger = getLogger()
    return logger # returning the logger so we can pass it to other functions.

 
def virus_scan(logger):
    """a function that will start a run a virus scan."""
    logger()
    results = run(["clamscan","--gen-json"])
    print(results)
    return results
    

# a function that will send a notification to my phone via pushbullet api.
def notify_me(logger, results): # inputs the virus count from below.
    # Adding some variables for the function to work.
    """calling a OS environment variable that I've stored locally, ideally
    I would like to find a better or more secure way to handle this 
    environment variable."""
    
    logger()
    
    api = ""

    hostname = uname()[1] # Lets me know the hostname of the computer where the virus infection was found.
    
    title = "Daily Clamscan Results on {0}".format(hostname) # The title of the message in the Pushbullet API Post.
    
    data_send = {
                    "type": "note", 
                    "title": title, 
                    "body": results
                } # What gets sent to Pushbullet API
    response = post(
                    "https://api.pushbullet.com/v2/pushes", 
                    data=data_send,
                    headers={
                        "Access-Token": api, 
                        "Content-Type": "application/json"
                    }
            )
    status_code = response.status_code   
    if status_code != 200:
        raise Exception("Something went wrong")

if __name__ == "__main__":
    logger = start_logging
    results = virus_scan(logger)
    notify_me(logger, results)

#TODO list:

# Find a more secure way to handle the OS environment variable.
# add some proper error handling in the all of the functions
