#! /usr/bin/env python3
# -*- coding: utf-8 -*-

'''
Script to check the status of ssl, through the api (https://api.ssllabs.com/api/v2/) do ssllabs (ssllabs.com)

Creation date: 12/02/2017
Date last updated: 18/03/2017

Nagios check_ssl plugin
* 
* License: GPL
* Copyright (c) 2017 DI-FCUL
* 
* Description:
* 
* This file contains the check_ssl plugin
* 
* Use the nrpe program to check update information for wordpress in remote host.
* 
* 
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
* 
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys
from optparse import OptionParser
import os
import json
import time
#import urllib2
import urllib
import socket
import ssl
import datetime
import time
import requests

__author__ = "\nAuthor: Raimundo Henrique da Silva Chipongue\nE-mail: fc48807@alunos.fc.ul.pt, chipongue1@gmail.com\nInstitution: Faculty of Science of the University of Lisbon\n"
__version__= "1.0.0"

# define exit codes
ExitOK = 0
ExitWarning = 1
ExitCritical = 2
ExitUnknown = 3

def ssl_expiry_datetime(hostname):
    ssl_date_fmt = r'%b %d %H:%M:%S %Y %Z'

    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=hostname,)
    
    conn.settimeout(3.0)

    conn.connect((hostname, 443))
    ssl_info = conn.getpeercert()
    exprirationdate = datetime.datetime.strptime(ssl_info['notAfter'], ssl_date_fmt)
    date = []
    ts = str(exprirationdate)
    ts = ts.replace("-", ",")
    ts = ts.replace(" ", ",")
    ts = ts.replace(":", ",")
    Ig = [i for i in ts.split(",")]
    date.extend([int(i) for i in Ig])
    dt = datetime.datetime(int(date[0]), int(date[1]), int(date[2]), int(date[3]), int(date[4]), int(date[5]))
    exp_timestemp = float(time.mktime(dt.timetuple()))
    exprirationdate = str(exprirationdate)
    return exp_timestemp, exprirationdate

def getgrade(payload, num, opts):

    API_url = 'https://api.ssllabs.com/api/v2/analyze?'
    response = requests.get(API_url, params=payload)
    status = response.json()["status"]
    
    #response = urllib2.urlopen("%s%s"%(API_url, urllib.urlencode(payload)))
    #status = json.load(response)["status"]
    
    if status != "READY" and num == 2:
        time.sleep(opts.sleep)
        response = requests.get(API_url, params=payload)
        status = response.json()["status"]
        #response = urllib2.urlopen("%s%s"%(API_url, urllib.urlencode(payload)))
        #status = json.load(response)["status"]
    elif status == "READY":
        response = requests.get(API_url, params=payload)
        message = response.json()["endpoints"][0]
        #response = urllib2.urlopen("%s%s"%(API_url, urllib.urlencode(payload)))
        #message = json.load(response)["endpoints"][0]
        if message["statusMessage"] == "No secure protocols supported":
            print(message["statusMessage"])
            sys.exit(ExitCritical)  
        elif message["statusMessage"] == "Ready":
            response = requests.get(API_url, params=payload)
            grade = response.json()["endpoints"][0]
            #response = urllib2.urlopen("%s%s"%(API_url, urllib.urlencode(payload)))
            #grade = json.load(response)["endpoints"][0]
            grade = str((grade["grade"]))
            return (grade)
        else:
            return False

    else:
        return False

def getcacheresult(opts, publish='off', startNew='off', fromCache='on', all='done'):
    payload = {
        "host": opts.domain,
        "publish": publish,
        "startNew": startNew,
        "fromCache": fromCache,
        "all": all}
    num = 1
    grade = getgrade(payload, num, opts)
    
    return grade

def getnewScanresult(opts, publish="off", startNew="on", all="done", ignoreMismatch="on"):
    payload = {
        "host": opts.domain,
        "publish": publish,
        "startNew": startNew,
        "all": all,
        "ignoreMismatch": ignoreMismatch}
    num = 2
    grade = getgrade(payload, num, opts)
    return grade    

def scan(opts):
    grade = (getcacheresult(opts))
    if not grade:
        grade = getnewScanresult(opts)
        return grade
    else:
        return grade   

def testssl(opts):
    result = scan(opts)
    expiry_datetime = (ssl_expiry_datetime(opts.domain))
    current_date = time.time()
    difftime = expiry_datetime[0] - current_date
    timetoexpire = difftime/60/60/24

    try:
        grade = []
        grade.extend([i for i in result.split(",")])
    except:
        grade = False
        
    if not opts.critical or not opts.warning:
        critical = ["E+","E-","E","F+","F-","F","T","M"]
        warning = ["C+","C-","C","D+","D-","D"]

    else:
        try:
            critical=[]
            warning = []
            critical.extend([i for i in opts.critical.split(",")])
            warning.extend([i for i in opts.warning.split(",")])         
        except:
            sys.exit(ExitUnknown)
     
    if grade:
        if list(set(grade).intersection(critical)):
            if timetoexpire <= 0:
                print('SSLLABS grade for %s is %s, the ssl certificate expired on %s'%(opts.domain, grade[0], expiry_datetime[1]))
                sys.exit(exitcode)
            else:
                print('SSLLABS grade for %s is %s, ssl certificate expires in %s days'%(opts.domain, grade[0], int(timetoexpire)))
                sys.exit(ExitCritical)
            
        elif list(set(grade).intersection(warning)):
            if timetoexpire <= 0:
                exitcode = 2
                print('SSLLABS grade for %s is %s, the ssl certificate expired on %s'%(opts.domain, grade[0], expiry_datetime[1]))
                sys.exit(exitcode)
            else:
                exitcode = 1
            print('SSLLABS grade for %s is %s, ssl certificate expires in %s days'%(opts.domain, grade[0], int(timetoexpire)))
            sys.exit(exitcode)
            
        else:
            if timetoexpire <= 0:
                exitcode = 2
                print('SSLLABS grade for %s is %s, the ssl certificate expired on %s'%(opts.domain, grade[0], expiry_datetime[1]))
                sys.exit(exitcode)
            elif timetoexpire <= opts.days:
                exitcode = 1
            else:
                exitcode = 0
            print('SSLLABS grade for %s is %s, ssl certificate expires in %s days'%(opts.domain, grade[0], int(timetoexpire)))
            sys.exit(exitcode)
        
    else:
        print("Can't check SSL settings in %s"%opts.domain)
        sys.exit(ExitUnknown)
           
def main():
    parser = OptionParser("usage: %prog [options] ARG1 ARG2 ARG3 FOR EXAMPLE: -H www.ciencias.ulisboa.pt, -c E+,E-,E,F+,F-,F,T,M -w C+,C-,C,D+,D-,D")
    parser.add_option("-H","--domain", dest="domain", default=False, help="Domain name for check ssl")
    parser.add_option("-c","--critical", dest="critical", type=str, default=False,
                      help="Specify all value for ssllabs grade yo considered critical, Ex. -c T,M,E+,E-,E,F+,F-,F")
    parser.add_option("-w","--warning", dest="warning", default=False,
                      help="Specify all value for ssllabs grade yo considered warning, Ex. -w C+,C-,C,D+,D-,D")
    parser.add_option("-s","--sleep", dest="sleep", default=45,type=int,
                      help="Specify the number of seconds you want to wait, if not found the result in cache, the defoult value is 45 seconds")
    parser.add_option("-d","--days", dest="days", default=30,type=int,
                      help="specify how many days before it expires will be considered warning, the defoult value is 30 days")
    parser.add_option("-V","--version", action="store_true", dest="version", help="This option show the current version number of the program and exit")
    parser.add_option("-A","--author", action="store_true", dest="author", help="This option show author information and exit")
    (opts, args) = parser.parse_args()
    
    if opts.author:
        print(__author__)
        sys.exit()
    if opts.version:
        print("check_ssl.py %s"%__version__)
        sys.exit()
    if opts.domain == False:
        parser.error("Please, this program requires domain arguments, -H www.ciencias.ulisboa.pt")

    testssl(opts)

if __name__ == '__main__':
    main()
