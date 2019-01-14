#!/usr/bin/env python

import requests
import sys
import argparse
import cfscrape
import html2text
import datetime
import ast
import csv
import io
import contextlib
import random

from prettytable import PrettyTable
from IPy import IP
from bs4 import BeautifulSoup

#usage info
def msg(name=None):
    return'''
     __   ______       ______  __    __   _______   ______  __  ___ 
    |  | |   _  \     /      ||  |  |  | |   ____| /      ||  |/  / 
    |  | |  |_)  |   |  ,----'|  |__|  | |  |__   |  ,----'|  '  /  
    |  | |   ___/    |  |     |   __   | |   __|  |  |     |    <   
    |  | |  |        |  `----.|  |  |  | |  |____ |  `----.|  .  \  
    |__| | _|         \______||__|  |__| |_______| \______||__|\__\  
            
    IP_Check checks IPs/Domains for Tor nodes and current apility.io reputation
    USAGE: ip_check.py -h -v -i IPADDY or DOMAIN -l Text File with IPs
        -c CSV_OUTPUT (default is checkedIps.csv) -p PROXY -q
    If you don't specify "-c" it goes to STDOUT in TAB delimited format
    -p Proxies requests to apility to thwart rate limiting
    '''

#ip_check.py by inurdata
#blah blah license stuffs
#checks ips/domains for "bad" and geolocates
#normal output is stdout

#global vars-----------------------------------------
results = {}
proxies = []
tor_project_list = ""
ip_dan_list = ""
default_csv = "checkedIps.csv"

#COOL_COLORS------------------------------------------
class ecolors:
    HEADER = '\033[95m'
    MSG = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

#CLI_ARGS--------------------------------------------
parser = argparse.ArgumentParser(msg())
parser.add_argument('-i','--input',type=str,help="Input IP or Domain")
parser.add_argument('-l','--list',type=argparse.FileType('r'),help="List of IPs or Domains, ONE PER LINE")
parser.add_argument('-c','--csv',type=str,nargs='?',const=default_csv,help="Outputs to CSV, default is checkedIps.csv")
parser.add_argument('-v','--verbose',help="Prints out more detail",action="store_true")
parser.add_argument('-q','--quiet',help="Quiets all output and returns results to checkedIps.csv",action="store_true")
parser.add_argument('-p','--proxy',help="Proxies requests to apility",action="store_true")
parser.parse_args()
if (len(sys.argv) < 2):
    parser.print_usage()
    exit(0)
args = parser.parse_args()

#FUNCTIONS--------------------------------------------
#TODO add proxy ability to all functions
#GET_TOR_LISTS
def getTOR():
    global ip_dan_list
    try:
        print ecolors.MSG + "[#] Getting www.dan.me.uk/torlist ip list" + ecolors.ENDC
        ip_dan_list = requests.get("https://www.dan.me.uk/torlist/")
    except:
        print ecolors.FAIL + "[!] ",ip_dan_list.status_code, ip_dan_list.reason + ecolors.ENDC
    global tor_project_list
    try:
        print ecolors.MSG + "[#] Getting check.torproject.org/exit-addresses ip list" +   ecolors.ENDC
        tor_project_list = requests.get("https://check.torproject.org/exit-addresses")
    except:
        print ecolors.FAIL + "[!] ",tor_project_list.status_code, tor_project_list.reason + ecolors.ENDC

#Get Proxy list
def getProxies():
    global proxies
    proxiesReq = requests.get("https://www.sslproxies.org/")
    soup = BeautifulSoup(proxiesReq.content, 'html.parser')
    table = soup.find(id='proxylisttable')
    for row in table.tbody.find_all('tr'):
        proxies.append({'ip': row.find_all('td')[0].string,'port': row.find_all('td')[1].string})

#create base dictionaries for keys
def validateIP(input):
    try:
        IP(input)
        return True
    except:
        return False

def createDict():
    if args.input:
        if validateIP(args.input) == True:
            results.update({args.input : {"TOR": "UNKNOWN","GLOBAL": "UNKNOWN","BLACKLIST": "UNKNOWN","HOST": "UNKNOWN","IPACTIVITY": "UNKNOWN","COUNTRY": "UNKNOWN","REGION": "UNKNOWN","CITY": "UNKNOWN"}})
        elif args.verbose:
            print ecolors.FAIL + "[!] " + args.input + " is not a valid IP address" + ecolors.ENDC
            exit(1)
    elif args.list:
        for line in args.list:
            if validateIP(line) == True:
                results.update({line.strip() : {"TOR": "UNKNOWN","GLOBAL": "UNKNOWN","BLACKLIST": "UNKNOWN","HOST": "UNKNOWN","IPACTIVITY": "UNKNOWN","COUNTRY": "UNKNOWN","REGION": "UNKNOWN","CITY": "UNKNOWN"}})
            elif args.verbose:
                print ecolors.FAIL + "[!] " + args.input + " is not a valid IP address" + ecolors.ENDC
    else:
        print ecolors.FAIL + "[!] INPUT OR LIST required!" + ecolors.ENDC
        parser.print_usage()
        exit(1)

def checkTorIP(input):
    if args.verbose:
        print ecolors.MSG + "[#] Searching TOR lists for " + input + ecolors.ENDC
    tor_project_check = 0
    dan_tor_check = 0
    for line in tor_project_list.iter_lines():
        if input in line:
            tor_project_check = 1
    for line in ip_dan_list.iter_lines():
        if input in line:
            dan_tor_check = 1
    if (dan_tor_check == 1 or tor_project_check == 1) and args.verbose:
        print ecolors.OKGREEN + "[+] " + input + " is a tor node"
        results[input]["TOR"] = "Yes"
    elif dan_tor_check == 1 or tor_project_check == 1:
        results[input]["TOR"] = "Yes"
    else:
        results[input]["TOR"] = "No"
    return

def repCheck(num):
    if num is 0:
        return "Neutral"
    elif num < 0:
        return "Bad"
    else:
        return "Good"

def checkApility(input):
    apilityURL = "https://apility.io/search/" + str(input)
    request = ""
    if args.verbose:
        print ecolors.MSG + "[#] Searching apility.io for " + input + ecolors.ENDC
    try:
        #proxy request
        #TODO add error handling and delete proxy if bad
        #TODO add ability to specify your own proxy in the cli or proxy list
        if args.proxy:
            index = random.randint(0, len(proxies) - 1)
            proxy = proxies[index]['ip'] + ':' + proxies[index]['ip']
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/41.0.2228.0 Safari/537.36','Referer': 'https://apility.io/'}
            request = requests.get(apilityURL, headers=headers, proxies={"https":proxy.encode('utf-8')})
        #attempt to use cfscrape
        elif cfscrape:
            scraper = cfscrape.create_scraper()
            request = scraper.get(apilityURL)
        #try manual back up plan
        else:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML,like Gecko) Chrome/41.0.2228.0 Safari/537.36','Referer': 'https://apility.io/'}
            request = requests.get(apilityURL, headers=headers)
    except:
        print ecolors.FAIL + "[!] Reputation check failed for " + str(input)
        print "[!] ", request.status_code, request.reason + ecolors.ENDC
        return
    h = html2text.html2text(request.text)
    lines = h.splitlines()
    #CHECK IPS
    for line in lines:
            if "## Global score:" in line:
                results[input]["GLOBAL"] = repCheck(int(line.split()[-1]))
            elif "### IP Blacklists - Score:" in line:
                check = repCheck(int(line.split()[-1]))
                if check is "Bad":
                    results[input]["BLACKLIST"] = "Yes"
                else:
                    results[input]["BLACKLIST"] = "No"
            elif "#### Hostname - Score :" in line:
                check = repCheck(int(line.split()[-1]))
                if check is "Bad":
                    results[input]["HOST"] = "Yes"
                else:
                    results[input]["HOST"] = "No"
            elif "### IP Activity - Score:" in line:
                check = repCheck(int(line.split()[-1]))
                if check is "Bad":
                    results[input]["IPACTIVITY"] = "Yes"
                else:
                    results[input]["IPACTIVITY"] = "No"
            elif "Sorry, you have reached your daily quota." in line:
                print ecolors.FAIL + "[!] DAILY LIMIT REACHED AT APILITY"
                print "[!] Reputation will NOT be checked" + ecolors.ENDC
                print ecolors.MSG "[#] Use '-p' to proxy requests and thwart rate limiting!" + ecolors.ENDC
                return "kill"
    return "go"

def getGeoIP(input):
    geoLocation = ""
    try:
        request = requests.get("https://ipinfo.io/" + input)
        geoLocation = ast.literal_eval(request.text)
    except:
        print ecolors.FAIL + "[!] Can't geo-locate " + input + ecolors.ENDC
        return
    if args.verbose:
        print ecolors.OKGREEN + "[+] " + input + " Geo-locates to " + geoLocation["country"] + " " + geoLocation["region"] + " " + geoLocation["city"] + ecolors.ENDC
    results[input]["COUNTRY"] = geoLocation["country"]
    results[input]["REGION"] = geoLocation["region"]
    results[input]["CITY"] = geoLocation["city"]
    return

#prevent stdout
@contextlib.contextmanager
def nostdout():
    save_stdout = sys.stdout
    sys.stdout = io.BytesIO()
    yield
    sys.stdout = save_stdout

#MAIN-------------------------------------------------
def main():
    try:
        if args.proxy:
            getProxies()
        createDict()
        test = "go"
        for key in results:
            print ecolors.MSG + "[#] Checking " + key + ecolors.ENDC
            checkTorIP(key)
            if test is "go":
                test = checkApility(key)
            getGeoIP(key)
        if not args.csv:
            x = PrettyTable()
            x.field_names = ["IP", "TOR", "GLOBAL_REP", "IP_BLACKLISTED","COUNTRY", "REGION", "CITY"]
            for key in results:
                x.add_row([key,results[key]["TOR"],results[key]["GLOBAL"],results[key]["BLACKLIST"],results[key]["COUNTRY"],results[key]["REGION"],results[key]["CITY"]])
            print ecolors.MSG + "[#] DONE!" + ecolors.ENDC
            print x
            exit(0)
        elif args.quiet or args.csv:
            #OUTPUT TO CSV FILE
            with open(args.csv, 'wb') as csvfile:
                filewriter = csv.writer(csvfile, delimiter=',')
                filewriter.writerow(["DATE", "IP", "TOR", "GLOBAL_REP", "IP_BLACKLISTED", "HOSTNAME_BLACKLISTED", "BAD_ACTIVITY","COUNTRY", "REGION", "CITY"])
                for key in results:
                    filewriter.writerow([str(datetime.datetime.now()), key, results[key]["TOR"], results[key]["GLOBAL"],results[key]["BLACKLIST"], results[key]["HOST"], results[key]["IPACTIVITY"],results[key]["COUNTRY"], results[key]["REGION"], results[key]["CITY"]])
                    print ecolors.MSG + "[#] DONE!" + ecolors.ENDC
                exit(0)
    except Exception as e:
        print ecolors.FAIL + "[!] WOMP WOMP"
        print "[!] " + str(e) + ecolors.ENDC
        exit(1)

#EXECUTE----------------------------------------------
if __name__ == "__main__":
    if args.quiet:
        with nostdout():
            getTOR()
            main()
    else:
        getTOR()
        main()
