#!/usr/bin/python
#************************************************************
#multi_fuzzer.py: Simple Multi-Fuzzer.
#************************************************************
#Written by r0otki7 <https://github.com/r0otki7/>
#************************************************************

import requests
import urllib
import threading
import Queue
import sys
import time
import argparse

def main():
#Help
	if len(sys.argv) == 1:
		sys.exit("Usage: "+sys.argv[0]+" -u URL -pr PARAMS  -g/-p -t THROTTLE -x/-s/-pt/-o/-a OPTION\n\nRun "+sys.argv[0]+" -h for detailed help.")
#Declaring globals.
	global url, param, payload_list, f_log, throttle, xss_file, sql_file, path_file, os_file, all_file, body, cookie, get, post, verbose
	
	q = Queue.Queue(maxsize=0)
	q_thread = 5
	payload_list = []
	parser = argparse.ArgumentParser(description="Multi Fuzzer")
	group = parser.add_mutually_exclusive_group()
	group1 = parser.add_mutually_exclusive_group()
	
	parser.add_argument("-u", "--url", type=str, help="Give the URL. Include params for GET request")
	parser.add_argument("-pr", "--params", type=str, help="Give the parameters with * as the injection point for POST query")
	parser.add_argument("-c", "--cookie", type=str, help="Give the cookie value")
	parser.add_argument("-t", "--throttle", type=float, help="Throttling Value (in seconds)")
	parser.add_argument("-v", "--verbose", action="count", help="Show Verbose output, -vv for extensive verbosity")
	group.add_argument("-g", "--get", help="GET request", action="store_true")
	group.add_argument("-p", "--post", help="POST request", action="store_true")
	group1.add_argument("-x", "--xss", help="Fuzz for XSS from a payload file")
	group1.add_argument("-s", "--sql", help="Fuzz for SQLi")
	group1.add_argument("-pt", "--path", help="Path Traversal Fuzzer")
	group1.add_argument("-o", "--os", help="OS Command Injection")
	group1.add_argument("-a", "--all", help="All Payload Injected")	
	
	args = parser.parse_args()
#Initializing globals.	
	url, param, cookie, throttle, get, post, xss_file, sql_file, path_file, os_file, all_file, verbose = args.url, args.params, dict(x.split('=') for x in args.cookie.split(";")), args.throttle, args.get, args.post, args.xss, args.sql, args.path, args.os, args.all, args.verbose
#Log file.
	f_log = open("extensivelog","w")

#Searches for the wildcard in parameter.	
	if get:
		if str(url).find("*") == -1:
			sys.exit("No custom injection point found, Exiting...")
	elif post:
		if str(param).find("*") == -1:
			sys.exit("No custom injection point found, Exiting...")
	
	if xss_file:
		xss()
	elif sql_file:
		sql()
	elif path_file:
		path()
	elif os_file:
		os()
	elif all_file:
		all()

#Processing GET requests in threads and queues.		
	if get:
		for j in range(q_thread):
			threads = threading.Thread(target=getengine, args=(q,))
			threads.setDaemon(True)
			threads.start()
		
		for url_param in payload_list:
			try:
				time.sleep(throttle)
				q.put(url_param)
			except KeyboardInterrupt:
				sys.exit("\nExiting...")
		q.join()

#Processing POST requests in threads and queues.		
	elif post:
		for j in range(q_thread):
			threads = threading.Thread(target=postengine, args=(q,))
			threads.setDaemon(True)
			threads.start()
		
		for url_param in payload_list:
			try:
				time.sleep(throttle)
				q.put(url_param)
			except KeyboardInterrupt:
				sys.exit("\nExiting...")
		q.join()

#Function to process GET requests.		
def getengine(q):
	while True:
		try:
			r = requests.get(q.get(), cookies=cookie, timeout=30, verify=False)
			r_url = r.request.url.encode('utf-8')
			r_status = str(r.status_code)
			r_response_header = str("\n".join("{}: {}".format(k, v) for k, v in r.headers.items())).encode('utf=8')
			if verbose == 1:
				print r_url+"\t"+r_status
			elif verbose == 2:
				print "URL: "+r_url+"\nStatus Code: "+r_status+"\n\n\nResponse:\n"+r_response_header+"\n\n"+r.content.encode('utf-8')+"\n\n\n==================================================================\n\n\n"
			else:
				None
			f_log.write("URL: "+r_url+"\nStatus Code: "+r_status+"\n\n\nResponse:\n"+r_response_header+"\n\n"+r.content.encode('utf-8')+"\n\n\n==================================================================\n\n\n")
			q.task_done()
				
		except requests.exceptions.Timeout:
			print "Request Timed out"
		except requests.exceptions.ConnectionError:
			print "Connection Resetted"

#Function to process POST request.
def postengine(q):
	while True:
		try:
			r = requests.post(url, data=q.get(), cookies=cookie, timeout=30, verify=False)
			r_url = str(r.request.path_url).encode('utf-8')
			r_status = str(r.status_code)
			r_header = str("\n".join("{}: {}".format(k, v) for k, v in r.request.headers.items())).encode('utf=8')
			r_response_header = str("\n".join("{}: {}".format(k, v) for k, v in r.headers.items())).encode('utf=8')
			r_body = str(r.request.body).encode('utf-8')
			if verbose == 1:
				print r.request.url+"\t"+r_body
			elif verbose == 2:
				print "Request: \nPOST "+r_url+" HTTP/1.1\n"+r_header+"\n\n"+r_body+"\n\n\nResponse:\n"+r_response_header+"\n\n"+r.text.encode('utf-8')+"\n\n\n==================================================================\n\n\n"
			else:
				None
			f_log.write("Request: \nPOST "+r_url+" HTTP/1.1\n"+r_header+"\n\n"+r_body+"\n\n\nResponse:\n"+r_response_header+"\n\n"+r.text.encode('utf-8')+"\n\n\n==================================================================\n\n\n")
			q.task_done()
				
		except requests.exceptions.Timeout:
			print "Request Timed out"
		except requests.exceptions.ConnectionError:
			print "Connection Resetted"

#All the functions to fill the payload list.
def xss():
	if get:
		with open(xss_file, "r") as x1:
			for line in x1:
				payload_list.append(str(url).replace("*", urllib.quote(line)))

	elif post:
		with open(xss_file, "r") as x1:
			for line in x1:
				payload_list.append(str(param).replace("*", urllib.quote(line)))		
				
def sql():
	if get:
		with open(sql_file, "r") as s1:
			for line in s1:
				payload_list.append(str(url).replace("*", urllib.quote(line)))

	elif post:
		with open(sql_file, "r") as s1:
			for line in s1:
				payload_list.append(str(param).replace("*", urllib.quote(line)))

def path():
	payloads = ["etc/passwd","C:/Windows/win.ini","C:\Windows\win.ini"]
	for items in payloads:
		for i in range(0,16):
			if get:
				payload_list.append(str(url).replace("*","../"*i+items))
				payload_list.append(str(url).replace("*",(urllib.quote("../", safe='')*i+items)))
				payload_list.append(str(url).replace("*","../"*i+urllib.quote(items, safe='')))
				payload_list.append(str(url).replace("*",(urllib.quote(("../")*i+items, safe=''))))
				payload_list.append(str(url).replace("*","..\\"*i+items))
				payload_list.append(str(url).replace("*",(urllib.quote("..\\", safe='')*i+items)))
				payload_list.append(str(url).replace("*","..\\"*i+urllib.quote(items, safe='')))
				payload_list.append(str(url).replace("*",(urllib.quote(("..\\")*i+items, safe=''))))

			elif get:
				payload_list.append(str(param).replace("*","../"*i+items))
				payload_list.append(str(param).replace("*",(urllib.quote("../", safe='')*i+items)))
				payload_list.append(str(param).replace("*","../"*i+urllib.quote(items, safe='')))
				payload_list.append(str(param).replace("*",(urllib.quote(("../")*i+items, safe=''))))
				payload_list.append(str(param).replace("*","..\\"*i+items))
				payload_list.append(str(param).replace("*",(urllib.quote("..\\", safe='')*i+items)))
				payload_list.append(str(param).replace("*","..\\"*i+urllib.quote(items, safe='')))
				payload_list.append(str(param).replace("*",(urllib.quote(("..\\")*i+items, safe=''))))
def os():
	if get:
		with open(os_file, "r") as o1:
			for line in o1:
				payload_list.append(str(url).replace("*", urllib.quote(line)))

	elif post:
		with open(os_file, "r") as o1:
			for line in o1:
				payload_list.append(str(param).replace("*", urllib.quote(line)))
			
def all():
	if get:
		with open(all_file, "r") as a1:
			for line in a1:
				payload_list.append(str(url).replace("*", urllib.quote(line)))

	elif post:
		with open(all_file, "r") as a1:
			for line in a1:
				payload_list.append(str(param).replace("*", urllib.quote(line)))

if __name__ == '__main__':
	main()
