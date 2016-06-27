# Multi-Threaded Path Traversal Script

Requires **requests** module to be installed:

```
pip install requests
```
* Syntax:
 * Needs a wildcard * to be present in the URL where you want to inject the payloads, example:
 ```
  http://www.example.com/request.php?file=*
 ```
 * The wildcard would automatically be replaced with the payloads during runtime.
 

* By default, runs 5 requests in parallel, for better speed and reliability
* Has Two debug levels:
  * 1 level just saves the URL, Status code and any information about any files found while fuzzing.
  * 2 level saves all of the above, plus the responses to each requests as well in a separate file
