# Multi-Threaded Path Traversal Script

Requires **requests** module to be installed:

```
pip install requests
```

* By default, runs 5 requests in parellel, for better speed and reliability
*Has Two debug levels:
  * 1 level just saves the URL,Status code and any information about any files found while fuzzing.
  * 2 level saves all of the above, plus the responses to each requests as well in a separate file
