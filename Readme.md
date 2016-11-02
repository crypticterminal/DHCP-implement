### A simple implement of dhcp client and server 
[![Build Status](https://travis-ci.org/kerol2r20/DHCP-implement.svg?branch=master)](https://travis-ci.org/kerol2r20/DHCP-implement)
### Usage
* Server: ```python3 dhcp.py server```  
It will listen to port 67. And waiting for discover.

* Client: ```python3 dhcp.py client```  
It will send discover package and waiting for offer at port 68(default).
