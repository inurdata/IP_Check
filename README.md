# IP_Check
Python project to 'learn' me on interacting with web requests and checking tor status, location, and reputation of IP addresses with apility.io. 
```
 __   ______       ______  __    __   _______   ______  __  ___
|  | |   _  \     /      ||  |  |  | |   ____| /      ||  |/  / 
|  | |  |_)  |   |  ,----'|  |__|  | |  |__   |  ,----'|  '  /  
|  | |   ___/    |  |     |   __   | |   __|  |  |     |    <   
|  | |  |        |  `----.|  |  |  | |  |____ |  `----.|  .  \  
|__| | _|         \______||__|  |__| |_______| \______||__|\__\  
```

IP_Check checks IPs/Domains for Tor nodes and current apility.io reputation
```
USAGE: ip_check.py -h -v -i IPADDY or DOMAIN -l Text File with IPs 
        -c CSV_OUTPUT (default is checkedIps.csv) -p PROXY -q
        If you don't specify "-c" it goes to STDOUT in TAB delimited format
        -p Proxies requests to apility to thwart rate limiting
```

EXAMPLES:

General use with verbose mode:
> python ip_check.py -i (IP ADDRESS) -v 
    
Use with a list as input and quiet output:
> python ip_check.py -l (list file) -q
    
Set output as csv file with quiet mode:
> python ip_check.py -i (IP ADDRESS) -c (CSV FILE) -q
    
Use proxies to thwart rate limiting:
> python ip_check.py -i (IP ADDRESS) -p
    
