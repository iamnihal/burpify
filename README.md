<h1 align="center">burpify</h1>
burpify takes a Burp Suite XML file as input, parses it, and modifies the HTTP request headers as specified by the user before sending them.

## But why?
While analyzing a web application, I used Burp Suite to capture all the requests. After consolidating the requests, I wanted to modify specific header values in all requests and send them back to the server to analyze the responses. However, I found no built-in functionality in Burp to achieve this and that's why this tool came into the picture.

# Usage

```bash
python burpify.py --help
```
This will display help for the tool. Here are all the switches it supports.

```yaml
usage: burpify.py [-h] [-b BURP_XML] [-k HEADER_KEY] [-d NEW_HEADER_VALUE_DIRECT] [-f NEW_HEADER_VALUE_FILE] [-a] [-p PROXY] [-v VIEW]

Parse Burp Suite XML file to modify and send HTTP requests

options:
  -h, --help            show this help message and exit
  -b BURP_XML, --burp-xml BURP_XML
                        Path to the Burp Suite XML file
  -k HEADER_KEY, --header-key HEADER_KEY
                        Key of the header to modify
  -d NEW_HEADER_VALUE_DIRECT, --new-header-value-direct NEW_HEADER_VALUE_DIRECT
                        New header value (direct input)
  -f NEW_HEADER_VALUE_FILE, --new-header-value-file NEW_HEADER_VALUE_FILE
                        Path to the file containing the new header value
  -a, --add-header      Add the header if it doesn't exist
  -p PROXY, --proxy PROXY
                        Proxy URL (e.g., http://localhost:8080)
  -v VIEW, --view VIEW  What to view in the response (multiple views can be separated by comma, e.g., "status,headers"). Possible values: [status, headers, body, length, all, none]
```
#### Credit: [To this 4-year-old gist](https://gist.github.com/cunla/c074179a587c0d012229ee8cc5c04a8c)
