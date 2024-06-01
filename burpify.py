import xml.etree.ElementTree as ET
import sys
import argparse
import base64
import requests
import urllib3

# To disable 'InsecureRequestWarning' warning
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(description="Parse Burp Suite XML file to modify and send HTTP requests")
parser.add_argument("-b", "--burp-xml", help="Path to the Burp Suite XML file")
parser.add_argument("-k", "--header-key", help="Key of the header to modify")
parser.add_argument("-d", "--new-header-value-direct", help="New header value (direct input)")
parser.add_argument("-f","--new-header-value-file",help="Path to the file containing the new header value",)
parser.add_argument("-a", "--add-header", action="store_true", help="Add the header if it doesn't exist")
parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://localhost:8080)")
parser.add_argument("-v","--view",help='What to view in the response (multiple views can be separated by comma, e.g., "status,headers"). Possible values: [status, headers, body, length, all, none]',default="status",)
args = parser.parse_args()

allowed_views = ["status", "headers", "body", "length", "all", "none"]
user_views = [view.strip() for view in args.view.split(",")]
for view in user_views:
    if view not in allowed_views:
        print(
            f"Error: Invalid --view argument: '{view}' (choose from {', '.join(allowed_views)})"
        )
        sys.exit(1)

if args.header_key:
    if not args.new_header_value_direct and not args.new_header_value_file:
        print("Error: If -k is provided, either -d or -f must also be provided.")
        sys.exit(1)

if args.new_header_value_direct or args.new_header_value_file:
    if not args.header_key:
        print("Error: -d or -f requires -k to be specified.")
        sys.exit(1)

if args.new_header_value_file:
    with open(args.new_header_value_file, "r", encoding="utf-8") as file:
        new_header_value = file.read().strip()
elif args.new_header_value_direct:
    new_header_value = args.new_header_value_direct

CRLF = "\n"

DEFAULT_HTTP_VERSION = "HTTP/1.1"


class RequestParser(object):
    def __parse_request_line(self, request_line):
        request_parts = request_line.split(" ")
        self.method = request_parts[0]
        self.url = request_parts[1]
        self.protocol = (
            request_parts[2] if len(request_parts) > 2 else DEFAULT_HTTP_VERSION
        )

    def __init__(self, req_text):
        req_lines = req_text.split(CRLF)
        self.__parse_request_line(req_lines[0])
        ind = 1
        self.headers = dict()
        while ind < len(req_lines) and len(req_lines[ind]) > 0:
            colon_ind = req_lines[ind].find(":")
            header_key = req_lines[ind][:colon_ind].strip()
            header_value = req_lines[ind][colon_ind + 1 :].strip()
            self.headers[header_key] = header_value.strip()
            ind += 1
        ind += 1
        self.data = req_lines[ind:] if ind < len(req_lines) else None
        if self.data:
            self.body = CRLF.join(self.data)

    def __str__(self):
        headers = CRLF.join(f"{key}: {self.headers[key]}" for key in self.headers)
        return (
            f"{self.method} {self.url} {self.protocol}{CRLF}"
            f"{headers}{CRLF}{CRLF}{self.body}"
        )

    def to_request(self):
        host = self.headers["Host"].strip()
        url = f"https://{host}{self.url}"
        if self.method.lower() in ["get", "head"]:
            req = requests.Request(
                method=self.method,
                url=url,
                headers=self.headers,
            )
        else:
            req = requests.Request(
                method=self.method,
                url=url,
                headers=self.headers,
                data=self.body,
            )

        return req


view_map = {
    "status": lambda response: f"Status Code: {response.status_code}",
    "headers": lambda response: "Headers:\n" + "\n".join(f"{header}: {value}" for header, value in response.headers.items()),
    "body": lambda response: f"Response Content:\n{response.text}",
    "length": lambda response: f"Content-Length: {response.headers.get('Content-Length', 'N/A')}",
    "all": lambda response: f"Status Code: {response.status_code}\n" + "Headers:\n" + "\n".join(f"{header}: {value}" for header, value in response.headers.items()) + f"\nResponse Content:\n{response.text}",
}

if args.burp_xml:
    mytree = ET.parse(args.burp_xml)
    root = mytree.getroot()

    with requests.Session() as session:
        if args.proxy:
            session.proxies = {"http": args.proxy, "https": args.proxy}
            VERIFY = False
        else:
            VERIFY = True

        for index, issue in enumerate(root.findall("item")):
            base64_encoded = issue.find("request").attrib['base64']
            http_request = issue.find("request").text

            if base64_encoded == "true":
                base64_http_request = issue.find("request").text
                http_request = base64.b64decode(base64_http_request).decode(encoding="utf-8")
                CRLF = "\r\n"

            rp = RequestParser(http_request)

            if args.header_key:
                if args.header_key in rp.headers:
                    rp.headers[args.header_key] = new_header_value
                elif args.add_header:
                    rp.headers[args.header_key] = new_header_value

            req = rp.to_request()
            prepared_request = req.prepare()
            response = session.send(prepared_request, verify=VERIFY)

            if args.view:
                output = [rp.url]
                views = [view.strip() for view in args.view.split(",")]
                for view in views:
                    if view in view_map:
                        output.append(f"{[view_map[view](response)]}")
                    else:
                        print(f"Error: Invalid --view argument: {view}")
                print(" ".join(output))
else:
    print("Error: --burp-xml argument is required.")
    sys.exit(1)
