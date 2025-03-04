#!/usr/bin/env python3
########################################################
#
#
#  A simple HTTPS redirector using Flask
#
#
########################################################
#
'''
# CHANGELOG:
0.1
    Remove check for certfile and key when using HTTPS libraries?
    Added verify=False to accept all traffic
0.2
    It's simpler to just use SOCAT??
    Accept all routes
0.3
    Remove warnings YOLO
    Simple HTTPS beacon seems to be fully functional
0.4
    Automatically adapt target URL to custom port if not provided by appending the port to the URL
0.5
    Added a third flag to specify endpoints to forward (e.g. "/admin.php,/submit.php?id=882686070")
0.6
    Modified endpoint check to use full request (path + query string) if a query string is specified in an allowed endpoint.
0.7
    Custom HTML error page when endpoint is not allowed.
0.8:
    Added --header parameter to optionally require a specific header for forwarding traffic.
'''
import argparse
from flask import Flask, request, Response
import requests
from urllib.parse import urlparse
import urllib3

app = Flask(__name__)
TARGET_SERVER = ""
ALLOWED_ENDPOINTS = None  # List of endpoints to forward; if None, all routes are forwarded
REQUIRED_HEADER = None    # Tuple of (header_name, expected_value or None)

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    # Always decode query string so it's available for later
    qs = request.query_string.decode("utf-8")

    # Check for required header if provided.
    if REQUIRED_HEADER is not None:
        header_name, expected_value = REQUIRED_HEADER
        actual_value = request.headers.get(header_name)
        if not actual_value or (expected_value is not None and actual_value != expected_value):
            try:
                with open("custom404.html", "r") as f:
                    html = f.read()
            except Exception as e:
                html = "<html><head><title>404 Not Found</title></head><body><h1>Oops Page does not Exist</h1></body></html>"
            return Response(html, status=404, mimetype="text/html")

    # If ALLOWED_ENDPOINTS is set, only forward if the request path is allowed.
    if ALLOWED_ENDPOINTS is not None:
        allowed = False
        # Build the full request: path plus query string (if any)
        full_req = request.path if not qs else f"{request.path}?{qs}"
        for endpoint in ALLOWED_ENDPOINTS:
            endpoint = endpoint.strip()
            if "?" in endpoint:
                if full_req == endpoint:
                    allowed = True
                    break
            else:
                if request.path.startswith(endpoint):
                    allowed = True
                    break
        if not allowed:
            try:
                with open("custom404.html", "r") as f:
                    html = f.read()
            except Exception as e:
                html = "<html><head><title>404 Not Found</title></head><body><h1>Oops Page does not Exist</h1></body></html>"
            return Response(html, status=404, mimetype="text/html")
    
    # Construct the URL to forward the request to.
    if qs:
        url = f"{TARGET_SERVER.rstrip('/')}/{path}?{qs}"
    else:
        url = f"{TARGET_SERVER.rstrip('/')}/{path}"

    headers = {key: value for key, value in request.headers if key.lower() != 'host'}

    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            verify=False
        )
    except requests.exceptions.RequestException as e:
        return Response(f"Error forwarding request: {e}", status=502)

    excluded_headers = ['content-encoding', 'transfer-encoding', 'content-length', 'connection']
    response = Response(resp.content, status=resp.status_code)
    for name, value in resp.raw.headers.items():
        if name.lower() not in excluded_headers:
            response.headers[name] = value

    return response

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Flask HTTPS Redirector Cobalt Strike")
    parser.add_argument("--target", required=True,
                        help="Target server to forward requests to (e.g. https://example.com or 10.10.1.131:443)")
    parser.add_argument("--port", type=int, default=443,
                        help="Local port to listen on (default: 443)")
    parser.add_argument("--endpoints", help='Comma-separated list of endpoints to forward (e.g. "/admin.php,/submit.php?id=882686070")')
    parser.add_argument("--header", help="Optional required header for forwarding requests. Format: 'HeaderName:Value'. If only header name is provided, only its presence is checked.")
    args = parser.parse_args()

    # Check if the target includes a scheme; if not, assume 'https://'
    if not urlparse(args.target).scheme:
        args.target = "https://" + args.target

    # If no port is provided in the target, append the custom port.
    target_no_scheme = args.target.split("://")[1]
    if ":" not in target_no_scheme:
        args.target = args.target + f":{args.port}"

    TARGET_SERVER = args.target

    # Parse allowed endpoints if provided.
    if args.endpoints:
        ALLOWED_ENDPOINTS = [e if e.startswith("/") else "/" + e for e in args.endpoints.split(",")]

    # Parse required header if provided.
    if args.header:
        if ":" in args.header:
            header_name, header_value = args.header.split(":", 1)
            REQUIRED_HEADER = (header_name.strip(), header_value.strip())
        else:
            REQUIRED_HEADER = (args.header.strip(), None)
    
    print(f"Redirecting all requests to: {TARGET_SERVER}")
    if ALLOWED_ENDPOINTS:
        print(f"Only forwarding requests to the following endpoints: {ALLOWED_ENDPOINTS}")
    if REQUIRED_HEADER:
        if REQUIRED_HEADER[1]:
            print(f"Requests must include header '{REQUIRED_HEADER[0]}: {REQUIRED_HEADER[1]}'")
        else:
            print(f"Requests must include header '{REQUIRED_HEADER[0]}'")
    # Disable warnings, I know the risks
    # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
    urllib3.disable_warnings()
    app.run(host="0.0.0.0", port=args.port, ssl_context='adhoc')
