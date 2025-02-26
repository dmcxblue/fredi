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
'''
import argparse
from flask import Flask, request, Response
import requests
from urllib.parse import urlparse
import urllib3

app = Flask(__name__)
TARGET_SERVER = ""
ALLOWED_ENDPOINTS = None  # List of endpoints to forward; if None, all routes are forwarded

# Let's add all just to be safe

@app.route('/', defaults={'path': ''}, methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
@app.route('/<path:path>', methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
def proxy(path):
    # Always decode query string so it's available for later
    qs = request.query_string.decode("utf-8")
    
    # If ALLOWED_ENDPOINTS is set, only forward if the request path is allowed.
    if ALLOWED_ENDPOINTS is not None:
        allowed = False
        # Build the full request: path plus query string (if any)
        full_req = request.path if not qs else f"{request.path}?{qs}"
        for endpoint in ALLOWED_ENDPOINTS:
            endpoint = endpoint.strip()
            # I use the "?" as a placeholder because it is really common to see this one but we can add more like @, #, $, % if needed
            if "?" in endpoint:
                # For endpoints containing a query string, require an exact match.
                if full_req == endpoint:
                    allowed = True
                    break
            else:
                # Otherwise, allow if the request path starts with the allowed endpoint.
                if request.path.startswith(endpoint):
                    allowed = True
                    break
        if not allowed:
            try:
                # Attempt to read the custom HTML error page.
                with open("custom404.html", "r") as f:
                    html = f.read()
            except Exception as e:
                # Fallback HTML if the file is not found.
                html = "<html><head><title>404 Not Found</title></head><body><h1>Endpoint not allowed</h1></body></html>"
            return Response(html, status=404, mimetype="text/html")
    
    # Construct the URL to forward the request to
    if qs:
        url = f"{TARGET_SERVER.rstrip('/')}/{path}?{qs}"
    else:
        url = f"{TARGET_SERVER.rstrip('/')}/{path}"

    headers = {key: value for key, value in request.headers if key.lower() != 'host'}

    try:
        # Forward the request to the target server.
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            data=request.get_data(),
            cookies=request.cookies,
            allow_redirects=False,
            stream=True,
            # Verify should be false to accept all traffic
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
    args = parser.parse_args()

    # Check if the target includes a scheme; if not, assume 'https://'
    if not urlparse(args.target).scheme:
        args.target = "https://" + args.target

    # If no port is provided in the target, append the custom port.
    # This is a simple check: if the part after '://' does not contain a colon, append the port.
    target_no_scheme = args.target.split("://")[1]
    if ":" not in target_no_scheme:
        args.target = args.target + f":{args.port}"

    TARGET_SERVER = args.target

    # Parse allowed endpoints if provided.
    if args.endpoints:
        ALLOWED_ENDPOINTS = [e if e.startswith("/") else "/" + e for e in args.endpoints.split(",")]

    print(f"Redirecting all requests to: {TARGET_SERVER}")
    if ALLOWED_ENDPOINTS:
        print(f"Only forwarding requests to the following endpoints: {ALLOWED_ENDPOINTS}")
    # Disable warnings, I know the risks
    # https://urllib3.readthedocs.io/en/latest/advanced-usage.html#tls-warnings
    urllib3.disable_warnings()
    app.run(host="0.0.0.0", port=args.port, ssl_context='adhoc')

