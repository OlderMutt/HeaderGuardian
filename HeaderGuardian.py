import requests
from urllib.parse import urlparse, urlunparse
from tabulate import tabulate
from colorama import Fore, Style, init
import argparse
import base64
import xml.etree.ElementTree as ET

# Initialize colorama
init(autoreset=True)

# Print ASCII Art Title
ascii_title = r"""
    __  __               __          ______                     ___           
   / / / /__  ____ _____/ /__  _____/ ____/_  ______ __________/ (_)___ _____ 
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ / __/ / / / __ `/ ___/ __  / / __ `/ __ \
 / __  /  __/ /_/ / /_/ /  __/ /  / /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / /
/_/ /_/\___/\__,_/\__,_/\___/_/   \____/\__,_/\__,_/_/   \__,_/_/\__,_/_/ /_/ 
"""

print(ascii_title)

# Define the recommended security headers and their expected values (excluding Access-Control-Allow-Origin)
recommended_headers = {
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",  # Example, should be customized
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-site",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "X-DNS-Prefetch-Control": "off"
}

# Headers to be checked for deletion
headers_to_delete = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

def print_section(title, content, color=Fore.BLUE):
    """Print a section with a title and content, separated by a divider."""
    divider = f"{color}{Style.BRIGHT}{'=' * 80}{Style.RESET_ALL}"
    print(f"{divider}\n{color}{Style.BRIGHT}{title}{Style.RESET_ALL}\n{divider}")
    print(content)
    print(divider)

def check_security_headers(url, method='GET', session_cookie=None, data=None):
    try:
        headers = {}
        if session_cookie:
            headers['Cookie'] = session_cookie
        
        # Dispatch the request based on the method
        methods = {
            'GET': requests.get,
            'POST': requests.post,
            'PUT': requests.put,
            'PATCH': requests.patch,
            'DELETE': requests.delete
        }
        
        if method.upper() not in methods:
            print(f"{Fore.RED}{Style.BRIGHT}Unsupported HTTP method: {method}")
            return

        # Ensure URL has a scheme
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
        
        response = methods[method.upper()](url, headers=headers, data=data)
        response.raise_for_status()  # Raise an HTTPError for bad responses

        # Parse the domain from the URL for Access-Control-Allow-Origin
        parsed_url = urlparse(url)
        domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        recommended_headers["Access-Control-Allow-Origin"] = domain

        # Print the full HTTP response details
        print(f"\n{Fore.BLUE}{Style.BRIGHT}HTTP Response from {url}:")
        
        # Print HTTP version and status line
        http_version = f"HTTP/{response.raw.version // 10}.{response.raw.version % 10}"
        status_line = f"{http_version} {response.status_code} {requests.status_codes._codes[response.status_code][0].capitalize()}"
        print(status_line)
        
        # Print headers directly
        headers_content = '\n'.join(f"{header}: {value}" for header, value in response.headers.items())
        print_section("Response Headers", headers_content)

        response_headers = response.headers

        missing_headers = []
        incorrect_headers = []
        correct_headers = []
        delete_headers = []

        for header, expected_value in recommended_headers.items():
            actual_value = response_headers.get(header)
            if actual_value is None:
                missing_headers.append([header, expected_value])
            elif expected_value and expected_value not in actual_value:
                incorrect_headers.append([header, actual_value, expected_value])
            else:
                correct_headers.append([header, actual_value])

        # Check for headers that should be deleted
        for header in headers_to_delete:
            if response_headers.get(header):
                delete_headers.append([header, response_headers.get(header)])

        if missing_headers:
            print_section("Missing Headers", tabulate(missing_headers, headers=[Fore.MAGENTA + "Header" + Style.RESET_ALL, Fore.MAGENTA + "Expected Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.MAGENTA)

        if incorrect_headers:
            print_section("Incorrect Headers", tabulate(incorrect_headers, headers=[Fore.YELLOW + "Header" + Style.RESET_ALL, Fore.YELLOW + "Actual Value" + Style.RESET_ALL, Fore.YELLOW + "Expected Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.YELLOW)

        if correct_headers:
            print_section("Correct Headers", tabulate(correct_headers, headers=[Fore.GREEN + "Header" + Style.RESET_ALL, Fore.GREEN + "Actual Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.GREEN)

        if delete_headers:
            print_section("Headers to be Deleted", tabulate(delete_headers, headers=[Fore.RED + "Header" + Style.RESET_ALL, Fore.RED + "Actual Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.RED)

        if not missing_headers and not incorrect_headers and not delete_headers:
            print(f"{Fore.GREEN}{Style.BRIGHT}All recommended headers are correctly set.")

    except requests.RequestException as e:
        print(f"{Fore.RED}{Style.BRIGHT}Error fetching URL: {e}")

import xml.etree.ElementTree as ET
import base64

import xml.etree.ElementTree as ET
import base64

import xml.etree.ElementTree as ET
import base64
import urllib.parse

def parse_burp_request_file(file_path):
    """Parse the request from a Burp Suite exported XML file.
    
    Args:
        file_path (str): Path to the Burp Suite exported XML file.
    
    Returns:
        tuple: A tuple containing the HTTP method, URL, session cookie, and request body.
               If parsing fails, returns (None, None, None, None).
    """
    try:
        tree = ET.parse(file_path)
        root = tree.getroot()

        for item in root.findall('item'):
            request_data = item.find('request').text
            if request_data is not None and item.find('request').attrib.get('base64', 'false') == 'true':
                request_data = base64.b64decode(request_data).decode('utf-8')

            # Extract URL from the URL element
            base_url = item.find('url').text.strip()

            # Validate the URL
            if not base_url.startswith(('http://', 'https://')):
                raise ValueError(f"Invalid base URL format: {base_url}")

            # Extract method and request URL from the request line
            lines = request_data.split('\n')
            request_line = lines[0].strip()
            parts = request_line.split()

            if len(parts) == 3:
                method, path, _ = parts
            elif len(parts) == 2:
                method, path = parts
            else:
                raise ValueError("Invalid request line format")

            # Construct the full URL
            if path.startswith('/'):
                # If the path is relative, combine it with the base URL
                full_url = urllib.parse.urljoin(base_url, path)
            else:
                # If the path is absolute, use it directly
                full_url = path

            headers = {}
            body = None
            is_body = False

            for line in lines[1:]:
                line = line.strip()
                if is_body:
                    if body is None:
                        body = line
                    else:
                        body += "\n" + line
                elif line == '':
                    is_body = True
                else:
                    if ':' in line:
                        key, value = line.split(":", 1)
                        headers[key.strip()] = value.strip()

            session_cookie = headers.get('Cookie')
            return method, full_url, session_cookie, body
    except ET.ParseError as e:
        print(f"XML parsing error: {e}")
    except base64.binascii.Error as e:
        print(f"Base64 decoding error: {e}")
    except ValueError as e:
        print(f"Value error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")
    
    return None, None, None, None

def main():
    parser = argparse.ArgumentParser(description="Analyze HTTP security headers.")
    parser.add_argument("-r", "--request-file", help="Path to the Burp Suite exported request file", required=False)
    args = parser.parse_args()

    if args.request_file:
        method, url, session_cookie, data = parse_burp_request_file(args.request_file)
        if not url or not method:
            print(f"{Fore.RED}{Style.BRIGHT}Invalid request file format")
            return
        check_security_headers(url, method, session_cookie, data)
    else:
        print(f"{Fore.BLUE}{Style.BRIGHT}Welcome to HeaderGuardian!")
        url_to_check = input("Enter the URL to check: ").strip()
        if not url_to_check:
            print(f"{Fore.RED}{Style.BRIGHT}URL cannot be empty.")
        else:
            method = input("Enter the HTTP method (GET, POST, PUT, PATCH, DELETE): ").strip().upper()
            if method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
                print(f"{Fore.RED}{Style.BRIGHT}Unsupported HTTP method: {method}")
            else:
                session_cookie = input("Enter session cookie (optional): ").strip()
                data = input("Enter request body data (optional): ").strip()  # For POST, PUT, PATCH methods
                check_security_headers(url_to_check, method, session_cookie, data)

if __name__ == "__main__":
    main()
