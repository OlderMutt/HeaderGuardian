import requests
from tabulate import tabulate
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# Print ASCII Art Title
ascii_title =r"""
    __  __               __          ______                     ___           
   / / / /__  ____ _____/ /__  _____/ ____/_  ______ __________/ (_)___ _____ 
  / /_/ / _ \/ __ `/ __  / _ \/ ___/ / __/ / / / __ `/ ___/ __  / / __ `/ __ \
 / __  /  __/ /_/ / /_/ /  __/ /  / /_/ / /_/ / /_/ / /  / /_/ / / /_/ / / / /
/_/ /_/\___/\__,_/\__,_/\___/_/   \____/\__,_/\__,_/_/   \__,_/_/\__,_/_/ /_/ 
"""

print(ascii_title)


# Define the recommended security headers and their expected values
recommended_headers = {
    "X-Frame-Options": "DENY",
    "X-XSS-Protection": "0",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains; preload",
    "Content-Security-Policy": "default-src 'self'",  # Example, should be customized
    "Access-Control-Allow-Origin": "https://yoursite.com",  # Example, should be customized
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Embedder-Policy": "require-corp",
    "Cross-Origin-Resource-Policy": "same-site",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
    "X-DNS-Prefetch-Control": "off",
    "Server": "webserver",
    "X-Powered-By": "",
    "X-AspNet-Version": "",
    "X-AspNetMvc-Version": ""
}

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
        if method.upper() == 'GET':
            response = requests.get(url, headers=headers)
        elif method.upper() == 'POST':
            response = requests.post(url, headers=headers, data=data)
        elif method.upper() == 'PUT':
            response = requests.put(url, headers=headers, data=data)
        elif method.upper() == 'PATCH':
            response = requests.patch(url, headers=headers, data=data)
        elif method.upper() == 'DELETE':
            response = requests.delete(url, headers=headers)
        else:
            print(f"{Fore.RED}{Style.BRIGHT}Unsupported HTTP method: {method}")
            return

        response.raise_for_status()  # Raise an HTTPError for bad responses

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

        for header, expected_value in recommended_headers.items():
            actual_value = response_headers.get(header)
            if actual_value is None:
                missing_headers.append([header, expected_value])
            elif expected_value and expected_value not in actual_value:
                incorrect_headers.append([header, actual_value, expected_value])
            else:
                correct_headers.append([header, actual_value])

        if missing_headers:
            print_section("Missing Headers", tabulate(missing_headers, headers=[Fore.CYAN + "Header" + Style.RESET_ALL, Fore.CYAN + "Expected Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.RED)

        if incorrect_headers:
            print_section("Incorrect Headers", tabulate(incorrect_headers, headers=[Fore.CYAN + "Header" + Style.RESET_ALL, Fore.CYAN + "Actual Value" + Style.RESET_ALL, Fore.CYAN + "Expected Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.YELLOW)

        if correct_headers:
            print_section("Correct Headers", tabulate(correct_headers, headers=[Fore.CYAN + "Header" + Style.RESET_ALL, Fore.CYAN + "Actual Value" + Style.RESET_ALL], tablefmt="grid"), color=Fore.GREEN)

        if not missing_headers and not incorrect_headers:
            print(f"{Fore.GREEN}{Style.BRIGHT}All recommended headers are correctly set.")

    except requests.RequestException as e:
        print(f"{Fore.RED}{Style.BRIGHT}Error fetching URL: {e}")

if __name__ == "__main__":
    print(f"{Fore.BLUE}{Style.BRIGHT}Welcome to HeaderGuardian!")
    url_to_check = input("Enter the URL to check: ").strip()
    method = input("Enter the HTTP method (GET, POST, PUT, PATCH, DELETE): ").strip().upper()
    session_cookie = input("Enter session cookie (optional): ").strip()
    data = input("Enter request body data (optional): ").strip()  # For POST, PUT, PATCH methods
    check_security_headers(url_to_check, method, session_cookie, data)
