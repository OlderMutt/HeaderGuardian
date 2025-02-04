
**HeaderGuardian** is a Python script that checks HTTP security headers against recommended values according to OWASP guidelines. It helps ensure that your web application is configured with the appropriate security headers to protect against various security threats.



## Features

- **Checks for the presence and correctness of recommended HTTP security headers**
- **Supports different HTTP methods (GET, POST, PUT, PATCH, DELETE)**
- **Supports authenticated connections using cookies**
- **Displays results with color-coded outputs for easy interpretation**
- **Supports import and parse HTTP requests from Burp Suite exported XML files.

## Prerequisites

- **Python 3.x**: Make sure Python 3 is installed on your system.
- **pip**: Ensure you have `pip3` installed for Python package management.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/OlderMutt/HeaderGuardian.git
   cd HeaderGuardian
   
2. **Install Dependencies**

    ```bash
   pip3 install -r requirements.txt

## Usage

1. Run the Script

    ```bash
   python3 HeaderGuardian.py

2. Input Required Information

- Enter the URL to check: Provide the URL of the website you want to analyze (ex. https://your_site.com/).
- Enter the HTTP method: Specify the HTTP method to use (GET, POST, PUT, PATCH, DELETE).
- Enter session cookie (optional): If authentication is needed, provide the session cookie.
- Enter request body data (optional): For methods like POST, PUT, PATCH, provide the request body data.

3. View Results

  The script will display:

- HTTP Response Headers: Shows all response headers received from the server.
- Missing Headers: Lists headers that are missing from the response, highlighted in red.
- Incorrect Headers: Lists headers that are present but do not match the recommended values, highlighted in orange.
- Correct Headers: Lists headers that match the recommended values, highlighted in green.
- Headers to be deleted: Lists headers that must be deleted.

## Examples

![image](https://github.com/user-attachments/assets/ac65fca6-7426-47fe-b167-79cc846603c2)
![image](https://github.com/user-attachments/assets/633bd326-99c8-45d5-86e2-97b20193f38e)

## Usage with Burpsuite xml exported request

1. Run the Script

    ```bash
   python3 HeaderGuardian.py -r req.txt

## References

This script follows recommendations for HTTP security headers from OWASP. For more details on best practices for HTTP headers, please refer to the '[OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)'.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your improvements or bug fixes.

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

## Contact

For any questions or issues, please contact oldermutt@proton.me

