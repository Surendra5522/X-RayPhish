# Import necessary libraries
import socket
import requests
import platform
from urllib.parse import urlparse
import hashlib
from bs4 import BeautifulSoup
from difflib import SequenceMatcher
import sqlite3

# Define your VirusTotal API key here
VIRUSTOTAL_API_KEY = "186fa250f109fa2b237b511a2fc471ca4cfd1289dca09d51416b59c72fb3ae90"

# Set timeout value for requests
timeout_seconds = 60  # Adjust timeout value as needed

# Function to calculate similarity between two strings
def similar(a, b):
    return SequenceMatcher(None, a, b).ratio()

# Function to check if a URL is a phishing link
def is_phishing(url):
    # Implement a phishing detection logic
    phishing_keywords = ['login', 'account', 'password', 'verify', 'signin', 'secure', 'update', 'bank', 'paypal', 'amazon', 'google', 'bit.ly', 'ipgraber']  # Example phishing keywords
    domain = urlparse(url).netloc.lower()
    path = urlparse(url).path.lower()

    for keyword in phishing_keywords:
        if keyword in domain or keyword in path:
            return True

    return False

# Function to check for irregularities in the URL structure
def url_contains_irregularities(url):
    parsed_url = urlparse(url)

    # Check if the URL contains an IP address instead of a domain name
    if parsed_url.netloc.replace('.', '').isdigit():
        return True

    # Check for long URL paths or parameters
    if len(parsed_url.path) > 50:
        return True

    # Add more checks as needed

    return False

# Function to retrieve server information for a given URL
def get_server_info(url):
    try:
        response = requests.get(url, timeout=timeout_seconds)
        response.raise_for_status()
        server_info = response.headers.get('server')
        ip_address = socket.gethostbyname(urlparse(url).hostname)
        operating_system = platform.platform()
        headers = response.headers
        url_scheme = urlparse(url).scheme
        status_code = response.status_code
        body_length = len(response.content)
        sha256_hash = hashlib.sha256(response.content).hexdigest()

        soup = BeautifulSoup(response.content, 'html.parser')
        meta_tags = {tag.get('name', 'NoName'): tag.get('content', 'NoContent') for tag in soup.find_all('meta', attrs={'name': True})}

        return server_info, ip_address, operating_system, headers, url_scheme, status_code, body_length, sha256_hash, meta_tags
    except requests.exceptions.RequestException as e:
        print("An error occurred while retrieving URL:", str(e))
        return None, None, None, None, None, None, None, None, None
    except socket.gaierror as e:
        print("Failed to resolve IP address for:", url)
        return None, None, None, None, None, None, None, None, None
    except Exception as e:
        print("An unexpected error occurred:", str(e))
        return None, None, None, None, None, None, None, None, None

# Function to check if a URL is a phishing link using VirusTotal API
def is_phishing_virustotal(url):
    try:
        params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
        response = requests.get('https://www.virustotal.com/api/v3/urls', params=params, timeout=timeout_seconds)
        response.raise_for_status()
        data = response.json()
        attributes = data['data']['attributes']
        if 'categories' in attributes:
            categories = attributes['categories']
            if 'phishing' in categories:
                return True
        return False
    except requests.exceptions.RequestException as e:
        print("Error checking URL with VirusTotal:", str(e))
        return False
    except KeyError:
        print("Error parsing response from VirusTotal")
        return False

# Function to check if a URL is a phishing link using Google Safe Browsing API
def is_phishing_google_safe_browsing(url):
    try:
        API_KEY = "AIzaSyCd5ASxM6UFBWoqvH0cPK94LPvJDTXIHcM"
        params = {'client': 'new.py', 'key': API_KEY}
        payload = {'threatInfo': {'threatTypes': ['SOCIAL_ENGINEERING', 'THREAT_TYPE_UNSPECIFIED'], 'platformTypes': ['ANY_PLATFORM'], 'threatEntryTypes': ['URL'], 'threatEntries': [{'url': url}]}}
        response = requests.post('https://safebrowsing.googleapis.com/v4/threatMatches:find', params=params, json=payload)
        data = response.json()
        if 'matches' in data:
            return True
        return False
    except requests.exceptions.RequestException as e:
        print("Error checking URL with Google Safe Browsing:", str(e))
        return False

# Function to initialize the database
def init_database():
    conn = sqlite3.connect('phishing_urls.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS phishing_urls
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 url TEXT,
                 server TEXT,
                 ip_address TEXT,
                 http_headers TEXT,
                 http_response INTEGER,
                 operating_system TEXT,
                 timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    conn.commit()
    conn.close()

# Function to insert a phishing URL into the database
def insert_phishing_url(url, server, ip_address, http_headers, http_response, operating_system):
    conn = sqlite3.connect('phishing_urls.db')
    c = conn.cursor()
    c.execute("INSERT INTO phishing_urls (url, server, ip_address, http_headers, http_response, operating_system) VALUES (?, ?, ?, ?, ?, ?)", (url, server, ip_address, http_headers, http_response, operating_system))
    conn.commit()
    conn.close()

# Function to display all detected phishing URLs from the database
def display_phishing_urls():
    conn = sqlite3.connect('phishing_urls.db')
    c = conn.cursor()
    c.execute("SELECT * FROM phishing_urls")
    phishing_urls = c.fetchall()
    if phishing_urls:
        print("Detected Phishing URLs:")
        for row in phishing_urls:
            print("ID:", row[0])
            print("------------------------")
            print("URL:", row[1])
            print("------------------------")
            print("Server:", row[2])
            print("------------------------")
            print("IP Address:", row[3])
            print("------------------------")
            print("HTTP Headers:", row[4])
            print("------------------------")
            print("HTTP Response:", row[5])
            print("------------------------")
            print("Operating System:", row[6])
            print("------------------------")
            print("Timestamp:", row[7])
            print("---------------------------------------------------")
    else:
        print("No phishing URLs detected.")
    conn.close()

# Main function
def main():
    # Initialize the database
    init_database()
    user_input = input("Enter a URL: ")
    analyze_url(user_input)

# Function to analyze a single URL
def analyze_url(url):
    input_url = url.strip()
    original_url = input_url
    server_info, ip_address, operating_system, headers, url_scheme, status_code, body_length, sha256_hash, meta_tags = get_server_info(input_url)

    if server_info and ip_address and operating_system:
        # Check if the final URL after redirection is different from the input URL
        if original_url != input_url:
            print("The final URL after redirection is different from the input URL. Possible phishing detected!")
            insert_phishing_url(original_url, None, None, None, None, None)  # Insert the original URL into the database
            return

        print("-------------------------------------------------------")
        print("Server:", server_info)
        print("-------------------------------------------------------")
        print("IP Address:", ip_address)
        print("-------------------------------------------------------")
        print("Operating System:", operating_system)
        print("-------------------------------------------------------")
        print(f"{url_scheme.upper()} Headers:")
        for key, value in headers.items():
            print(f"{key}: {value}")
        print("-------------------------------------------------------")
        print("HTTP Response:")
        print("Status Code:", status_code)
        print("Body Length:", body_length)
        print("SHA256:", sha256_hash)
        print("-------------------------------------------------------")
        print("Phishing detection:")
        if is_phishing(input_url) or url_contains_irregularities(input_url) or is_phishing_google_safe_browsing(input_url) or is_phishing_virustotal(input_url):
            print("Phishing link detected!")
            insert_phishing_url(original_url, server_info, ip_address, str(headers), status_code, operating_system)  # Insert the original URL and other details into the database
        else:
            print("No phishing detected.")
        print("-------------------------------------------------------")
        print("HTML Meta Tags and Values:")
        for tag, value in meta_tags.items():
            print(f"{tag}: {value}")
        print("-------------------------------------------------------")

if __name__ == "__main__":
    main()
    display_phishing_urls()  # Display all detected phishing URLs from the database
