# crawler_module.py

import requests
from bs4 import BeautifulSoup

def crawl_website(domain):
    urls = []

    # Send a GET request to the domain
    response = requests.get(f"http://{domain}")

    # Parse the HTML content of the response using BeautifulSoup
    soup = BeautifulSoup(response.content, "html.parser")

    # Find all anchor tags in the HTML and extract the href attribute
    for link in soup.find_all("a"):
        href = link.get("href")
        if href:
            urls.append(href)

    return urls
