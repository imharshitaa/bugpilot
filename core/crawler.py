"""
crawler.py
-----------
Discovers additional URLs from a base target using: engine - crawling and endpoint discovery
- HTML link extraction
- Script file parsing
- Simple regex-based URL discovery

Only safe crawling is implemented.
"""

import re
from bs4 import BeautifulSoup

class Crawler:
    def __init__(self, utils):
        self.utils = utils
        self.max_depth = utils.settings["scanner"]["max_depth"]

    def extract_links(self, html, base_url):
        """
        Extract <a href>, <link>, <script src>, and simple endpoints from HTML.
        """
        soup = BeautifulSoup(html, "html.parser")
        urls = set()

        # Anchor tags
        for tag in soup.find_all("a", href=True):
            urls.add(self.utils.join_url(base_url, tag["href"]))

        # Script tags
        for tag in soup.find_all("script", src=True):
            urls.add(self.utils.join_url(base_url, tag["src"]))

        # Link tags (CSS, preload, etc.)
        for tag in soup.find_all("link", href=True):
            urls.add(self.utils.join_url(base_url, tag["href"]))

        # Regex discovery (e.g., "/api", "/login")
        pattern_urls = re.findall(r'href=["\'](.*?)["\']', html)
        for u in pattern_urls:
            urls.add(self.utils.join_url(base_url, u))

        return list(urls)

    def crawl(self, base_url):
        """
        Crawls recursively up to max_depth.
        """
        discovered = set([base_url])
        queue = [(base_url, 0)]

        while queue:
            url, depth = queue.pop(0)
            if depth >= self.max_depth:
                continue

            resp = self.utils.http_request(url)
            if not resp or resp.status_code >= 500:
                continue

            links = self.extract_links(resp.text, url)

            for link in links:
                if link not in discovered:
                    discovered.add(link)
                    queue.append((link, depth + 1))

        return list(discovered)

