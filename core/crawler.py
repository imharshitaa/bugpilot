"""Safe in-scope crawling and endpoint discovery."""

import re
from urllib.parse import urlsplit

from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, utils):
        self.utils = utils
        crawler_cfg = utils.settings.get("crawler", {})
        self.max_depth = crawler_cfg.get("max_depth", 1)
        self.max_links = crawler_cfg.get("max_links", 40)

    def extract_links(self, html, base_url):
        """Extract <a href>, <link>, <script src>, and simple href regex matches."""
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

    def _is_same_host(self, base_url, candidate_url):
        return urlsplit(base_url).netloc == urlsplit(candidate_url).netloc

    def crawl(self, base_url):
        """Crawl recursively up to configured depth and link limits."""
        discovered = {base_url}
        queue = [(base_url, 0)]

        while queue and len(discovered) < self.max_links:
            url, depth = queue.pop(0)
            if depth >= self.max_depth:
                continue

            resp = self.utils.http_request(url)
            if not resp or resp.status_code >= 500:
                continue

            links = self.extract_links(resp.text, url)

            for link in links:
                if not self._is_same_host(base_url, link):
                    continue
                if link not in discovered and len(discovered) < self.max_links:
                    discovered.add(link)
                    queue.append((link, depth + 1))

        return list(discovered)
