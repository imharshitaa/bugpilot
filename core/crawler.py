"""Safe in-scope crawling and endpoint discovery."""

import re
from urllib.parse import urljoin, urlsplit

from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, utils):
        self.utils = utils
        crawler_cfg = utils.settings.get("crawler", {})
        self.max_depth = crawler_cfg.get("max_depth", 1)
        self.max_links = crawler_cfg.get("max_links", 40)
        scanner_cfg = utils.settings.get("scanner", {})
        self.include_subdomains = bool(scanner_cfg.get("include_subdomains", True))

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
        base_host = (urlsplit(base_url).hostname or "").lower()
        cand_host = (urlsplit(candidate_url).hostname or "").lower()
        if not base_host or not cand_host:
            return False
        if cand_host == base_host:
            return True
        if self.include_subdomains and cand_host.endswith("." + base_host):
            return True
        return False

    def _seed_from_robots_and_sitemap(self, base_url):
        seeds = set()
        robots_url = urljoin(base_url, "/robots.txt")
        robots_resp = self.utils.http_request(robots_url)
        if robots_resp and robots_resp.status_code < 500:
            for line in robots_resp.text.splitlines():
                line = line.strip()
                lower = line.lower()
                if lower.startswith("sitemap:"):
                    sitemap_url = line.split(":", 1)[1].strip()
                    if sitemap_url.startswith("http"):
                        seeds.add(sitemap_url)
                if lower.startswith("allow:") or lower.startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    if path.startswith("/"):
                        seeds.add(urljoin(base_url, path))

        if not any("sitemap" in s for s in seeds):
            seeds.add(urljoin(base_url, "/sitemap.xml"))
        return list(seeds)

    def crawl(self, base_url):
        """Crawl recursively up to configured depth and link limits."""
        discovered = {base_url}
        queue = [(base_url, 0)]
        for seed in self._seed_from_robots_and_sitemap(base_url):
            if len(discovered) >= self.max_links:
                break
            discovered.add(seed)
            queue.append((seed, 0))

        while queue and len(discovered) < self.max_links:
            url, depth = queue.pop(0)
            if depth >= self.max_depth:
                continue

            resp = self.utils.http_request(url)
            if not resp or resp.status_code >= 500:
                continue

            links = self.extract_links(resp.text, url)
            # Regex hints for API endpoints inside JS/HTML blobs.
            api_hints = re.findall(r'["\'](/api/[A-Za-z0-9_./?-]+)["\']', resp.text)
            for hint in api_hints:
                links.append(urljoin(base_url, hint))

            for link in links:
                if not self._is_same_host(base_url, link):
                    continue
                if link not in discovered and len(discovered) < self.max_links:
                    discovered.add(link)
                    queue.append((link, depth + 1))

        return list(discovered)
