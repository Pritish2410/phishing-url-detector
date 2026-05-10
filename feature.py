from urllib.parse import urlparse, parse_qs
import ipaddress
import re
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import tldextract

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        try:
            self.urlparse = urlparse(url)
            self.hostname = self.urlparse.hostname if self.urlparse.hostname else ''
            self.path = self.urlparse.path
            self.query = self.urlparse.query
            self.extracted = tldextract.extract(url)
            self.domain = self.extracted.domain
        except Exception:
            self.urlparse, self.hostname, self.path, self.query, self.extracted, self.domain = None, '', '', '', None, ''
        
        self.features = []
        self.response = None
        self.soup = None

        try:
            
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
            self.response = requests.get(url, timeout=5, headers=headers)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        self.generate_features()

    def generate_features(self):
        self.features.append(self.num_dots())
        self.features.append(self.subdomain_level())
        self.features.append(self.path_level())
        self.features.append(self.url_length())
        self.features.append(self.num_dash())
        self.features.append(self.num_dash_in_hostname())
        self.features.append(self.at_symbol())
        self.features.append(self.tilde_symbol())
        self.features.append(self.num_underscore())
        self.features.append(self.num_percent())
        self.features.append(self.num_query_components())
        self.features.append(self.num_ampersand())
        self.features.append(self.num_hash())
        self.features.append(self.num_numeric_chars())
        self.features.append(self.no_https())
        self.features.append(self.random_string())
        self.features.append(self.ip_address())
        self.features.append(self.domain_in_subdomains())
        self.features.append(self.domain_in_paths())
        self.features.append(self.https_in_hostname())
        self.features.append(self.hostname_length())
        self.features.append(self.path_length())
        self.features.append(self.query_length())
        self.features.append(self.double_slash_in_path())
        self.features.append(self.num_sensitive_words())
        self.features.append(self.embedded_brand_name())
        self.features.append(self.pct_ext_hyperlinks())
        self.features.append(self.pct_ext_resource_urls())
        self.features.append(self.ext_favicon())
        self.features.append(self.insecure_forms())
        self.features.append(self.relative_form_action())
        self.features.append(self.ext_form_action())
        self.features.append(self.abnormal_form_action())
        self.features.append(self.pct_null_self_redirect_hyperlinks())
        self.features.append(self.frequent_domain_name_mismatch())
        self.features.append(self.fake_link_in_status_bar())
        self.features.append(self.right_click_disabled())
        self.features.append(self.pop_up_window())
        self.features.append(self.submit_info_to_email())
        self.features.append(self.iframe_or_frame())
        self.features.append(self.missing_title()) 
        self.features.append(self.images_only_in_form())
        self.features.append(self.subdomain_level_rt())
        self.features.append(self.url_length_rt())
        self.features.append(self.pct_ext_resource_urls_rt())
        self.features.append(self.abnormal_ext_form_action_rt())
        self.features.append(self.ext_meta_script_link_rt())
        self.features.append(self.pct_ext_null_self_redirect_hyperlinks_rt())

    # Feature implementations
    def num_dots(self): return self.url.count('.')
    def subdomain_level(self): return len(self.hostname.split('.')) - 2
    def path_level(self): return self.path.count('/')
    def url_length(self): return len(self.url)
    def num_dash(self): return self.url.count('-')
    def num_dash_in_hostname(self): return self.hostname.count('-')
    def at_symbol(self): return 1 if '@' in self.url else 0
    def tilde_symbol(self): return 1 if '~' in self.url else 0
    def num_underscore(self): return self.url.count('_')
    def num_percent(self): return self.url.count('%')
    def num_query_components(self): return len(parse_qs(self.query))
    def num_ampersand(self): return self.url.count('&')
    def num_hash(self): return self.url.count('#')
    def num_numeric_chars(self): return sum(c.isdigit() for c in self.url)
    def no_https(self): return 1 if self.urlparse and self.urlparse.scheme != 'https' else 0
    def random_string(self): return 1 if re.search(r'[0-9a-f]{10,}', self.url) else 0
    def ip_address(self):
        try:
            ipaddress.ip_address(self.hostname)
            return 1
        except:
            return 0
    def domain_in_subdomains(self): return 1 if self.extracted and self.extracted.domain in self.extracted.subdomain else 0
    def domain_in_paths(self): return 1 if self.domain and self.domain in self.path else 0
    def https_in_hostname(self): return 1 if 'https' in self.hostname else 0
    def hostname_length(self): return len(self.hostname)
    def path_length(self): return len(self.path)
    def query_length(self): return len(self.query)
    def double_slash_in_path(self): return 1 if '//' in self.path else 0
    def num_sensitive_words(self):
        if not self.response: return 0
        words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm', 'password']
        return sum(self.response.text.lower().count(word) for word in words)
    def embedded_brand_name(self): return 0
    def _get_all_urls(self):
        if not self.soup: return []
        urls = []
        for a in self.soup.find_all('a', href=True): urls.append(a['href'])
        for img in self.soup.find_all('img', src=True): urls.append(img['src'])
        for script in self.soup.find_all('script', src=True): urls.append(script['src'])
        for link in self.soup.find_all('link', href=True): urls.append(link['href'])
        return urls
    def pct_ext_hyperlinks(self):
        if not self.soup: return 0.0
        links = [a.get('href', '') for a in self.soup.find_all('a', href=True)]
        if not links: return 0.0
        ext_count = sum(1 for link in links if tldextract.extract(link).domain != self.domain)
        return (ext_count / len(links)) * 100 if links else 0.0
    def pct_ext_resource_urls(self):
        if not self.soup: return 0.0
        resources = [tag.get('src') or tag.get('href', '') for tag in self.soup.find_all(['img', 'script', 'link'])]
        if not resources: return 0.0
        ext_count = sum(1 for res in resources if tldextract.extract(res).domain != self.domain)
        return (ext_count / len(resources)) * 100 if resources else 0.0
    def ext_favicon(self):
        if not self.soup: return 0
        for link in self.soup.find_all('link', rel=re.compile(r'icon', re.I)):
            if tldextract.extract(link.get('href', '')).domain != self.domain:
                return 1
        return 0
    def insecure_forms(self):
        if not self.soup: return 0
        return 1 if self.soup.find('form', action=re.compile(r'^http://', re.I)) else 0
    def relative_form_action(self):
        if not self.soup: return 0
        return 1 if self.soup.find('form', action=re.compile(r'^(?!http)')) else 0
    def ext_form_action(self):
        if not self.soup: return 0
        for form in self.soup.find_all('form', action=True):
            if tldextract.extract(form['action']).domain != self.domain:
                return 1
        return 0
    def abnormal_form_action(self):
        if not self.soup: return 0
        return 1 if self.soup.find('form', action=re.compile(r'^(about:blank|#)', re.I)) else 0
    def pct_null_self_redirect_hyperlinks(self):
        if not self.soup: return 0.0
        links = [a.get('href', '') for a in self.soup.find_all('a', href=True)]
        if not links: return 0.0
        null_count = sum(1 for link in links if link in ['#', ''] or self.hostname in link)
        return (null_count / len(links)) * 100 if links else 0.0
    def frequent_domain_name_mismatch(self): return 0
    def fake_link_in_status_bar(self):
        if not self.response: return 0
        return 1 if re.search(r"onmouseover\s*=\s*['\"]window.status", self.response.text, re.I) else 0
    def right_click_disabled(self):
        if not self.response: return 0
        return 1 if re.search(r"event.button\s*==\s*2", self.response.text) else 0
    def pop_up_window(self):
        if not self.response: return 0
        return 1 if re.search(r'window.open\(', self.response.text, re.I) else 0
    def submit_info_to_email(self):
        if not self.soup: return 0
        return 1 if self.soup.find('form', action=re.compile(r'^mailto:', re.I)) else 0
    def iframe_or_frame(self):
        if not self.soup: return 0
        return 1 if self.soup.find_all(['iframe', 'frame']) else 0
    def missing_title(self):
        if not self.soup: return 1
        if not self.soup.title: return 1
        if not self.soup.title.string or not self.soup.title.string.strip():
            return 1
        return 0
    def images_only_in_form(self): return 0
    def subdomain_level_rt(self):
        level = self.subdomain_level()
        return 1 if level > 1 else (0 if level == 1 else -1)
    def url_length_rt(self):
        length = self.url_length()
        return 1 if length > 75 else (0 if 54 <= length <= 75 else -1)
    def pct_ext_resource_urls_rt(self):
        pct = self.pct_ext_resource_urls()
        return 1 if pct > 61 else (0 if 22 <= pct <= 61 else -1)
    def abnormal_ext_form_action_rt(self): return 0
    def ext_meta_script_link_rt(self): return 0
    def pct_ext_null_self_redirect_hyperlinks_rt(self):
        pct = self.pct_null_self_redirect_hyperlinks()
        return 1 if pct > 67 else (0 if 31 <= pct <= 67 else -1)

    def get_features_list(self):
        return self.features