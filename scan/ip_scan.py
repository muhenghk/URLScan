import requests
import socket
import re
import whois
import random

# 请求头库
def headers_lib():
    lib = ["Mozilla/5.0 (Macintosh; Intel Mac OS X 10.10; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.11; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.12; rv:58.0) Gecko/20100101 Firefox/58.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:25.0) Gecko/20100101 Firefox/25.0",
           "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36 OPR/50.0.2762.58",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.84 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.121 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0",
           "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:58.0) Gecko/20100101 Firefox/58.0"]
    headers = {
        "User-Agent": random.choice(lib)}
    return headers

# 获取ip地址所属位置
def check_ip(ip):
    ip_list = []
    for i in ip:
        url = "https://ip.cn/ip/{}.html".format(i)
        res = requests.get(url=url, timeout=10, headers=headers_lib())
        html = res.text
        site = re.findall('<div id="tab0_address">(.*?)</div>', html, re.S)[0]
        result ="{} {}".format(i, site).replace("  ", " ").replace(" ", " ")
        ip_list.append(result)
    return ip_list


# 格式化url
def check_url(url):
    if "https://" in url or "http://" in url:
        url = url.replace("https://", "").replace("http://", "")
    domain = "{}".format(url).split("/")[0]
    return domain


# 判断输入是IP还是域名
def isIP(str):
    try:
        check_ip = re.compile(
            '^(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|[1-9])\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)\.(1\d{2}|2[0-4]\d|25[0-5]|[1-9]\d|\d)$')
        if check_ip.match(str):
            return True
        else:
            return False
    except:
        return False


# 获取网站whois等基本信息
def get_base_info(url):
    domain_url = check_url(url)
    ip = []
    try:
        addrs = socket.getaddrinfo(domain_url, None)
        for item in addrs:
            if item[4][0] not in ip:
                ip.append(item[4][0])
        if len(ip) > 1:
            print("\033[1;32m[Ip]:\033[0m\033[36m{}\033[0m \033[1;31m PS:CDN may be used\033[0m".format(check_ip(ip)))

        else:
            print("\033[1;32m[Ip]:\033[0m\033[36m{}\033[0m".format(check_ip(ip)[0]))
    except Exception as e:
        print("\033[1;32m[Ip_Error]:\033[0m\033[36m{}\033[0m".format(e))
    if isIP(domain_url):
        url = "https://site.ip138.com/{}/".format(domain_url)
        res = requests.get(url=url, headers=headers_lib())
        html = res.text
        site = re.findall('<span class="date">(.*?)</span><a href="/(.*?)/" target="_blank">(.*?)</a>', html, re.S)
        if len(site) > 0:
            print("\033[1;32m[The bound domain_name]:\033[0m")
            for a, b, c in site:
                print("\033[36m{} {}\033[0m".format(a, b))
    else:
        whois_info = whois.whois(domain_url)
    return ip


# 检测http头是否缺失
def check_head(url):
    if url[:4] == "http":
        return url
    else:
        head = "https://"
        fix_url = head + url
        try:
            res = requests.get(url=url, headers=headers_lib(), verify=False)
            if res.status_code == 200:
                return fix_url
            else:
                return "http://" + url
        except:
            return "http://" + url

# 主程序入口
if __name__ == '__main__':

    url = input("请输入URL：")
    url = check_head(url)
    ip = get_base_info(url)
    address = str(check_ip(ip))
    address = address.replace("'", '').replace("[", '').replace("]", '')
    print(address)