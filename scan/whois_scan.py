import json
import random
import requests

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

def whois_scan(url):
    whois_url = 'https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=at_jJNZcbgEqiLvoaJ0SM2s5s7YHieOT&domainName={}&outputFormat=json'.format(
        url)
    r = requests.get(whois_url)
    whois_json = json.loads(r.text)
    whois_registrar = whois_json['WhoisRecord']['registrarName']  # 注册商
    whois_registrarAbuseContactEmail = whois_json['WhoisRecord']['contactEmail']  # 注册邮箱
    whois_registrarWHOISServer = whois_json['WhoisRecord']['registryData']['whoisServer']  # 注册商whois服务器
    whois_nameServer = whois_json['WhoisRecord']['nameServers']['hostNames']  # DNS 解析服务器
    whois_creationDate = whois_json['WhoisRecord']['createdDate']  # 注册日期
    whois_registryExpiryDate = whois_json['WhoisRecord']['expiresDate']  # 到期日期
    whois_updatedDate = whois_json['WhoisRecord']['updatedDate']  # 更新日期
    result = []
    whois_result = (
        '注册商：{}\n'
        '注册邮箱：{}\n'
        '注册商 Whois 服务器：{}\n'
        '域名解析服务器：{} \n'
        '注册日期：{}\n'
        '到期日期：{}\n'
        '更新日期：{}'
            .format(
            whois_registrar,
            whois_registrarAbuseContactEmail,
            whois_registrarWHOISServer,
            whois_nameServer,
            whois_creationDate[0:10],
            whois_registryExpiryDate[0:10],
            whois_updatedDate[0:10]
        ))
    result.append(whois_result)
    return whois_result





