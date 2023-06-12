import os
import sys
import crawl, common

payload = []
filename = os.path.join(sys.path[0], "../data", "xss.txt")

f = open(filename)
for i in f:
    payload.append(i.strip())


class Spider:
    def run(self, url):
        download = crawl.HtmlCrawl()
        urls = common.urlsplit(url)
        if urls is None:
            return "XSS may not exist: %s" % url
        for _urlp in urls:
            for _payload in payload:
                _url = _urlp.replace("my_Payload", _payload)
                print("[xss test]:", _url)
                # 我们需要对URL每个参数进行拆分,测试
                _str = download.request(_url)
                if _str is None:
                    return "XSS may not exist: %s" % url
                if (_str.find(_payload) != -1):
                    return "XSS may exist: %s" % url
        return "XSS may not exist: %s" % url


if __name__ == "__main__":
    url = input("请输入目标URL：")
    a = Spider()
    c = a.run(url)

