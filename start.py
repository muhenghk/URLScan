from concurrent.futures.thread import ThreadPoolExecutor
from PySide2.QtWidgets import QApplication
from PySide2.QtUiTools import QUiLoader
from PySide2.QtCore import QFile
from scan import ip_scan, port_scan, domain_scan, whois_scan, ping_scan
from webscan import SQL_inject
from URLScan.webscan import XSS_check, Webshell_check
import datetime


class Stats:

    def __init__(self):
        # 从文件中加载UI定义
        qfile_stats = QFile("D:/desktop/URLScan/ui/URLScan.ui")
        qfile_stats.open(QFile.ReadOnly)
        qfile_stats.close()

        # 从 UI 定义中动态 创建一个相应的窗口对象
        # 注意：里面的控件对象也成为窗口对象的属性了
        # 比如 self.ui.button , self.ui.textEdit
        self.ui = QUiLoader().load(qfile_stats)
        self.ui.pushButton.clicked.connect(self.go)

    def go(self):
        now = datetime.datetime.now()
        if self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '12345'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(70, 81):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n', 'Ping'
                                                                                                                '扫描结果：',
                      '\n', result_5, '\n\n', file=file0)



        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked():
            name = '1234'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox5.isChecked():
            name = '1235'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)


        elif self.ui.checkBox1.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '1345'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '2345'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)


        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked():
            name = '123'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', '子域名扫描结果：', '\n', domain, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox4.isChecked():
            name = '124'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked() and self.ui.checkBox5.isChecked():
            name = '125'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)


        elif self.ui.checkBox1.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked():
            name = '134'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox5.isChecked():
            name = '135'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result_5, '\n\n',
                      file=file0)



        elif self.ui.checkBox1.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '145'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', 'Whois扫描结果：',
                      '\n', result4, '\n\n', 'Whois扫描结果：', '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked():
            name = '234'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Whois扫描结果：', '\n', result4, '\n\n',
                      file=file0)

        elif self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked() and self.ui.checkBox5.isChecked():
            name = '235'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)


        elif self.ui.checkBox2.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '245'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', 'Whois扫描结果：',
                      '\n', result4, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '345'
            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Whois扫描结果：',
                      '\n', result4, '\n\n', 'Ping扫描结果：', '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox6.isChecked() and self.ui.checkBox7.isChecked() and self.ui.checkBox8.isChecked():
            name = '678'
            url = self.ui.lineEdit.text()
            html = ""
            a = SQL_inject.Spider()
            result_sql = a.run(url, html)
            self.ui.textBrowser6.setText(result_sql)

            url = self.ui.lineEdit.text()
            b = XSS_check.Spider()
            result_xss = b.run(url)
            self.ui.textBrowser7.setText(result_xss)

            url = self.ui.lineEdit.text()
            c = Webshell_check.Spider()
            result_webshell = c.run(url)
            self.ui.textBrowser8.setText(result_webshell)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'SQL漏洞扫描结果：', '\n', result_sql, '\n\n', 'XSS漏洞扫描结果：',
                      '\n', result_xss, '\n\n', 'Webshell漏洞扫描结果：', '\n', result_webshell, '\n\n',
                      file=file0)


        elif self.ui.checkBox1.isChecked() and self.ui.checkBox2.isChecked():
            name = '12'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '端口扫描结果：',
                      '\n', res, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox3.isChecked():
            name = '13'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', '子域名扫描结果：',
                      '\n', domain, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox4.isChecked():
            name = '14'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', 'whois扫描结果：',
                      '\n', result4, '\n\n',
                      file=file0)

        elif self.ui.checkBox1.isChecked() and self.ui.checkBox5.isChecked():
            name = '15'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address1 = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address1)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)

            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address1, '\n\n', 'Ping扫描结果：',
                      '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox2.isChecked() and self.ui.checkBox3.isChecked():
            name = '23'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)
            with open('scan_result.txt', 'a') as file0:
                print(
                    '********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                    '********************************* ',
                    '\n', '端口扫描结果：', '\n', res, '\n\n', '子域名扫描结果：',
                    '\n', domain, '\n\n',
                    file=file0)

        elif self.ui.checkBox2.isChecked() and self.ui.checkBox4.isChecked():
            name = '24'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print(
                    '********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                    '********************************* ',
                    '\n', '端口扫描结果：', '\n', res, '\n\n', 'Whois扫描结果：',
                    '\n', result4, '\n\n',
                    file=file0)


        elif self.ui.checkBox2.isChecked() and self.ui.checkBox5.isChecked():
            name = '25'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', 'Ping扫描结果：',
                      '\n', result_5, '\n\n',
                      file=file0)


        elif self.ui.checkBox3.isChecked() and self.ui.checkBox4.isChecked():
            name = '34'
            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print(
                    '********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                    '********************************* ',
                    '\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Whois扫描结果：',
                    '\n', result4, '\n\n',
                    file=file0)

        elif self.ui.checkBox3.isChecked() and self.ui.checkBox5.isChecked():
            name = '35'
            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print(
                    '********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                    '********************************* ',
                    '\n', '子域名扫描结果：', '\n', domain, '\n\n', 'Ping扫描结果：',
                    '\n', result_5, '\n\n',
                    file=file0)

        elif self.ui.checkBox4.isChecked() and self.ui.checkBox5.isChecked():
            name = '45'
            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))

            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'Whois扫描结果：', '\n', result4, '\n\n', 'Ping扫描结果：',
                      '\n', result_5, '\n\n',
                      file=file0)

        elif self.ui.checkBox6.isChecked() and self.ui.checkBox7.isChecked():
            name = '67'
            url = self.ui.lineEdit.text()
            html = ""
            a = SQL_inject.Spider()
            result_sql = a.run(url, html)
            self.ui.textBrowser6.setText(result_sql)

            url = self.ui.lineEdit.text()
            b = XSS_check.Spider()
            result_xss = b.run(url)
            self.ui.textBrowser7.setText(result_xss)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'SQl漏洞扫描结果：', '\n', result_sql, '\n\n', 'XSS漏洞扫描结果：',
                      '\n', result_xss, '\n\n',
                      file=file0)

        elif self.ui.checkBox6.isChecked() and self.ui.checkBox8.isChecked():
            name = '68'
            url = self.ui.lineEdit.text()
            html = ""
            a = SQL_inject.Spider()
            result_sql = a.run(url, html)
            self.ui.textBrowser6.setText(result_sql)

            url = self.ui.lineEdit.text()
            c = Webshell_check.Spider()
            result_webshell = c.run(url)
            self.ui.textBrowser8.setText(result_webshell)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'SQl漏洞扫描结果：', '\n', result_sql, '\n\n', 'XSS漏洞扫描结果：',
                      '\n',  result_webshell, '\n\n',
                      file=file0)

        elif self.ui.checkBox7.isChecked() and self.ui.checkBox8.isChecked():
            name = '78'
            url = self.ui.lineEdit.text()
            b = XSS_check.Spider()
            result_xss = b.run(url)
            self.ui.textBrowser7.setText(result_xss)

            url = self.ui.lineEdit.text()
            c = Webshell_check.Spider()
            result_webshell = c.run(url)
            self.ui.textBrowser8.setText(result_webshell)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'SQl漏洞扫描结果：', '\n', result_xss, '\n\n', 'XSS漏洞扫描结果：',
                      '\n',  result_webshell, '\n\n',
                      file=file0)



        elif self.ui.checkBox1.isChecked():
            name = '1'
            url = self.ui.lineEdit.text()
            url = ip_scan.check_head(url)
            ip = ip_scan.get_base_info(url)
            address = str(ip_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '').replace(",", "\n")
            self.ui.textBrowser.setText(address)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'IP扫描结果：', '\n', address, '\n\n', file=file0)


        elif self.ui.checkBox2.isChecked():
            name = '2'
            result_list = []
            url = self.ui.lineEdit.text()
            ip = url.replace("https://", '').replace("http://", '').replace("/", '')
            with ThreadPoolExecutor(200) as f:
                for port in range(0, 1024):
                    f.submit(port_scan.portscan, ip, port)
                    result = str(port_scan.portscan(ip, port))
                    if result == "None":
                        del result
                    else:
                        result_list.append(result)
                res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ',
                                                                                                                   '\n')
            self.ui.textBrowser2.setText(res)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '端口扫描结果：', '\n', res, '\n\n', file=file0)

        elif self.ui.checkBox3.isChecked():
            name = '3'
            url = self.ui.lineEdit.text()
            url = domain_scan.check_head(url)
            ip = domain_scan.get_base_info(url)
            address = str(domain_scan.check_ip(ip))
            address = address.replace("'", '').replace("[", '').replace("]", '')
            ip1 = (address[0:15]).replace(" ", '')
            url = domain_scan.check_head(ip1)
            ip = str(domain_scan.get_base_info(url))
            domain = ip.replace("[", '').replace("]", '').replace("'", '').replace(",", '\n')
            self.ui.textBrowser3.setText(domain)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', '子域名扫描结果：', '\n', domain, '\n\n', file=file0)

        elif self.ui.checkBox4.isChecked():
            name = '4'
            url = self.ui.lineEdit.text()
            result4 = whois_scan.whois_scan(url)
            self.ui.textBrowser4.setText(str(result4))
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'Whois扫描结果：', '\n', result4, '\n\n', file=file0)


        elif self.ui.checkBox5.isChecked():
            name = '5'
            name = " "
            url = self.ui.lineEdit.text()
            address = url.replace("https://", '').replace("http://", '').replace("/", '')
            try:
                result5 = str(ping_scan.ping(name, address, quantity=1))
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            except:
                result5 = ('状态：检测失败      时间 = 未知\n' % locals())
                result_5 = result5.replace("[", '').replace("]", '').replace("'", '')
                self.ui.textBrowser5.setText(result_5)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'Ping扫描结果：', '\n', result_5, '\n\n', file=file0)


        elif self.ui.checkBox6.isChecked():
            name = '6'
            url = self.ui.lineEdit.text()
            html = ""
            a = SQL_inject.Spider()
            result_sql = a.run(url, html)
            self.ui.textBrowser6.setText(result_sql)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'SQl漏洞扫描结果：', '\n', result_sql, '\n\n', file=file0)

        elif self.ui.checkBox7.isChecked():
            name = '7'
            url = self.ui.lineEdit.text()
            b = XSS_check.Spider()
            result_xss = b.run(url)
            self.ui.textBrowser7.setText(result_xss)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'XSS漏洞扫描结果：', '\n', result_xss, '\n\n', file=file0)


        elif self.ui.checkBox8.isChecked():
            name = '8'
            url = self.ui.lineEdit.text()
            c = Webshell_check.Spider()
            result_webshell = c.run(url)
            self.ui.textBrowser8.setText(result_webshell)
            with open('scan_result.txt', 'a') as file0:
                print('********************************', now.strftime("%Y-%m-%d %H:%M:%S"),
                      '********************************* ',
                      '\n', 'Webshell漏洞扫描结果：', '\n', result_webshell, '\n\n', file=file0)


app = QApplication([])
stats = Stats()
stats.ui.show()
app.exec_()
