from concurrent.futures import ThreadPoolExecutor
import socket
import sys
import getopt


def portscan(ip, port):
    s = socket.socket()   # 创建 socket 对象
    status_result = []
    s.settimeout(0.1)
    protocolname = 'tcp'
    if s.connect_ex((ip, port)) == 0:
        try:
            port_status = ("端口%4d开启：%s" % (port, socket.getservbyport(port, protocolname)))
            status_result.append(port_status)
        except:
            port_status = ('端口%4d开启: Unknown ' % port)
            status_result.append(port_status)
        return status_result
    s.close()


if __name__ == "__main__":
    result_list = []
    url = input("请输入url：")
    ip = url.replace("https://", '').replace("http://", '').replace("/", '')
    with ThreadPoolExecutor(200) as f:
        for port in range(0, 300):
            f.submit(portscan, ip, port)
            result = str(portscan(ip, port))
            if result == "None":
                del result
            else:
                result_list.append(result)
        res = str(result_list).replace("[", '').replace("]", '').replace("'", '').replace('"', '').replace(', ', '\n')
        print(res)
