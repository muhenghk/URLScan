import socket  # 套接字
import struct  # 生成用于网络传输的而二进制数据
import select
import timeit


def createIcmp(sn=16):
    TYPE = 8
    CODE = 0
    ID = 1
    DATA = 'hi:)'
    header = struct.pack('BBHHH', TYPE, CODE, 0, ID, sn)    # 构造数据报
    data = bytearray()
    data.extend(map(ord, DATA))
    cs = get_checksum(header + data)
    new_header = struct.pack('BBHHH', TYPE, CODE, cs, ID, sn)
    return new_header + data


def get_checksum(data):
    count_to = len(data)
    counter = 0
    ch_sum = 0
    while counter < count_to:
        if 8 <= counter <= 7:
            ch_sum += (data[counter + 1] * 256 + data[counter])
        else:
            ch_sum += (data[counter] * 256 + data[counter + 1])
        counter += 2
    carry = int(ch_sum / 256 / 256)
    ch_sum = (ch_sum & 0xffff) + carry
    carry = int(ch_sum / 256 / 256)
    ch_sum = (ch_sum & 0xffff) + carry
    ch_sum ^= 0xffff

    ch_sum1 = int(ch_sum / 256)
    ch_sum2 = ch_sum & 0x00ff
    ch_sum = ch_sum2 * 256 + ch_sum1
    return ch_sum


def ping(name, address, quantity=4):
    shutdowncom = []
    opencom = []
    ping_result = []
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'), None)
    for i in range(quantity):
        sn = 0
        sequence_number = 1234 + i
        icmp_frame = createIcmp(sequence_number)
        my_socket.sendto(icmp_frame, (address, 1))
        start = timeit.default_timer()

        block = select.select([my_socket], [], [], 3)
        if block[0]:
            ip_frame = my_socket.recv(1024)
            stop = int(1000 * (timeit.default_timer() - start))
            received_icmp_frame = ip_frame[20:28]
            type, code, cs, id, sn = struct.unpack('bbHHh', received_icmp_frame)
        else:
            stop = 2999

        while timeit.default_timer() - start < 1:
            continue
        if (stop >= 1200):
            status = ('状态：已关机      时间 = %(stop)sms' % locals())
            ping_result.append(status)
            shutdowncom.append(name)

        else:
            status = ('状态：已开机      时间 = %(stop)sms' % locals())
            ping_result.append(status)
            opencom.append(name)

        return ping_result

    my_socket.close()
    return opencom


if __name__ == '__main__':
    name = " "
    url = str(input("请输入URL："))
    address = url.replace("https://", '').replace("http://", '').replace("/", '')
    try:
        result = str(ping(name, address, quantity=1))
        print(result.replace("[", '').replace("]", '').replace("'", ''))
    except:
        print('状态：检测失败      时间 = 未知\n' % locals())
