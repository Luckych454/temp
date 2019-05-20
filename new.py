from socket import *
import threading
import sys
import socketserver
import time
from prettytable import PrettyTable

# receiving port
portIn = 12000
threading_lock = threading.Lock()
thread_key = True
# 获取本机IP
hostname = gethostname()
ip = "172.20.10.3"
# ip=str(portIn)
# 使用一个离散化的路由表
forwarding_table = dict()  # forwarding_table[destination] = [neighbour, cost]
neighbour_dict = dict()  # neighbour_table[neighbour]=cost
# 路由算法 DV
'''
在DV算法中，路由器只需要向邻居路由器发送自己的路由表，并在不断地迭代中，得到路由表的更新
'''


# 一系列的辅助函数

class Packet():
    def __init__(self, message='', addr=ip):
        # message:[func|src|dist|data]
        if message == '':
            message_list = ['', '', '', '']
        message_list = message.split('|')
        self.func = message_list[0]  # 功能号
        self.src = message_list[1]  # 起始IP
        self.dst = message_list[2]  # 目的IP
        self.data = message_list[3]  # 数据段
        self.to_addr = addr  # 发送地址nexthop

    def to_string(self):
        message = self.func + '|' + self.src + '|' + self.dst + '|' + self.data
        return message

    def set_to_addr(self, addr):
        self.to_addr = addr

    def set_path(self, src, dst):
        self.src = src
        self.dst = dst

    def set_func(self, func):
        self.func = func


def updateRouteTable(table, from_addr):
    # DV:交换更新路由表
    updated = False
    for dst, val in table.items():
        new_cost = neighbour_dict[from_addr] + val[1]
        if dst not in forwarding_table.keys():
            if dst != ip:
                forwarding_table[dst] = [from_addr, new_cost]
                updated = True
        elif new_cost < forwarding_table[dst][1]:  # dx(y)=min{dv(y)+dx(v),dx(y)}
            forwarding_table[dst] = [from_addr, new_cost]
            updated = True
        elif from_addr == forwarding_table[dst][0]:
            # if cost of link increased(bad news)
            if new_cost > forwarding_table[dst][1]:
                forwarding_table[dst] = [from_addr, new_cost]
                updated = True
    return updated


def sendForwardingTable():  # 向邻居发送转发表
    to_table = []
    for key, val in forwarding_table.items():
        to_table.append(key + ',' + val[0] + ',' + str(val[1]))  # destination,next_hop,cost
    table_message = '\n'.join(to_table)  # 通过字符串形式发送转发表
    for neighbour in neighbour_dict.keys():
        packet = Packet("2|" + ip + '|' + neighbour + '|' + table_message, neighbour)
        sendPacket(packet)


def getForwardingTable(table_message):  # 从数据段中解析得到转发表
    table_list = table_message.split('\n')
    from_table = dict()
    for entry in table_list:
        entry = entry.split(',')  # destination,next_hop,cost
        from_table[entry[0]] = [entry[1], int(entry[2])]
    return from_table.copy()


def showForwardingTable():  # 展示转发表
    table = PrettyTable(["destination", "nexthop", "cost"])
    for key, value in forwarding_table.items():
        table.add_row([key, value[0], str(value[1])])
    print(table)


def sendPacket(packet):
    output_addr = packet.to_addr
    message = packet.to_string()
    output_port = portIn
    output_socket = socket(AF_INET, SOCK_DGRAM)
    output_socket.sendto(message.encode(), (output_addr, output_port))
    #    output_socket.sendto(message.encode(), (gethostbyname(hostname), int(output_addr)))
    output_socket.close()


def broadcastPacket(func, datagram):
    for dst in forwarding_table.keys():
        packet = Packet(func + '|' + ip + '|' + dst + '|' + datagram, dst)
        sendPacket(packet)


def routerDown(down_ip):
    global forwarding_table
    if down_ip in neighbour_dict.keys():
        del neighbour_dict[down_ip]
    new_table = dict()
    for key, value in forwarding_table.items():
        if down_ip != key and down_ip != value[0]:
            new_table[key] = value
    for neighbour in neighbour_dict.keys():
        if neighbour not in new_table.keys():
            new_table[neighbour] = [neighbour, neighbour_dict[neighbour]]
    forwarding_table = new_table.copy()
    print('A router is down and Forwarding Table has been changed:')
    showForwardingTable()


def processAndSwitching(packet):  # 对输入的数据包进行解析处理操作
    # process datagram
    function = packet.func
    src_ip = packet.src
    dst_ip = packet.dst
    datagram = packet.data

    # forward message：处理信息报文，根据转发表转发
    if function == '0':
        if dst_ip == ip:
            print("[Message from " + src_ip + ']: ' + datagram)
        elif dst_ip.split('.')[3] == '255' and src_ip == ip:
            broadcastPacket(function, datagram)
        else:
            try:
                next_hop = forwarding_table[dst_ip][0]
            except KeyError:
                print('A packet to ' + dst_ip + ' failed to be forwarded.')
            else:
                packet.set_to_addr(next_hop)
                sendPacket(packet)
                print('A packet to ' + dst_ip + ' is forwarding to ' + next_hop)

    # router down：处理路由器开关报文，更新邻居表和转发表
    if function == '1':
        if datagram == 'down':
            if src_ip == ip:
                broadcastPacket(function, datagram)
            elif dst_ip == ip:
                routerDown(src_ip)
            else:
                try:
                    next_hop = forwarding_table[dst_ip][0]
                except KeyError:
                    print('A packet to ' + dst_ip + ' failed to be forwarded.')
                else:
                    packet.set_to_addr(next_hop)
                    sendPacket(packet)
                    print('A packet to ' + dst_ip + ' is forwarding to ' + next_hop)

    # route:处理路由报文，更新转发表
    if function == '2' and ip == dst_ip:
        is_updated = False
        if src_ip != ip:
            from_table = getForwardingTable(datagram)
            is_updated = updateRouteTable(from_table, src_ip)
        else:
            is_updated = True
        if is_updated:
            print("Forwarding Table has been updated:")
            showForwardingTable()
            sendForwardingTable()


# print('Periodically sending forwarding table')
def exchangeTablePeriodically():
    global thread_key
    while True:
        time.sleep(10)
        sendForwardingTable()
        if thread_key == False:
            break


# 处理控制台的输入
def routeConsole():
    # 首先输出路由器的信息
    # 然后请求输入，根据输入控制路由器：生成任务，关闭路由器
    global thread_key
    while True:
        # 在终端接受用户的输入，然后对输入进行解析，并执行
        # 更改自己的路由表
        # 关闭自己的路由器（即清空自己的路由表）
        # 发送一个任务给其他路由器
        # 手动更新自己的路由表
        command = input("请输入你的命令：")
        command = command.split(" ")
        if command[0] == "change":
            # 改变自己的直连路由的链路代价 change neighbour cost
            neighbour = command[1]
            new_cost = command[2]
            if neighbour in neighbour_table.keys():
                for key, value in forwarding_table.items():
                    if key == neighbour:
                        forwarding_table[neighbour] = [neighbour, cost]
                    elif value[0] == neighbour:
                        forwarding_table[key] = [neighbour, value[1] - neighbour_dict[neighbour] + cost]
                neighbour_dict[neighbour] = cost
                print("转发表更新完成:")
                showForwardingTable()
            else:
                print("IP不在路由表中！更新失败")
        if command[0] == "shutdown":
            # 关闭路由器
            thread_key = False
            # 要先告知其他路由器
            packet = Packet('1|' + ip + '|' + '0.0.0.255' + '|' + 'down', ip)
            processAndSwitching(packet)
            # 关闭套接字
            routerServer.shutdown()
            routerServer.server_close()
            sys.exit()
        if command[0] == "send":  # send ip port
            # 输入内容
            dst_addr = input("Please enter IP address of destination(last 255 to broadcast)\n")
            message = input("Please enter the message you want to send('|' is NOT allowed in the message)\n")
            packet = Packet('0|' + ip + '|' + dst_addr + '|' + message, dst_addr)
            processAndSwitching(packet)
        if command[0] == "show":
            # 查看路由表
            showForwardingTable()


# 处理别的路由器发过来的路由信息
class routerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            # 接收信息
            data, socket = self.request
            packet = Packet(data.decode(), self.client_address[0])
            processAndSwitching(packet)
            # print(self.request)
        #            print("{}wrote:".format(self.client_address[0]))
        #            print(data)
        # 将这个data放入输入缓冲区
        # socket.sendto(self.data.upper(),self.client_address)
        except Exception as e:
            print(self.client_address, "连接断开")


if __name__ == '__main__':
    # 使用UDP的方法进行连接
    # 配置路由表
    # 输入连接路由器的数量
    '''
    neighbour_count = int(input("Please enter the number of neighbours of this node:\n"))
    # 输入连接路由器的IP，链路代价
    for i in range(neighbour_count):
        neighbour = input("Please enter IP address of neighbour " + str(i + 1) + ":\n")
        cost = int(input("Please enter the cost of this link:\n"))
        forwarding_table[neighbour] = [neighbour, cost]  # table[destination] = [neighbour, cost]
        neighbour_dict[neighbour] = cost
    forwarding_table[ip] = [ip, 0]
    '''
    neighbour_dict["172.20.10.6"] = 2
    forwarding_table["172.20.10.6"] = ["172.20.10.6", 2]
    neighbour_dict["172.20.10.5"] = 1
    forwarding_table["172.20.10.5"] = ["172.20.10.5", 1]
    print("Router initialization done!")
    # 开始执行路由器的功能
    '''
    1. 向相邻的路由器发送路由表
    2. 接受相邻路由器的路由表,计算路由表
    3. 生成任务
    4. 转发任务
    5. 接受任务
    '''
    # 创建一个路由器的控制台
    console = threading.Thread(target=routeConsole)
    console.start()
    # 后台周期性交换转发表
    backstage = threading.Thread(target=exchangeTablePeriodically)
    backstage.start()
    # 多线程的UDP服务器
    routerServer = socketserver.ThreadingUDPServer((ip, portIn), routerHandler)  # 多线程版
    routerServer.serve_forever()

