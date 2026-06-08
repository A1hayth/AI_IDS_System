from scapy.all import get_if_list, show_interfaces

# 打印网卡列表
print("当前系统可用网卡列表：")
show_interfaces()  # 这个函数比 get_if_list 更详细，能看到网卡的中文人类可读名称