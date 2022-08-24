# 引入依赖库、包、文件等依赖程序代码
import re
import sys
import json
import nmap
import urllib3
import masscan
import tkinter
import datetime
import requests
import threading
import dns.resolver
import urllib.parse
import urllib.request
from tkinter import ttk
from wappalyzer import Wappalyzer, WebPage


# 禁用部分请求告警提示信息
urllib3.disable_warnings(urllib3.exceptions.InsecurePlatformWarning)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# 配置信息
CONFIGURATION = {  # These configurations are for all of api tokens
    # 三种端口判断：企业常用端口、关键端口、全端口
    "EnterprisePorts": "21,22,23,25,53,80,81,110,111,123,123,135,137,139,161,389,443,445,465,500,515,520,523,548,623,636,873,902,1080,1099,1433,1521,1604,1645,1701,1883,1900,2049,2181,2375,2379,2425,3128,3306,3389,4730,5060,5222,5351,5353,5432,5555,5601,5672,5683,5900,5938,5984,6000,6379,7001,7077,8080,8081,8443,8545,8686,9000,9001,9042,9092,9100,9200,9418,9999,11211,27017,37777,40000,50000,50070,61616",
    "KeyPorts": "21,22,80,443,445,1433,3306,3389,6379,8080,8443,9200",
    "AllPorts": "1-65535",
}


class AssetScanner(object):
    """资产扫描（资产信息收集）类"""

    def __init__(self):
        """初始化资产扫描（资产信息收集）类，定义实例属性"""
        self.virustotal_api_url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        self.virustotal_requests_parameters = None
        self.domain_name_service_resolver = dns.resolver
        self.port_scan_type = ["Enterprise", "Key", "All"]
        self.masscan_port_parameters = None
        self.masscan_port_scanner = masscan.PortScanner()
        self.maximum_thread_count = 10
        self.current_thread_size = 0
        self.nmap_port_scanner = nmap.PortScanner()
        self.title_scan_requests_headers = None
        self.thread_creater = threading.Thread
        self.thread_lock = threading.Lock()
        self.thread_lock_event = threading.Event()
        self.thread_lock_event.set()
        self.scan_pause_flag = False
        self.windows = tkinter.Tk()
        self.windows.geometry("1630x800")
        self.windows.maxsize(1630, 800)
        self.windows.minsize(1630, 800)
        self.windows.title("资产信息收集客户端V1.2")
        self.top_level_domain = None
        self.top_level_domain_laber = tkinter.Label(self.windows, text="目标域名:")
        self.top_level_domain_input = tkinter.Entry(self.windows, width=30)
        self.port_label = tkinter.Label(self.windows, text="端口类型选择:")
        self.enterprise_port_label = tkinter.Label(self.windows, text="常用端口")
        self.key_port_label = tkinter.Label(self.windows, text="关键端口")
        self.all_port_label = tkinter.Label(self.windows, text="全部端口")
        self.port_scan_type = tkinter.StringVar()
        self.enterprise_port_radio = tkinter.Radiobutton(self.windows, value="Enterprise", variable=self.port_scan_type, command=self.set_port_scan_type)
        self.key_port_radio = tkinter.Radiobutton(self.windows, value="Key", variable=self.port_scan_type, command=self.set_port_scan_type)
        self.all_port_radio = tkinter.Radiobutton(self.windows, value="All", variable=self.port_scan_type, command=self.set_port_scan_type)
        self.virustotal_token = None
        self.virustotal_token_label = tkinter.Label(self.windows, text="VT令牌:")
        self.virustotal_token_input = tkinter.Entry(self.windows, width=30)
        self.thread_count_label = tkinter.Label(self.windows, text="最大线程数:")
        self.thread_count_input = tkinter.Entry(self.windows, width=5)
        self.scan_button = tkinter.Button(self.windows, width=8, text="开始收集", bg="blue", command=self.scan)
        self.pause_button = tkinter.Button(self.windows, width=8, text="暂停/继续", bg="blue", command=self.pause)
        self.result_frame = tkinter.Frame(self.windows, width=1600, height=300)
        self.result_frame.pack_propagate(0)
        self.y_scrollbar = ttk.Scrollbar(self.result_frame, orient=tkinter.VERTICAL)
        self.table_columns = ['主域名', '子域名', 'IP地址', '端口', '协议', '服务', '产品', '版本', '页面标题', '中间件']
        self.result_table = ttk.Treeview(
            master = self.result_frame,
            height=15,
            columns = self.table_columns,
            show = "headings",
            selectmode = "browse",
            yscrollcommand=self.y_scrollbar.set
        )
        self.result_table.heading('主域名', text='主域名')
        self.result_table.column('主域名', width=150, minwidth=100, anchor='center')
        self.result_table.heading('子域名', text='子域名')
        self.result_table.column('子域名', width=250, minwidth=100, anchor='center')
        self.result_table.heading('IP地址', text='IP地址')
        self.result_table.column('IP地址', width=150, minwidth=100, anchor='center')
        self.result_table.heading('端口', text='端口')
        self.result_table.column('端口', width=80, minwidth=60, anchor='center')
        self.result_table.heading('协议', text='协议')
        self.result_table.column('协议', width=55, minwidth=50, anchor='center')
        self.result_table.heading('服务', text='服务')
        self.result_table.column('服务', width=150, minwidth=80, anchor='center')
        self.result_table.heading('产品', text='产品')
        self.result_table.column('产品', width=150, minwidth=80, anchor='center')
        self.result_table.heading('版本', text='版本')
        self.result_table.column('版本', width=150, minwidth=80, anchor='center')
        self.result_table.heading('页面标题', text='页面标题')
        self.result_table.column('页面标题', width=250, minwidth=80, anchor='center')
        self.result_table.heading('中间件', text='中间件')
        self.result_table.column('中间件', width=200, minwidth=80, anchor='center')
        self.text_output_label = tkinter.Label(self.windows, text="过程详细信息:")
        self.text_output = tkinter.Text(self.windows, width=229, height=30, relief=tkinter.RAISED, bg="gray")
        self.text_output.config(state=tkinter.DISABLED)
        self.download_button = tkinter.Button(self.windows, width=8, text="信息下载", bg="blue", command=self.information_download)


    def graph(self):
        """界面绘制函数"""
        self.top_level_domain_laber.place(x=15, y=20)
        self.top_level_domain_input.place(x=90, y=20)
        self.port_label.place(x=410, y=20)
        self.enterprise_port_label.place(x=530, y=20)
        self.key_port_label.place(x=630, y=20)
        self.all_port_label.place(x=730, y=20)
        self.enterprise_port_radio.place(x=590, y=20)
        self.key_port_radio.place(x=690, y=20)
        self.all_port_radio.place(x=790, y=20)
        self.virustotal_token_label.place(x=830, y=20)
        self.virustotal_token_input.place(x=890, y=20)
        self.thread_count_label.place(x=1200, y=20)
        self.thread_count_input.place(x=1290, y=20)
        self.scan_button.place(x=1370, y=18)
        self.pause_button.place(x=1510, y=18)
        self.result_frame.place(x=17, y=50)
        self.result_table.pack(side="left", anchor='nw')
        self.y_scrollbar.pack(side='right', fill='y')
        # self.result_table.place(x=15, y=90)
        self.text_output_label.place(x=15, y=355)
        self.text_output.place(x=10,y=380)
        self.download_button.place(x=1510, y=350)
        self.windows.mainloop()

    def show_message(self, title, message):
        """弹窗提示函数"""
        messagebox.showinfo(title, message)

    def show_log(self, message):
        """日志显示函数线程启动函数"""
        thread = self.thread_creater(target=self.show_log_helper, args=(message,))
        thread.start()

    def show_log_helper(self, message):
        """日志显示函数"""
        self.text_output.config(state=tkinter.NORMAL)
        self.text_output.insert(tkinter.END, message + '\n')
        self.text_output.config(state=tkinter.DISABLED)

    def set_port_scan_type(self):
        """设置待扫描的端口"""
        scan_type = self.port_scan_type.get()
        if scan_type == "All":
            self.masscan_port_parameters = CONFIGURATION["AllPorts"]
        elif scan_type == "Key":
            self.masscan_port_parameters = CONFIGURATION["KeyPorts"]
        elif scan_type == "Enterprise":
            self.masscan_port_parameters = CONFIGURATION["EnterprisePorts"]
        else:
            self.show_message("提示", "配置端口扫描类型选择错误，默认选择关键端口!")

    def get_subdomains_by_virustotal_api(self, domain_name):
        """通过VirusTotal获取主域名对应的子域名"""
        self.virustotal_requests_parameters['domain'] = domain_name
        try:
            response = urllib.request.urlopen('%s?%s' % (self.virustotal_api_url, urllib.parse.urlencode(self.virustotal_requests_parameters))).read()
            subdomain_list = json.loads(response)
            subdomain_list = subdomain_list["subdomains"]
            self.show_log("[+] 从VirusTotal获取子域名成功! ")
            return subdomain_list
        except Exception as exception:
            self.show_log("[-] 从VirusTotal获取子域名失败，失败原因: %s" %str(exception))
            return []

    def get_subdomains(self, domain_name):
        """通用的获取子域名的函数"""
        subdomain_list = self.get_subdomains_by_virustotal_api(domain_name)
        return subdomain_list

    def get_cname_record(self, subdomain):
        """获取CNAME的函数"""
        cname_list = None
        try:
            cname_list = self.domain_name_service_resolver.resolve(subdomain, "CNAME").response.answer
        except Exception as exception:
            self.show_log("[-] 从DNS服务获取CNAME失败，失败子域名: %s 失败原因: " % str(subdomain) + str(exception))
            cname_list = []
        cnames = []
        if len(cname_list) < 0:
            self.show_log("[+] 子域名: %s 未获取到子域名 " % str(subdomain))
            return cnames
        for cname in cname_list:
            if cname.rdtype == 5:
                for item in cname:
                    cnames.append(str(item)[:-1])
        return cnames

    def get_a_record(self, domain_name):
        """获取A记录的函数"""
        ip_list = None
        try:
            ip_list = self.domain_name_service_resolver.resolve(domain_name, "A").response.answer
        except Exception as exception:
            self.show_log("[-] 从DNS服务获取A记录失败，失败域名: %s 失败原因: " % str(domain_name) + str(exception))
            ip_list = []
        ips = []
        if len(ip_list) < 0:
            self.show_log("[+] 域名: %s 未获取到A记录IP地址 " % str(domain_name))
            return ips
        for ip in ip_list:
            if ip.rdtype == 1:
                for item in ip:
                    ips.append(str(item))
        return ips

    def get_tcp_port(self, ip):
        """利用MASSCAN获取TCP开放端口的函数"""
        try:
            response = self.masscan_port_scanner.scan(ip, ports=self.masscan_port_parameters, arguments='--max-rate 10000 --wait 3')
            return response["scan"][ip]["tcp"]
        except Exception as exception:
            self.show_log("[-] IP地址: %s 未获取到TCP端口， 失败原因 " % str(ip) + str(exception))
            return []

    def get_udp_port(self, ip):
        """利用MASSCAN获取UDP开放端口的函数"""
        try:
            response = self.masscan_port_scanner.scan(ip, ports=self.masscan_port_parameters, arguments='--max-rate 10000 --wait 3')
            try:
                return response["scan"][ip]["udp"]
            except:
                return []
        except Exception as exception:
            self.show_log("[-] IP地址: %s 未获取到UDP端口， 失败原因 " % str(ip) + str(exception))
            return []

    def tcp_port_information_scanner(self, ip, port):
        """利用NMAP获取TCP开放端口具体信息的函数"""
        try:
            self.nmap_port_scanner.scan(hosts=ip, ports=str(port), arguments="-sV", sudo=True)
            service = self.nmap_port_scanner[ip]["tcp"][port]["name"]
            product = self.nmap_port_scanner[ip]["tcp"][port]["product"]
            version = self.nmap_port_scanner[ip]["tcp"][port]["version"]
            return service, product, version
        except Exception as exception:
            self.show_log("[-] TCP IP地址: %s 端口: %s 未获取到端口信息， 失败原因 " % (str(ip), str(port)) + str(exception))
            return "", "", ""

    def udp_port_information_scanner(self, ip, port):
        """利用NMAP获取UDP开放端口具体信息的函数"""
        try:
            self.nmap_port_scanner.scan(hosts=ip, ports=str(port), arguments="-sV", sudo=True)
            service = self.nmap_port_scanner[ip]["udp"][port]["name"]
            product = self.nmap_port_scanner[ip]["udp"][port]["product"]
            version = self.nmap_port_scanner[ip]["udp"][port]["version"]
            return service, product, version
        except Exception as exception:
            self.show_log("[-] UDP IP地址: %s 端口: %s 未获取到端口信息， 失败原因 " % (str(ip), str(port)) + str(exception))
            return "", "", ""

    def service_information_scanner(self, ip, port):
        """利用WEB页面标题信息"""
        url = "http://%s:%s" % (ip, str(port))
        try:
            response = requests.get(url, headers=self.title_scan_requests_headers, timeout=5)
            title = re.findall('<title>(.+)</title>', str(response.text))
            if len(title) > 0:
                return title[0]
        except Exception as exception:
            self.show_log("[-] 获取页面标题失败（%s:%s），失败原因 " % (str(ip), str(port)) + str(exception))
        url = "https://%s:%s" % (ip, str(port))
        try:
            response = requests.get(url, headers=self.title_scan_requests_headers, verify=False, timeout=5)
            title = re.findall('<title>(.+)</title>', str(response.text))
            if len(title) > 0:
                return title[0]
        except Exception as exception:
            self.show_log("[-] 获取页面标题失败（%s:%s），失败原因 " % (str(ip), str(port)) + str(exception))
        return ''

    def middle_ware_information_scanner(self, ip, port):
        """利用中间件标签信息"""
        middle_scanner = Wappalyzer.latest()
        url = "http://%s:%s" % (str(ip), str(port))
        try:
            webpage = WebPage.new_from_url(url)
        except Exception as exception:
            self.show_log("[-] 获取中间件信息（http://%s:%s），失败原因 " % (str(ip), str(port)) + str(exception))
            url = "https://%s:%s" % (str(ip), str(port))
            try:
                webpage = WebPage.new_from_url(url)
            except Exception as exception:
                self.show_log("[-] 获取中间件信息（https://%s:%s），失败原因 " % (str(ip), str(port)) + str(exception))
                return ""
        web_prints = list(middle_scanner.analyze(webpage))
        if len(web_prints) > 0:
            message = ''
            for middle in web_prints:
                message += middle + '/'
            return message[0:-1]
        return ""

    def table_insert(self, domain, subdomain, ip, port, protocol, service, product, version, title, middle):
        """向结果表格中插入数据"""
        data = (domain, subdomain, ip, port, protocol, service, product, version, title, middle)
        self.result_table.insert("", tkinter.END, text='', values=data)
        self.windows.update()

    def port_scan(self, domain_name, subdomain, protocol, ip, port):
        """统一端口信息扫描函数"""
        # content = "[+] %s端口扫描中 " % str(protocol) + ip + ":" + port
        # self.thread_print(content)
        service, product, version = self.tcp_port_information_scanner(ip, port)
        title, middle = "", ""
        if protocol == "TCP":
            if port in [80, 8080, 8443, 443, 8000] or service.find("http") >= 0:
                title = self.service_information_scanner(ip, port)
                middle = self.middle_ware_information_scanner(ip, port)
        self.table_insert(str(domain_name), str(subdomain), str(ip), str(port), 'TCP', str(service), str(product), str(version), str(title), str(middle))
        self.current_thread_size -= 1

    def pause(self):
        """设置暂停标志位的函数"""
        if self.scan_pause_flag:
            self.scan_pause_flag= False
        else:
            self.scan_pause_flag = True

    def scan(self):
        """资产扫描函数启动线程函数"""
        thread = self.thread_creater(target=self.scan_helper)
        thread.start()

    def information_download_helper(self):
        """信息下载函数"""
        if len(self.result_table.get_children()) == 0:
            self.show_log("[-] 待下载数据为0")
            return
        result_list = []
        for information_item in self.result_table.get_children():
            result_list.append(self.result_table.item(information_item)['values'])
        filename = self.top_level_domain + str(datetime.datetime.now()).replace(" ", "_") + ".csv"
        with open("./result/%s" % filename, 'w') as file_writer:
            file_writer.write("主域名,子域名,IP地址,端口,协议,服务,产品,版本,页面标题,中间件\n")
            for information_line in result_list:
                content = str(information_line).replace("[", "").replace("]","").replace("'", "")
                file_writer.write(content + "\n")

    def information_download(self):
        """信息下载函数线程启动函数"""
        thread = self.thread_creater(target=self.information_download_helper, args=())
        thread.start()

    def scan_helper(self):
        """资产扫描启动函数"""
        self.virustotal_token = self.virustotal_token_input.get()
        self.top_level_domain = self.top_level_domain_input.get()
        if self.virustotal_token in [None, "", " "]:
            self.show_message("VT令牌错误", "请检查VT令牌配置")
            return
        self.show_log("[+] 获取到VT令牌 %s" % self.virustotal_token)
        if self.top_level_domain in [None, "", " "]:
            self.show_message("目标错误", "请检查目标主域名配置")
            return
        self.show_log("[+] 获取到目标域名 %s" % self.top_level_domain)
        self.virustotal_requests_parameters = {'domain': None, 'apikey': self.virustotal_token}
        try:
            self.maximum_thread_count = int(self.thread_count_input.get())
            if self.maximum_thread_count < 10:
                self.maximum_thread_count = 10
        except:
            self.maximum_thread_count = 10
        self.show_log("[+] 获取到最大线程数配置 %s" % str(self.maximum_thread_count))
        port_string = CONFIGURATION[self.port_scan_type.get() + "Ports"]
        self.show_log("[+] 获取到端口扫描配置 %s" % str(port_string))
        self.set_port_scan_type()
        subdomains = self.get_subdomains(self.top_level_domain)
        if len(subdomains) <= 0:
            return False
        for subdomain in subdomains:
            while self.scan_pause_flag:
                continue
            cnames = self.get_cname_record(subdomain)
            for cname in cnames:
                while self.scan_pause_flag:
                    continue
                ips = self.get_a_record(subdomain)
                if len(cnames) >= 0:
                    ips = self.get_a_record(cname)
                if len(ips) > 0:
                    for ip in ips:
                        while self.scan_pause_flag:
                            continue
                        tcp_ports = self.get_tcp_port(ip)
                        udp_ports = self.get_udp_port(ip)
                        tcp_ports_size = len(tcp_ports)
                        udp_ports_size = len(udp_ports)
                        tcp_ports_index = 0
                        udp_ports_index = 0
                        if len(tcp_ports) > 0:
                            for port in tcp_ports:
                                while self.scan_pause_flag:
                                    continue
                                while True:
                                    if self.current_thread_size < self.maximum_thread_count:
                                        thread = self.thread_creater(target=self.port_scan, args=(self.top_level_domain, subdomain, "TCP", ip, port))
                                        self.current_thread_size += 1
                                        tcp_ports_index += 1
                                        thread.start()
                                        if tcp_ports_size - tcp_ports_index < self.maximum_thread_count:
                                            thread.join()
                                        break
                                    else:
                                        continue
                        if len(udp_ports) > 0:
                            for port in udp_ports:
                                while self.scan_pause_flag:
                                    continue
                                while True:
                                    if self.current_thread_size < self.maximum_thread_count:
                                        thread = self.thread_creater(target=self.port_scan, args=(self.top_level_domain, subdomain, "UDP", ip, port))
                                        self.current_thread_size += 1
                                        udp_ports_index += 1
                                        thread.start()
                                        if udp_ports_size - udp_ports_index < self.maximum_thread_count:
                                            thread.join()
                                        break
                                    else:
                                        continue



if __name__ == "__main__":
    scanner = AssetScanner()
    scanner.graph()
