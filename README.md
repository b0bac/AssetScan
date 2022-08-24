# AssetScan

## 测试与编译环境（Enviroment -- Tested & Compiled By:）

+ Operating System: Mac OS Monterey 12.5.1
+ Python Version: 3.9.13
+ Software：MasScan & Nmap

## 安装（Installation）
```bash
brew install masscan
brew install nmap
git clone https://github.com/b0bac/AssetScan.git
python3 -m pip install -r requirements.txt
```

##  使用（Usage）
```bash
python3 AssetScan.py
```

## 功能（Functions）：
+ 支持基于主域名和VirusTotal的子域名获取 （Get Subdomains by Virustotal website api with token.）
+ 支持CNMAE记录和A记录的查询（不展示CNAME记录）（Get cname records & a records from dnsserver.）
+ 支持端口及其详细信息的扫描（基于MasScan和Nmap）（Scan the ports to gather their state & information with masscan & nmap.）
+ 支持HTTP协议的页面标题和中间件的探查 （Get the website titles.）
+ 支持多线程 （Multi-Threads）
+ 支持图形化展示和获取信息下载 （GUI & Downloading:Export To CSV）

## 展示（Display）
<img width="1630" alt="WX20220824-142649@2x" src="https://user-images.githubusercontent.com/11972644/186351494-7bd6fadd-17d9-4226-9719-b5db209c73ef.png">
