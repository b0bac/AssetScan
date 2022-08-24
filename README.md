# AssetScan

## 测试与编译环境（Enviroment -- Test & Compile By:）

+ Operating System: Mac OS Monterey 12.5.1
+ Python Version: 3.9.13
+ Software：MasScan & Nmap

## 安装（Installation）
```bash
git clone https://github.com/b0bac/AssetScan.git
python3 -m pip install -r requirements.txt
```

##  使用（Usage）
```bash
python3 AssetScan.py
```

## 功能（Functions）：
+ 支持基于主域名和VirusTotal的子域名获取
+ 支持CNMAE记录和A记录的查询（不展示CNAME记录）
+ 支持端口及其详细信息的扫描（基于MasScan和Nmap）
+ 支持HTTP协议的页面标题和中间件的探查
+ 支持多线程
+ 支持图形化展示和获取信息下载

## 展示
<img width="1630" alt="WX20220824-142649@2x" src="https://user-images.githubusercontent.com/11972644/186351494-7bd6fadd-17d9-4226-9719-b5db209c73ef.png">
