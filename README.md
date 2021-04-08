## DNS协议
DNS协议参考[RFC 1035](https://tools.ietf.org/html/rfc1035)。

## 使用方法
编译：
```shell
g++ basic_dns_sender.cpp -o mydns
```
运行：
```shell
./mydns 8.8.8.8 www.baidu.com
```

## 运行环境
CentOS Linux release 7.8.2003  
g++ (GCC) 4.8.5

## 运行测试
![testdns](http://github.com/dgnn96/simple-dns/raw/master/images/testdns.png)