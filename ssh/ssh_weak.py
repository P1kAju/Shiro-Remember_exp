#!/usr/bin/env python
#coding:utf-8

import paramiko
import logging
logging.raiseExceptions=False  #paramikoロギングをオフにする

# 処理機能
def Parse_url(arg):
    import sys
    if sys.version_info < (3, 0):
        import urlparse
        if arg.startswith("http"): result = urlparse.urlparse(arg)
        else: result = urlparse.urlparse('http://%s'%arg)
    else:
        from urllib.parse import urlparse
        if arg.startswith("http"): result = urlparse(arg)
        else: result = urlparse('http://%s'%arg)
    if result.port is None and result.scheme == 'https': port = 443
    elif result.port is None and result.scheme == 'http': port = 80
    else: port = result.port
    if str(port) in ['80','443']: return result.hostname,str(port)
    else: return result.hostname,str(port)

"""チェックが必要なアカウントのパスワード"""
def PassDir():
    username = ['root',]
    password = ['root','123456','qwer1234']
    users = []
    pwds = []
    for user in username:
        username = user.strip()
        users.append(username)
    for pwd in password:
        password = pwd.strip()
        pwds.append(password)
    return users,pwds

''' 脆弱性検知機能 '''
def checkSSH(host,port):
    is_ok = False
    is_timed = False
    users,pwds = PassDir()
    # 負荷接続準備
    ssh = paramiko.SSHClient() 
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    for user in users:
        for pwd in pwds:
            if is_ok != True:
                try:
                    print('IP:{}  POST:{}  USER:{}  PASS:{}'.format(host,port,user,pwd))
                    sshd = ssh.connect(hostname=host,port=int(port),username=user,password=pwd,timeout=4)
                    if sshd == None:
                    # system命令テストを実行します。
                        # stdin,stdout,stderr = ssh.exec_command('cat /etc/passwd')
                        # print(stdout.read())
                        is_ok = True
                        return 'ok',user,pwd

                except Exception as error:
                    if 'Authentication' not in str(error):
                        is_timed = True
                        break
    # エラーメッセージ
    if is_ok != True and is_timed != True:
        return 'ng',None,None

    if is_timed:
        return 'time',None,None

def audit(arg):
    host,port = Parse_url(arg)    
    ports = [22]
    for port in ports:
        try: 
            _,user,pwd = checkSSH(host,port)
            if 'ok' in _:
                warning_info = "[success] Host:{} userName:{} passWord:{}".format(host,user,pwd)
            elif 'time' in _:
                warning_info = '[timeout] Host:{} '.format(host)
            else:
                warning_info = '[failed] Host:{}'.format(host)
            print (warning_info)

            # 検査記録をファイルに保存
            result_F = open('result_.txt','a')
            result_F.write(warning_info+'\n')
            result_F.close()
        except Exception as error:
            logging.warning(host)

if __name__ == "__main__":
    # がんばって
    LIst = ['127.0.0.1']
    for _ in LIst:
        audit(_)

    # ファイルタイプのアセットをロードする必要があるかどうかを選択してください 👇
    # _ = open('資産.txt','r')
    # for i in _.readlines():
    #     audit(i)



