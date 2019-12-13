# /usr/bin/python2.7
# -*- coding: utf-8 -*-
# Author: Hurray(hurray0@icloud.com)
# Date: 2017.05.28

from socket import *
import threading
import json

HOST = ""
PORT = 8945
BUFSIZ = 1024
ADDR = (HOST, PORT)


class User:
    def __init__(self, address, client_socket):
        self.address = address
        self.client_socket = client_socket


class Handler:
    user_pool = {}  # user: user_pool

    def __init__(self, user):
        self.user = user

    # @staticmethod
    # def getUser(username):
    #     def getKey(list, value):
    #         return [k for k,v in d.items() if v == value][0]
    #     return getKey(Handler.user_pool, username)
    #
    # @staticmethod
    # def delUsername(username):
    #     try:
    #         user = Handler.getUser(username)
    #         Handler.remove_user(user)
    #     except:
    #         pass

    @staticmethod
    def remove_user(user):
        try:
            Handler.user_pool.pop(user)
        except Exception as e:
            log(e, "ERROR")

    @staticmethod
    def send_to_users(users, data):
        raw_data = json.dumps(data).encode()
        for user in users:
            user.client_socket.send(raw_data)
        log("[send_to_users] " + raw_data, "SUCCESS")

    @staticmethod
    def send_to_user(user, data):
        """向用户列表发送相同的数据包"""
        userList = [k for k, v in Handler.user_pool.items() if v in user]
        Handler.send_to_users(userList, data)

    def send_back(self, data):
        """给本用户发送信息包"""
        raw_data = json.dumps(data).encode()
        self.user.client_socket.send(raw_data)
        log("[send_to_user] " + raw_data, "SUCCESS")

    def login(self, data):
        """处理登录信息包"""
        # already login
        if self.user in Handler.user_pool.keys():
            data["status"] = False
            data["info"] = "您已经登录了"
        # username in use
        elif data["username"] in Handler.user_pool.values():
            data["status"] = False
            data["info"] = "该用户名已被占用"
        else:
            data["status"] = True
            Handler.user_pool[self.user] = data["username"]
        self.send_back(data)

    def ping(self):
        self.send_back({"type": "ping"})

    def get_list(self, data):
        """获取在线用户列表"""
        data["list"] = Handler.user_pool.values()
        self.send_back(data)

    def private_chat(self, data):
        """私聊"""
        self.send_to_user(data["to"], data)

    def group_chat(self, data):
        """群聊(公共聊天)"""
        self.send_to_users(Handler.user_pool.keys(), data)

    def logout(self, data):
        """登出"""
        log("[log_out] user:{} logout".format(Handler.user_pool[self.user]), "SUCCESS")
        Handler.user_pool.pop(self.user)

    def __main__(self, data):
        """处理信息包"""
        switcher = {
            "login": self.login,
            "ping": self.ping,
            "list": self.get_list,
            "private_chat": self.private_chat,
            "group_chat": self.group_chat,
            "logout": self.logout,
        }
        try:
            return switcher[data["type"]](data)
        except Exception as e:
            log(e, "ERROR")
            data["status"] = False
            data["info"] = "未知错误"
            return data


class ClientThread(threading.Thread):
    """单个用户线程"""

    def __init__(self, addr, client_socket):
        threading.Thread.__init__(self)
        self.user = User(addr, client_socket)

    def run(self):
        try:
            handler = Handler(self.user)  # handler input
            while True:
                raw_data = self.user.client_socket.recv(BUFSIZ).decode()
                rec_data = json.loads(raw_data)
                log("receive " + raw_data)
                if rec_data["type"] == "logout":
                    break
                else:
                    handler.__main__(rec_data)
        except Exception as e:
            if str(e) != "No JSON object could be decoded":
                log("Connect Failed: " + str(e), "ERROR")
        finally:
            log(
                "[log_out] user:{} logout".format(Handler.user_pool[self.user]),
                "SUCCESS",
            )
            Handler.remove_user(self.user)
            self.user.client_socket.close()

    def stop(self):
        try:
            self.user.client_socket.shutdown(2)
            self.user.client_socket.close()
        except Exception as e:
            log(e, "ERROR")
            pass


class Server:
    def __main__(self):
        server_socket = socket(AF_INET, SOCK_STREAM)
        server_socket.bind(ADDR)
        server_socket.listen(5)

        client_thread_pool = []

        while True:
            try:
                log("Waiting for connection")
                client_socket, addr = server_socket.accept()
                log("connected from:" + str(addr), "SUCCESS")

                client_thread_pool.append(ClientThread(addr, client_socket))
                client_thread_pool[-1].start()

            except KeyboardInterrupt:
                log("shutdown")
                for t in client_thread_pool:
                    t.stop()
                break

        server_socket.close()


def log(msg, type=None):
    if type == "ERROR":
        print("\033[31m[ERROR]\033[0m   {}".format(msg))
    elif type == "SUCCESS":
        print("\033[32m[SUCCESS]\033[0m {}".format(msg))
    else:
        print("\033[33m[STATUS]\033[0m  {}".format(msg))


if __name__ == "__main__":
    pic = ";;;;;;;;;;;;;;;;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;!!!;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;!!!!;;;;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;!!!;;;;;;;;;;!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;!!!!!!!!!!!!!!!!!!||%%||!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;!!!!!!!!!!!!$@############&$$$%|!!|!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;!!!!!!!!|&#######################@&%|!!!!!!!!!!!!!!!!!!!!!!!!!!!\n!!!!!!!;!!!;;;;;;;;!!!!!!|$@#############################@$%!!!!!!!!!!!!!!!!!!!!!!!!!\n!!!!!!!!!!!!!!!;;;;;!!!|&###################################&|!!!!!!!!!!!!!!!!!!!!!!!\n!!!!!!!!!!!!!!!;;;!!!!$#######################################&%!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;!!!!!!!;;!!!!%@#########################################@$|!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;!!!%@############@@@##@@@@@@@@@@&&&@@@@#########@&|!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!!!$@######@@@@@@&&&&@@&&&&&&&&&&$$%$$$$$&@@##@@##@&|!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!!%@####@@@@&&$$$%$%$$$$$%%%%$$%|||||%%|||%$&@####@@$!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!|&@@@@@@@&$$%%||||!|%||!!;!!!!!!;!!!!!;!!!||$@###@@&|!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!$@@@##@@&$%|!!!!;;::;;;:::::::::::;;;;;;;;!!|$@###@@%!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;!|&@@@##@&%|!;:::::''''''''''''''':::::::::;;;!|&###@@$|!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;!%&@@@@@&$|!::::'''''''''''''''''''''::::::::;;!$@###@&|!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;!%&@@@&&$|;::''':::''''''''''''''''':::;!!;:::;;|$@@@@$|!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;|&@@@&$|;::':::;;;!!!;;::''```'':;;!!!!!!!;;;:;;%&@@@$!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!%&@@@$!::'::::''''''::::''''''':::'''''::;;;::;|&@@&|!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;!|%&##$;:'''::':::;;:::''''``'':''':;;;;;;;;::::!&@$|!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;!!::|%%%!;:'':;;;||!!;:::::::::':;|%%|!!;::;;||%|!;||!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;!;::|!:''::''::'::;;;;:;!;:';!;;;;;;;:;;;;;;;::;||:!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;'';;::''''''''''''''''::''::::::'''''''':''::;|!;!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;::;!;::''`````''''''''''''''::::''''''''''''::;!;;;;!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;::;;::''``````````''''''`''':::''```````'''::;;;;;!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;:::::'''````````'':''''``''::;;:'`````''':::;;;;!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;:::::'''``````''::';|;:':;!;:;;''````'''::;;;;!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;:::''''````'''''':::::::;::'''''''''':::;;;;!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;::'''''``''''''''''':'':::'''''''''':::;!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;::''''''''''''''''''''''::::''''''':::;;!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;;:'''''''':;!!!!!!!|!|||||!!::'''::::;;!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;!!;;:::'''''::''::::::;;;;::::::::::::;;!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;;;;;;:::::'''''':::;;;::::::::::;;;;||!!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;;|&%;;;;::''''''''''''''''::::;;;!!$#&|!!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;;!$#$;;;!!;::''''''''''''''::;;!!!!!$#&%|!!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;;;;;;;|%$#&;::;;!!;;:::::::::::;;;!!|!!;;;$#&$$|!!!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;;;;;;;!|%$$$$%$@&!::::;;!!|||||||%%||%%||!!;;;;!$#$%$$%|!!!!!!!!!!!!!!!!!!!\n;;;;;;;;;;!!|%%$%%$$$%$%$&@%:':::::;;;!!|||%|||!!!;;;;:;;%&@$%$$%$$$%|!!!!!!!!!!!!!!!\n;;;;;;;!|%%||%%%$&&$$%%%%$&@%:''':::::::::;;;;;;;;;::::;|&&&$%$$$%$$$&$%%|!!!!!!!!!!!\n;;!!!|%%%||%|%$$&&&$%$%|%$$&&%:''''::::::::::;;;::::::;!$&$$%%$$$%$$$$%$$$$%%%|!!!!!!\n|||||%%$$$$$%$$$&$$$%$%|%%$&$&%;''''':::;;;;;;:::::::;!$&$$$%%$$$%%$$%$$$$$&$%%%%||!!\n|%%$%%$$$$$$%$$$$%$%%%$$@##@&$$$|;''''''::::::::::::;|$$&$$$%%$$$%%$%$$$$$&&$%%$$$|%|\n%%%%%%%%%%&$%$$$$$%$$@######&$$$%|!:''''':::::'''':;|%$$&####@$$$%%$$$%$&&&$$%%$$$$$%\n%%$%|%%$%$&$%%$$$%$@####@@@@@&&&&$%!;:''''''''''':!|%$$&@######@$%%$$&$$&&$$$%%$$%%$%\n$%%||%$$$$$%|%%$&&@&&&&$$&%%@@&$&&&$%!:'``````'':;|$$&@&&##@@####&%$$$$%$$$$%%%$$%%$%\n%%%||%$$%$$%|%$%&&$%$$$%%$%|%&&&&$$@&&%;''```''!%%%$@&$$&&&$&&$$&@@&$$%%%$$$%%%$%%%$%\n%%$||%$%%$$%%%%%%$$%%%%%%%%||%$$$$$&$&&&%;''':|$%%%&&&&$$$$$$$%%%&&@@$%%$$$$%%%$%%$$%\n%%$!|%%%%%%%%$$$$$$%|%%%%%%||%%%%%$%|%%%&$!;!|%%%%%&&&$%$$%%$$%|%$$$$$%%$%$$$$%$%%$$%\n%%$!|%%%%%%|!%%%%%%||%%%%%%||%%%%%$%|%$%%&@$%%%||&&$&$|%$$%%$%||%$%%$%|%$$$$$%%$$%%%|\n%%%|||%||%%|!%%%|%%|!|%%%%%%||%%%%$$||%$$%||%$$&&$%$$%|%$$%%%%||%%%%$$%%$$$%$%%%$%%%|\n%|%|||%%|%%%!%%%|%%|!|%%|%$%||%%%%$$%|$&$%&&&%%$$%%$$%|%%%%%%%||%$%%%%||%%%%$%|%$%%%|\n%|%|!|%%%%%%!|%%%|%|!|%%%%$%!|%%%%%%%|$$$$$$$%|%$%%%$%|%$%%%$%!|%$%%$%||%$%%%%|%%%$%|\n%|%|!|%%||%%!!%%%%%|!%%%%%%%||%%%%%%%%$$$%%$$||%$%%%$%|%%%%%%%!|%%%%%%||$$%%%%||%%%%|\n%|%%|!|%||%|||%||%%|!%$%|%%%||%%%%%$%%$$$%%$$||%%%%%%%!%%%|%%%!|%%%%%%||%%%%%%||%%%%|\n%|%%|!|%||%|||%%|%%|!%%%|%%%||%%%%$$$$&%$%%$$||%$%%%%|!%%%%%%%!|%%%%%%||%%%%%%!|$%%%%\n%||%|!|%%%%|!|%%|%%|!%%%||%%!|%%%%$$$&&%$%%$%||%$%%%%|!%%%%%%%!|%%%%%%!|%%%%$%||$%%%|\n%||%||%%%|%|!|%%|%%%!|%%||%%!|%$%%$$$$&%$%%$%||%%%%$%|!%%%|%%|!|%%||%%!|%%%%$|||$%%%|\n%%|%||%||%%%!|%%|%%%!|%%||%%!|%$%%$$$$&%$%%$%||%%%%%%%||%%|%%|!|%%|%%%!|%%%%%|||$%%$|\n|%%|||%%%$%|!|%%|%%|!|%%||%%!!$$%%$&$$$$&$$$$||%$%%%%|!%%%|%%|!|%%||%%!|%%%%%|||$%%$|\n%%%|!|$$%%%|||%%|%%|!|%%||%%||$$%$$&%%$$&$$$$||%%%%%%|!%%%|%%%!|%%%%%%!|%$%%$|||$%%$%\n%$$%|%$%%|%|!|%%|%%%!|%%||%%||$$%%$$%%$$$%%$$||%%%%%%|!%$%|%$%!%%%||%%!|$%%%$%|%$%%$|\n&$%$%%%%%%%|!%%%|%%%!|%%||%%||$$%%$&%|$$$%%%%||%%%%%%|!%$%%%%%|%%%%%$%||$%%%$||$$%%$|\n"
    print("\033[5;30;41m{}\033[0m".format(pic))
    Server().__main__()
