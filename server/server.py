from socket import *
import threading
import json
from Crypto.Cipher import AES
import hashlib, datetime

HOST = ""
PORT = 8945
BUFFERSIZE = 2048
ADDR = (HOST, PORT)


class Crypt:
    @staticmethod
    def __key():
        sha256 = hashlib.sha256()
        sha256.update(str(datetime.date.today()).encode("utf-8"))
        return sha256.hexdigest()[16:32].encode()

    @staticmethod
    def en(text):
        key = Crypt.__key()
        text += "\0" * (16 - (len(text.encode()) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(text.encode())

    @staticmethod
    def de(text):
        key = Crypt.__key()
        plain_text = AES.new(key, AES.MODE_CBC, key).decrypt(text)
        return plain_text.decode().rstrip("\0")


class User:
    def __init__(self, address, client_socket):
        self.address = address
        self.client_socket = client_socket


class MsgHandler:
    user_pool = {}  # user: username
    ack_buffer = []

    def __init__(self, user):
        self.user = user

    @classmethod
    def remove_user(cls, user):
        try:
            cls.user_pool.pop(user)
        except Exception as e:
            log("[MsgHandler.remove_user] {}".format(e), "ERROR")

    @staticmethod
    def send_json(users, data):
        raw_data = json.dumps(data)
        for user in users:
            user.client_socket.send(Crypt.en(raw_data))
        log("[send_json] " + raw_data, "SUCCESS")

    def send_json_back(self, data):
        raw_data = json.dumps(data)
        self.user.client_socket.send(Crypt.en(raw_data))
        log("[send_to_user] " + raw_data, "SUCCESS")

    def send_file(self, users, size, ext, bin_data):
        for user in users:
            print(user)
            # ! send file head
            self.send_json(
                [user],
                {
                    "type": "file",
                    "from": MsgHandler.user_pool[self.user],
                    "size": size,
                    "ext": ext,
                },
            )

            self.recv_ack(user)
            user.client_socket.send(bin_data)
            log("[send_file] To:" + MsgHandler.user_pool[user], "SUCCESS")

    def recv_file(self, size):
        self.send_ack()
        bin_data = b""
        while size > 0:
            buffer = self.user.client_socket.recv(
                BUFFERSIZE if size > BUFFERSIZE else size
            )
            size -= len(buffer)
            bin_data += buffer
            if not buffer:
                break
        log("[recv_file] From:" + MsgHandler.user_pool[self.user], "SUCCESS")
        return bin_data

    def send_ack(self):
        print("=" * 32 + "server send_ack")
        self.user.client_socket.send(Crypt.en(json.dumps({"type": "ack"})))

    def recv_ack(self, user):
        if user.address != self.user.address:
            while True:
                if user in MsgHandler.ack_buffer:
                    MsgHandler.ack_buffer.remove(user)
                    print("=" * 32 + "server recv_ack")
                    return
        else:
            raw_data = Crypt.de(user.client_socket.recv(BUFFERSIZE))
            if json.loads(raw_data)["type"] == "ack":
                print("=" * 32 + "server recv_ack")
                return

    @staticmethod
    def private_msg(data):
        MsgHandler.send_json(
            [k for k, v in MsgHandler.user_pool.items() if v == data["to"]], data
        )

    @staticmethod
    def group_msg(data):
        MsgHandler.send_json(MsgHandler.user_pool.keys(), data)

    def private_file(self, data):
        bin_data = self.recv_file(size=data["size"])
        self.send_file(
            users=[k for k, v in MsgHandler.user_pool.items() if v == data["to"]],
            size=data["size"],
            ext=data["ext"],
            bin_data=bin_data,
        )

    def group_file(self, data):
        bin_data = self.recv_file(size=data["size"])
        self.send_file(
            users=list(MsgHandler.user_pool.keys()),
            size=data["size"],
            ext=data["ext"],
            bin_data=bin_data,
        )

    def login(self, data):
        if self.user in MsgHandler.user_pool.keys():  # already login
            data["status"] = False
            data["info"] = "您已经登录了"
        elif data["username"] in MsgHandler.user_pool.values():  # username in use
            data["status"] = False
            data["info"] = "该用户名已被占用"
        else:  # login success
            data["status"] = True
            MsgHandler.user_pool[self.user] = data["username"]
        self.send_json_back(data)

    def logout(self, _):
        log(
            "[log_out] user:{} logout".format(MsgHandler.user_pool[self.user]),
            "SUCCESS",
        )
        MsgHandler.user_pool.pop(self.user)

    def ping(self):
        self.send_json_back({"type": "ping"})

    def get_list(self, data):
        data["list"] = list(MsgHandler.user_pool.values())
        self.send_json_back(data)

    def __main__(self, data):
        switcher = {
            "login": self.login,
            "logout": self.logout,
            "ping": self.ping,
            "list": self.get_list,
            "private_msg": self.private_msg,
            "group_msg": self.group_msg,
            "private_file": self.private_file,
            "group_file": self.group_file,
            "ack": lambda x: MsgHandler.ack_buffer.append(self.user),
        }
        try:
            return switcher[data["type"]](data)
        except Exception as e:
            log("[MsgHandler.__main__] {}".format(e), "ERROR")
            data["status"] = False
            data["info"] = "未知错误"
            return data


class ClientThread(threading.Thread):
    def __init__(self, addr, client_socket):
        threading.Thread.__init__(self)
        self.user = User(addr, client_socket)

    def run(self):
        try:
            handler = MsgHandler(self.user)  # handler input
            while True:
                raw_data = Crypt.de(self.user.client_socket.recv(BUFFERSIZE))
                rec_data = json.loads(raw_data)
                log("receive " + raw_data)
                if rec_data["type"] == "logout":
                    break
                else:
                    handler.__main__(rec_data)
        except Exception as e:
            if str(e) != "No JSON object could be decoded":
                log("[Connect Failed] {}".format(e), "ERROR")
        finally:
            log(
                "[log_out] user:{} logout".format(MsgHandler.user_pool[self.user]),
                "SUCCESS",
            )
            MsgHandler.remove_user(self.user)
            self.user.client_socket.close()

    def stop(self):
        try:
            # self.user.client_socket.shutdown(2)
            self.user.client_socket.close()
        except Exception as e:
            log("[ClientThread.stop] {}".format(e), "ERROR")
            pass


class Server:
    @staticmethod
    def __main__():
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
    Server.__main__()
