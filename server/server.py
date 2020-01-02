import threading, json, datetime
from loopyCryptor import Cryptor
from socket import socket, AF_INET, SOCK_STREAM

BUFFERSIZE = 2048
ADDR = ("", 8950)


class User:
    """User struct"""

    def __init__(self, address, client_socket):
        self.address = address
        self.client_socket = client_socket
        self.AES_key = Cryptor.generate_AES_key()


class Handler:
    """
    Handle the msg or files
    """

    user_pool = {}  # user: username
    ack_buffer = []

    def __init__(self, user):
        self.user = user

    @classmethod
    def remove_user(cls, user):
        """
        remove user from user_pool

        :method: classmethod
        :param user: user_instance user to be removed
        """
        try:
            cls.user_pool.pop(user)
        except Exception as e:
            log("[Handler.remove_user] {}".format(e), "ERROR")

    @staticmethod
    def send_json(users, data):
        """
        send json to users: dumps the json data into string and send to users

        :method: staticmethod
        :param users: user_instance_list user to be sent
        :param data: json data to be sent
        """
        raw_data = json.dumps(data)
        for user in users:
            user.client_socket.send(Cryptor.AES_encrypt(raw_data, user.AES_key))
        log("[send_json] " + raw_data, "SUCCESS")

    def send_json_back(self, data):
        """
        send json back to self.user

        :param data: json data to be sent
        """
        raw_data = json.dumps(data)
        self.user.client_socket.send(Cryptor.AES_encrypt(raw_data, self.user.AES_key))
        log("[send_to_user] " + raw_data, "SUCCESS")

    def send_file(self, users, size, ext, bin_data):
        """
        send file to users: Traverse all users: send a file header and wait for ack before continuing to send\
         all file data to client

        :note: send file header first and won't send file until recv_ack
        :param users: user_instance_list user to be sent
        :param size: int size of file(byte_stream)
        :param ext: str file extension
        :param bin_data: byte file(byte_stream)
        """
        for user in users:
            # ! send file head
            self.send_json(
                [user],
                {
                    "type": "file",
                    "from": Handler.user_pool[self.user],
                    "size": size,
                    "ext": ext,
                },
            )

            self.recv_ack(user)
            user.client_socket.send(bin_data)
            log("[send_file] To:" + Handler.user_pool[user], "SUCCESS")

    def recv_file(self, size):
        """
        recv file from self.user: send ack to allow client send file, then recv file piece by piece until\
         file size matches or none have received.

        :param size: int size of file(byte_stream)
        """
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
        log("[recv_file] From:" + Handler.user_pool[self.user], "SUCCESS")
        return bin_data

    def send_ack(self):
        """
        send ack to allow client send file
        """
        self.user.client_socket.send(
            Cryptor.AES_encrypt(json.dumps({"type": "ack"}), self.user.AES_key)
        )
        log("[send_ack]", "SUCCESS")

    def recv_ack(self, user):
        """
        recv ack to allow self send file

        :note: if user!=self.user, ack package is handled by other threads. Threads communicate through\
         Handler.ack_buffer to share recv_ack information
        :param user: user_instance
        """
        if user.address != self.user.address:
            loop_start_time = datetime.datetime.now()
            while (datetime.datetime.now() - loop_start_time).seconds < 3:
                if user in Handler.ack_buffer:
                    Handler.ack_buffer.remove(user)
                    log("[recv_ack]", "SUCCESS")
                    return
        else:
            raw_data = Cryptor.AES_decrypt(
                user.client_socket.recv(BUFFERSIZE), user.AES_key
            )
            if json.loads(raw_data)["type"] == "ack":
                log("[recv_ack]", "SUCCESS")
                return

    @staticmethod
    def private_msg(data):
        """
        forward private msg for self.user

        :param data: json private msg
        """
        Handler.send_json(
            [k for k, v in Handler.user_pool.items() if v in data["to"]], data
        )

    @staticmethod
    def group_msg(data):
        """
        forward group msg for self.user

        :param data: json group msg
        """
        Handler.send_json(Handler.user_pool.keys(), data)

    def private_file(self, data):
        """
        forward private file for self.user

        :param data: json private file header
        """
        bin_data = self.recv_file(size=data["size"])
        self.send_file(
            users=[k for k, v in Handler.user_pool.items() if v in data["to"]],
            size=data["size"],
            ext=data["ext"],
            bin_data=bin_data,
        )

    def group_file(self, data):
        """
        forward group file for self.user

        :param data: json group file header
        """
        bin_data = self.recv_file(size=data["size"])
        self.send_file(
            users=list(Handler.user_pool.keys()),
            size=data["size"],
            ext=data["ext"],
            bin_data=bin_data,
        )

    def login(self, data):
        """
        deal with the login package

        :param data: json login package
        """
        if self.user in Handler.user_pool.keys():  # already login
            data["status"] = False
            data["info"] = "您已经登录了"
        elif data["username"] in Handler.user_pool.values():  # username in use
            data["status"] = False
            data["info"] = "该用户名已被占用"
        else:  # login success
            temp_user = list(Handler.user_pool.keys())
            data["status"] = True
            Handler.user_pool[self.user] = data["username"]
            self.send_json(
                temp_user, {"type": "list", "list": list(Handler.user_pool.values())}
            )
        self.send_json_back(data)

    def logout(self, _):
        """
        deal with the logout package

        :param _: useless
        """
        log(
            "[log_out] user:{} logout".format(Handler.user_pool[self.user]), "SUCCESS",
        )
        Handler.user_pool.pop(self.user)

    def ping(self):
        """ping"""
        self.send_json_back({"type": "ping"})

    def get_list(self, data):
        """
        get user list

        :param data: json
        """
        data["list"] = list(Handler.user_pool.values())
        print(data)
        self.send_json_back(data)

    def __main__(self, data):
        """
        main process of handler
        Use switcher to switch the package type, and run the corresponding handle_function.

        :param data: json recv_package
        """
        switcher = {
            "login": self.login,
            "logout": self.logout,
            "ping": self.ping,
            "list": self.get_list,
            "private_msg": self.private_msg,
            "group_msg": self.group_msg,
            "private_file": self.private_file,
            "group_file": self.group_file,
            "ack": lambda x: Handler.ack_buffer.append(self.user),
        }
        try:
            return switcher[data["type"]](data)
        except Exception as e:
            log("[Handler.__main__] {}".format(e), "ERROR")
            data["status"] = False
            data["info"] = "未知错误"
            return data


class ClientThread(threading.Thread):
    """ClientThread: Each thread corresponds to one client(User)"""

    def __init__(self, addr, client_socket):
        threading.Thread.__init__(self)
        self.user = User(addr, client_socket)

    def key_exchange(self):
        """
        exchange AES key with client: The client generates an RSA key pair and sends the public key to the server, \
         which generates an AES key for this socket. The server uses the RSA public key of the client to encrypt the\
         AES key as a ciphertext and sends it back to the client, who decrypts the ciphertext and obtains the AES key\
         of the socket
        
        """
        client_pub_key = self.user.client_socket.recv(BUFFERSIZE)
        self.user.client_socket.send(
            Cryptor.RSA_encrypt(self.user.AES_key, client_pub_key)
        )
        log("Send AES key to {}".format(self.user.address), "SUCCESS")

    def run(self):
        """
        main process of ClientThread
        Instantiate one handler, recv byte stream and decrypt it, then load it as json, pass the json to the handler.\
         When handler returns logout information or some error arise, the current thread is terminated and socket is \
         closed.
        """
        try:
            handler = Handler(self.user)  # handler input
            self.key_exchange()
            while True:
                raw_data = Cryptor.AES_decrypt(
                    self.user.client_socket.recv(BUFFERSIZE), self.user.AES_key
                )
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
                "[log_out] user:{} logout".format(Handler.user_pool[self.user]),
                "SUCCESS",
            )
            Handler.remove_user(self.user)
            self.user.client_socket.close()

    def stop(self):
        try:
            # self.user.client_socket.shutdown(2)
            self.user.client_socket.close()
        except Exception as e:
            log("[ClientThread.stop] {}".format(e), "ERROR")
            pass


class Server:
    """Server: Task distributor"""

    @staticmethod
    def __main__():
        """
        main process of server
        Run a socket to receive new connection, When a new link is created,\
         a corresponding thread is instantiated to handle all requests from users on that link
        """
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


def log(msg, msg_type=None):
    """
    log the msg

    :param msg: any_type msg to log
    :param msg_type: str optional msg type
    """
    if msg_type == "ERROR":
        print("\033[31m[ERROR]\033[0m   {}".format(msg))
    elif msg_type == "SUCCESS":
        print("\033[32m[SUCCESS]\033[0m {}".format(msg))
    else:
        print("\033[33m[STATUS]\033[0m  {}".format(msg))


if __name__ == "__main__":
    Server.__main__()
