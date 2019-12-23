from socket import *
import json
from tkinter import *
from tkinter.filedialog import askopenfilename
import threading
import struct
import uuid
import hashlib, datetime, base64

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto import Random
from Crypto.PublicKey import RSA

SENDERPORT = 1501
HOST = "127.0.0.1"  # 'chat.loopy.tech'
PORT = 8945
BUFFERSIZE = 2048
ADDR = (HOST, PORT)


class Cryptor:
    """Cryptor is based on AES-CBC-16 and RSA_PKCS"""

    def __init__(self):
        """
        init func
        :Note: should not be called
        """
        raise AttributeError("Cryptor should not be instantiated")

    @classmethod
    def set_AES_key(cls, AES_key):
        cls.__AES_key = AES_key

    @staticmethod
    def generate_RSA_key():
        """
        generate a RSA key pair

        :return: tuple_of_byte (public_pem,private_pem)
        """
        rsa = RSA.generate(1024, Random.new().read)
        private_pem = rsa.exportKey()
        public_pem = rsa.publickey().exportKey()
        return public_pem, private_pem

    @staticmethod
    def generate_AES_key():
        """
        Generate a AES key

        :return: byte AES key
        """
        return Random.get_random_bytes(16)

    @classmethod
    def AES_encrypt(cls, text, key=None):
        """
        Encrypt: Encode the string into a byte-stream, then add it to a multiple of 16, then obtained a \
        symmetric encryption key that is updated daily and then encrypt the string with the key.It is worth noting \
        that '\0' is used in the completion.

        :param text: str String to be encrypted
        :param key: byte AES key
        :return: byte Encrypted byte stream
        """
        key = cls.__AES_key if key is None else key
        text += "\0" * (16 - (len(text.encode()) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(text.encode())

    @classmethod
    def AES_decrypt(cls, byte, key=None):
        """
        Decrypt: Obtained the symmetric encrypted key, decrypt the byte stream and removed '\0',finally decoded\
         it into a string

        :param byte: byte Byte stream to be decrypted
        :param key: byte AES key
        :return: str Decrypted string
        """
        key = cls.__AES_key if key is None else key
        plain_text = AES.new(key, AES.MODE_CBC, key).decrypt(byte)
        return plain_text.decode().rstrip("\0")

    @staticmethod
    def RSA_encrypt(byte, public_key):
        """
        Encrypt: import a RSA public key and use it to encrypt a byte stream

        :param byte: byte Byte stream to be encrypted
        :param public_key: byte RSA public_key
        :return: byte Encrypted byte stream
        """
        rsa_key = RSA.importKey(public_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        cipher_byte = base64.b64encode(cipher.encrypt(byte))
        return cipher_byte

    @staticmethod
    def RSA_decrypt(byte, private_key):
        """
        Decrypt: import a RSA public key and use it to decrypt a byte stream

        :param byte: byte Byte stream to be decrypted
        :param private_key: byte RSA private_key
        :return: byte Decrypted byte
        """
        rsa_key = RSA.importKey(private_key)
        cipher = PKCS1_v1_5.new(rsa_key)
        text = cipher.decrypt(base64.b64decode(byte), "ERROR")
        return text


class Client:
    def __init__(self):
        self.connected = False

    def connect(self):
        """连接服务器"""
        if not self.connected:
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect(ADDR)
            self.key_exchange()
            self.connected = True

    def key_exchange(self):
        """
        exchange AES key with client: The client generates an RSA key pair and sends the public key to the server, \
         which generates an AES key for this socket. The server uses the RSA public key of the client to encrypt the\
         AES key as a ciphertext and sends it back to the client, who decrypts the ciphertext and obtains the AES key\
         of the socket
        
        """
        pub_key, pri_key = Cryptor.generate_RSA_key()
        self.client_socket.send(pub_key)
        cipher_RSA_key = self.client_socket.recv(BUFFERSIZE)
        Cryptor.set_AES_key(Cryptor.RSA_decrypt(cipher_RSA_key, pri_key))

    def disconnect(self):
        """断开服务器"""
        self.client_socket.close()

    @staticmethod
    def error_window(error_info):
        """错误提示界面"""
        error_window = Tk()
        screenwidth = error_window.winfo_screenwidth()
        screenheight = error_window.winfo_screenheight()
        width = 200
        height = 120
        alignstr = "%dx%d+%d+%d" % (
            width,
            height,
            (screenwidth - width) / 2,
            (screenheight - height) / 2,
        )
        error_window.geometry(alignstr)
        error_window.title("错误")
        Label(error_window, text=error_info).pack(padx=5, pady=20, fill="x")
        button = Button(error_window, text="确定", command=error_window.destroy)
        button.place(relx=0.3, rely=0.5, relwidth=0.4, relheight=0.3)
        error_window.mainloop()

    class Login:
        """登录界面"""

        def __init__(self, father):
            self.father = father

        def login(self, username, login_window):
            """登录操作"""
            self.father.username = username
            data = {"type": "login", "username": username}
            try:
                self.father.connect()
            except Exception as e:
                print(e)
                self.father.error_window("网络连接异常，无法连接到服务器")
                return False
            else:
                raw_data = Cryptor.AES_encrypt(json.dumps(data))
                socket = self.father.client_socket
                socket.send(raw_data)
                raw_data = Cryptor.AES_decrypt(socket.recv(BUFFERSIZE))
                recv_data = json.loads(raw_data)
                if (
                    recv_data["type"] == "login"
                    and recv_data["username"] == username
                    and recv_data["status"] == True
                ):
                    # login success!
                    mainFrame = self.father.MainFrame(self.father)
                    login_window.destroy()
                    mainFrame.__main__()
                else:
                    # login failed
                    if recv_data["info"]:
                        self.father.error_window(recv_data["info"])
                    else:
                        self.father.error_window("未知登录错误")

        def window(self):
            """登录窗口GUI"""
            window = Tk()
            # mycanvas=Canvas(window,width=580,height=400,bg='red')
            # mycanvas.pack()
            # window.attributes("bg",red)
            screenwidth = window.winfo_screenwidth()
            screenheight = window.winfo_screenheight()
            width = 300
            height = 400
            alignstr = "%dx%d+%d+%d" % (
                width,
                height,
                (screenwidth - width) / 2,
                (screenheight - height) / 2,
            )
            window.geometry(alignstr)
            window.title("登录")
            window.resizable(width=False, height=False)
            # frame = Frame(window)
            # frame.pack(expand=YES, fill=BOTH)

            # Label
            # lable = Label(window, font=("Wawati SC", 30), text="请输入用户名", anchor="n").pack(
            #     padx=10, pady=15, fill="x"
            # ).place(relx=0.15, rely=0.1)

            lable = Label(window, font=("Wawati SC", 30), text="请输入用户名", anchor="n")
            lable.place(relx=0.19, rely=0.01)
            # lable.pack(
            #     padx=10, pady=15, fill="x"
            # )
            # lable
            # Username Entry
            username_entry = Entry(window, font=17, justify="center")
            username_entry.place(relx=0.05, rely=0.15, relwidth=0.9, relheight=0.1)
            username_entry.bind(
                "<Key-Return>", lambda x: self.login(username_entry.get(), window)
            )

            # Login Button
            button = Button(
                window,
                text="登录",
                font=50,
                command=lambda: self.login(username_entry.get(), window),
            )
            button.place(relx=0.2, rely=0.3, relheight=0.1, relwidth=0.2)

            # ! Logo Coon
            # Coonda = Label(window, font="Arial, 20", text="请输入用户名", anchor="n").pack(
            #     padx=10, pady=15, fill="x"
            # )

            img_gif = PhotoImage(file="./client/coonda1.gif")
            label_img = Label(window, image=img_gif)
            label_img.pack()
            label_img.place(relx=0.16, rely=0.5)
            label_img.borderwidth = 0

            coonda_text = Label(window, text="COONDA", font=("Phosphate", 30))
            # coonda_text.borderwidth = 0
            coonda_text.place(relx=0.29, rely=0.45)

            # Exit Button
            button = Button(window, text="退出", font=50, command=window.destroy)
            button.place(relx=0.6, rely=0.3, relheight=0.1, relwidth=0.2)

            window.mainloop()

        def __main__(self):
            self.window()

    class MainFrame:
        """聊天主窗口"""

        def __main__(self):
            # 开启监听线程
            self._listen_thread = self.ListenThread(self.socket, self)
            self._listen_thread.start()

            # 建立窗口
            self._window = self.Window(self)
            self._window.__main__()

        def __init__(self, father):
            self.father = father
            self.socket = father.client_socket  # may raise a Exception
            self.recv_socket = None
            self.send_socket = self.socket
            self.username_list = None
            self.ack_buffer = []
            self.did_get_ack = False

        def exit(self):
            """点击退出按钮"""
            self.send_socket.close()
            self.recv_socket.close()
            self._listen_thread.join()
            self._window.destroy()

        class ListenThread(threading.Thread):
            """Socket监听线程，对收到的信息作出相应反馈"""

            def __init__(self, socket, father):
                threading.Thread.__init__(self)
                self.father = father
                self.socket = socket
                self.father.recv_socket = socket

            def run(self):
                while True:
                    try:
                        raw_data = Cryptor.AES_decrypt(self.socket.recv(BUFFERSIZE))
                        data = json.loads(raw_data)
                        # print(data)
                    except:
                        break
                    switcher = {
                        "list": self.list,
                        "private_msg": self.chat,
                        "group_msg": self.chat,
                        "ping": self.ping,
                        "file": self.recv_file,
                        "ack": self.recv_ack,
                    }
                    switcher[data["type"]](data)

            def recv_ack(self, _):
                self.father.did_get_ack = True

            def send_ack(self):
                self.socket.send(Cryptor.AES_encrypt(json.dumps({"type": "ack"})))
                # print('send_ack' + "=" * 64)

            def recv_file(self, data):
                # print("[RECV_FILE]")

                self.send_ack()
                file_remain_size = data["size"]
                file_ext = data["ext"]
                file_sender = data["from"]
                bin_data = b""
                while file_remain_size > 0:
                    buffer = self.socket.recv(
                        BUFFERSIZE
                        if file_remain_size > BUFFERSIZE
                        else file_remain_size
                    )
                    file_remain_size -= len(buffer)
                    bin_data += buffer
                    if not buffer:
                        break

                file_name = "./" + str(uuid.uuid4()) + "." + file_ext

                # print(file_name, file_remain_size)

                with open(file_name, "wb") as f:
                    f.write(bin_data)

                text_box = self.father.text_box
                t = "[" + file_sender + "]发给你了一个文件：" + file_name[2:] + "\n"
                text_box.insert(END, t)

            def list(self, data):
                """刷新列表"""
                listbox = self.father.listbox
                username_list = ["群聊"]
                username_list += data["list"]
                self.father.username_list = username_list
                listbox.delete(0, END)  # 清空现有列表
                for l in username_list:
                    listbox.insert(END, l)  # 插入新列表

            def chat(self, data):
                """接收聊天信息并打印"""
                text_box = self.father.text_box
                # print(data)
                text = (
                    ("[群聊]" if data["type"] == "group_msg" else "")
                    + data["from"]
                    + ": "
                    + data["msg"]
                    + "\n"
                )
                text_box.insert(END, text)

            def ping(self):
                pass

        class Window:
            def __init__(self, father):
                self.father = father

            @staticmethod
            def refresh(socket):
                """点击刷新按钮"""
                data = {"type": "list"}
                raw_data = Cryptor.AES_encrypt(json.dumps(data))
                socket.send(raw_data)

            def send_file(self, socket, listbox):
                """点击发送文件按钮"""
                all_items = listbox.get(
                    0, END
                )  # tuple with text of all items in Listbox
                sel_idx = listbox.curselection()  # tuple with indexes of selected items
                target = [all_items[item] for item in sel_idx]
                # print(target)
                filename = askopenfilename()
                # print(filename)
                ext = filename.split(".")[-1]
                with open(filename, "rb") as f:
                    data = f.read()
                size = len(data)
                if "群聊" in target:
                    header = {
                        "type": "group_file",
                        "size": size,
                        "ext": ext,
                    }
                    t = "[-> 群聊] " + "File Sent" + "\n"
                else:
                    header = {
                        "type": "private_file",
                        "size": size,
                        "ext": ext,
                        "to": target,
                    }
                    t = "[->" + ",".join(target) + "] " + "File Sent" + "\n"
                raw_data = Cryptor.AES_encrypt(json.dumps(header))
                socket.send(raw_data)

                self.recv_ack()

                socket.send(data)
                text_box = self.father.text_box
                text_box.insert(END, t)

            # @staticmethod
            def recv_ack(self):
                loop_start_time = datetime.datetime.now()
                while (datetime.datetime.now() - loop_start_time).seconds < 3:
                    if self.father.did_get_ack:
                        self.father.did_get_ack = False
                        break

            def send(self, socket, listbox, entry_input):
                """点击发送按钮"""
                # print(listbox.curselection())
                text = entry_input.get()
                all_items = listbox.get(
                    0, END
                )  # tuple with text of all items in Listbox
                sel_idx = listbox.curselection()  # tuple with indexes of selected items
                target = [all_items[item] for item in sel_idx]
                # print(target)
                username = self.father.father.username
                if "群聊" in target:
                    data = {"type": "group_msg", "msg": text, "from": username}
                else:
                    # 私聊
                    data = {
                        "type": "private_msg",
                        "msg": text,
                        "to": target,
                        "from": username,
                    }
                    text_box = self.father.text_box
                    t = "[->" + ",".join(target) + "]" + text + "\n"
                    text_box.insert(END, t)
                raw_data = Cryptor.AES_encrypt(json.dumps(data))
                socket.send(raw_data)
                entry_input.delete(0, END)

            @staticmethod
            def didSelectOneItem(listbox, label_target):
                """双击选择列表"""
                try:
                    label_target["text"] = listbox.get(listbox.curselection())
                except:
                    pass

            def destroy(self):
                self.window.destroy()

            def __main__(self):
                father = self.father
                grandfather = self.father.father
                self.window = Tk()
                screenwidth = self.window.winfo_screenwidth()
                screenheight = self.window.winfo_screenheight()
                width = 600
                height = 400
                alignstr = "%dx%d+%d+%d" % (
                    width,
                    height,
                    (screenwidth - width) / 2,
                    (screenheight - height) / 2,
                )
                self.window.geometry(alignstr)
                self.window.title(
                    "iCoonda Chat Room [Your name: {}]".format(grandfather.username)
                )
                self.window.resizable(width=False, height=False)
                # 背景
                f = Frame(self.window, bg="#EEEEEE", width=600, height=400)
                # f.place(x=0, y=0)
                f.pack()

                # ! 聊天内容框

                text_box = Text(f, bg="#FFFFFF", width=60, height=22, bd=0)
                text_box.place(x=150, y=10, anchor=NW)
                text_box.bind("<KeyPress>", lambda x: "break")
                father.text_box = text_box
                text_box.focus_set()

                # ! 右侧选择聊天对象
                # Label(f, text="双击选择发送对象:", bg="#EEEEEE").place(x=460, y=10, anchor=NW)
                listbox = Listbox(
                    f,
                    width=13,
                    height=23,
                    bg="#FFFFFF",
                    borderwidth=0,
                    highlightthickness=0,
                    selectmode=EXTENDED,
                )
                listbox.place(x=5, y=5, anchor=NW)
                # listbox.
                father.listbox = listbox
                jjj = -80
                # 刷新列表
                button_refresh = Button(
                    f,
                    text="刷新列表",
                    bd=1,
                    relief=FLAT,
                    command=lambda: self.refresh(father.socket),
                )
                button_refresh.place(x=300 - jjj, y=372, anchor=CENTER)

                # 下方内容输入框
                # label_target = Label(f, text="群聊", bg="#FFFFFF", width=8, height=1)
                # label_target.place(x=150, y=320)
                label_target = None
                listbox.bind(
                    "<Double-Button-1>",
                    lambda x: self.didSelectOneItem(listbox, label_target),
                )
                # self.label_target = label_target
                entry_input = Entry(f, width=30)
                entry_input.place(x=230, y=318)
                entry_input.bind(
                    "<Key-Return>",
                    lambda x: self.send(father.socket, listbox, entry_input),
                )
                self.et_input = entry_input

                # 清屏按钮
                button_clear = Button(
                    f, text="清屏", command=lambda: text_box.delete(0.0, END)
                )
                button_clear.place(x=480, y=372, anchor=CENTER)

                # 发送按钮
                button_send = Button(
                    f,
                    text="发送",
                    command=lambda: self.send(father.socket, listbox, entry_input),
                )
                button_send.place(x=540, y=333, anchor=CENTER)

                # ! 退出按钮🔘
                button_send = Button(f, text="退出", command=self.father.exit,)
                button_send.place(x=560, y=371, anchor=CENTER)

                # ! button send file
                # 发送文件
                button_send_file = Button(
                    f,
                    text="发送文件",
                    command=lambda: self.send_file(father.socket, listbox),
                )
                button_send_file.place(x=190 - jjj, y=372, anchor=CENTER)

                # ! Coonda
                coon_bg = PhotoImage(file="./client/coonda_100x100.gif")
                img_bg = Label(self.window, image=coon_bg, bg=None)
                img_bg.pack()

                img_bg.place(x=0, y=300)
                img_bg.borderwidth = 0

                # 刷新列表
                self.refresh(father.socket)

                self.window.mainloop()

    def __main__(self):
        login = Client.Login(self)
        login.__main__()


if __name__ == "__main__":
    Client().__main__()
