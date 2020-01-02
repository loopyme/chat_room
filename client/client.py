from loopyCryptor import Cryptor
import json, uuid, datetime, threading
from socket import socket, AF_INET, SOCK_STREAM
from tkinter.filedialog import askopenfilename
from tkinter import Label, Button, Tk, Entry, CENTER, END, Listbox, EXTENDED, NW, Text, Frame

SENDERPORT = 1501
BUFFERSIZE = 2048
ADDR = ("chat.loopy.tech", 8950)


class Client:
    def __init__(self):
        self.connected = False

    def connect(self):
        """connect to the server and exchange key"""
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
        pub_key, pri_key = Cryptor.generate_RSA_key(ret_str=False)
        self.client_socket.send(pub_key)
        cipher_RSA_key = self.client_socket.recv(BUFFERSIZE)
        Cryptor.set_AES_key(Cryptor.RSA_decrypt(cipher_RSA_key, pri_key, ret_str=False))

    def disconnect(self):
        """disconnected to the server"""
        self.client_socket.close()

    @staticmethod
    def error_window(error_info):
        """error msg window"""
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
        """login window"""

        def __init__(self, father):
            self.father = father

        def login(self, username, login_window):
            """
            login func
            :param username: string username
            :param login_window: TK window
            """
            self.father.username = username
            if username == "":
                self.father.error_window("用户名不能为空！！！")
                return False

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
            """
            login window GUI
            """
            window = Tk()
            width = 400
            height = 60
            alignstr = "%dx%d+%d+%d" % (width, height, 30, 5,)
            window.geometry(alignstr)
            window.title("聊天室登录-请输入你的用户名")
            window["background"] = "white"
            window.resizable(width=False, height=False)

            username_entry = Entry(window, width=30, justify="center")
            username_entry.place(x=180, y=25, anchor=CENTER)
            username_entry.bind(
                "<Key-Return>", lambda x: self.login(username_entry.get(), window)
            )

            # Login Button
            button = Button(
                window,
                text="登录",
                command=lambda: self.login(username_entry.get(), window),
            )
            button.place(x=350, y=25, anchor=CENTER)

            window.mainloop()

        def __main__(self):
            self.window()

    class MainFrame:
        """chat-room main window"""

        def __main__(self):
            # create listen thread
            self._listen_thread = self.ListenThread(self.socket, self)
            self._listen_thread.start()

            # create window
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
            """exit func"""
            self.send_socket.close()
            self.recv_socket.close()
            self._listen_thread.join()
            self._window.destroy()

        class ListenThread(threading.Thread):
            """listen the sockect, deal with the msg"""

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

            def recv_file(self, data):

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

                with open(file_name, "wb") as f:
                    f.write(bin_data)

                text_box = self.father.text_box
                t = "[" + file_sender + "]发给你了一个文件：" + file_name[2:] + "\n"
                text_box.insert(END, t)

            def list(self, data):
                """update chat-room user list"""
                listbox = self.father.listbox
                username_list = ["群聊"]
                username_list += data["list"]
                self.father.username_list = username_list
                listbox.delete(0, END)  # 清空现有列表
                for l in username_list:
                    listbox.insert(END, l)  # 插入新列表

            def chat(self, data):
                """recv a msg and print"""
                text_box = self.father.text_box

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
                """update chat-room user list"""
                data = {"type": "list"}
                raw_data = Cryptor.AES_encrypt(json.dumps(data))
                socket.send(raw_data)

            def send_file(self, socket, listbox):
                """send a file func"""
                all_items = listbox.get(
                    0, END
                )  # tuple with text of all items in Listbox
                sel_idx = listbox.curselection()  # tuple with indexes of selected items
                target = [all_items[item] for item in sel_idx]

                filename = askopenfilename()

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

            def recv_ack(self):
                loop_start_time = datetime.datetime.now()
                while (datetime.datetime.now() - loop_start_time).seconds < 3:
                    if self.father.did_get_ack:
                        self.father.did_get_ack = False
                        break

            def send(self, socket, listbox, entry_input):
                """send a msg"""

                text = entry_input.get()
                all_items = listbox.get(0, END)
                sel_idx = listbox.curselection()
                target = [all_items[item] for item in sel_idx]

                username = self.father.father.username
                if "群聊" in target:
                    data = {"type": "group_msg", "msg": text, "from": username}
                else:

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
                """select target"""
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
                # self.window["background"] = "white"
                self.window.geometry(alignstr)
                self.window.title("聊天室")
                self.window.resizable(width=False, height=False)
                # 背景
                f = Frame(self.window, bg="white", width=600, height=400)

                f.pack()

                # ! 聊天内容框

                text_box = Text(
                    f, bg="#FFFFFF", width=60, height=19, bd=0, borderwidth=1
                )
                text_box.place(x=150, y=10, anchor=NW)
                text_box.bind("<KeyPress>", lambda x: "break")
                father.text_box = text_box
                text_box.focus_set()

                # ! 右侧选择聊天对象
                listbox = Listbox(
                    f,
                    width=13,
                    height=20,
                    bg="#FFFFFF",
                    borderwidth=1,
                    highlightthickness=0,
                    selectmode=EXTENDED,
                )
                listbox.place(x=10, y=10, anchor=NW)
                # listbox.
                father.listbox = listbox
                jjj = -80
                # 刷新列表
                button_refresh = Button(
                    f,
                    text="刷新列表",
                    # bd=1,
                    # relief=FLAT,
                    command=lambda: self.refresh(father.socket),
                    bg="white",
                )
                # button_refresh.place(x=300 - jjj, y=372, anchor=CENTER)
                button_refresh.place(x=70, y=370, anchor=CENTER)
                # 下方内容输入框

                label_target = None
                listbox.bind(
                    "<Double-Button-1>",
                    lambda x: self.didSelectOneItem(listbox, label_target),
                )

                entry_input = Entry(f, width=46)
                entry_input.place(x=200, y=318, anchor=NW)
                entry_input.bind(
                    "<Key-Return>",
                    lambda x: self.send(father.socket, listbox, entry_input),
                )
                self.et_input = entry_input

                # 清屏按钮
                button_clear = Button(
                    f, text="清屏", command=lambda: text_box.delete(0.0, END), bg="white"
                )
                button_clear.place(x=500, y=370, anchor=CENTER)

                # 发送按钮
                button_send = Button(
                    f,
                    text="发送消息",
                    command=lambda: self.send(father.socket, listbox, entry_input),
                    bg="white",
                )
                button_send.place(x=190, y=370, anchor=CENTER)

                button_send = Button(f, text="退出", command=self.father.exit, bg="white")
                button_send.place(x=560, y=370, anchor=CENTER)

                # 发送文件
                button_send_file = Button(
                    f,
                    text="发送文件",
                    command=lambda: self.send_file(father.socket, listbox),
                    bg="white",
                )
                button_send_file.place(x=275, y=370, anchor=CENTER)

                name_box = Label(
                    f,
                    text="{}:".format(grandfather.username),
                    bg="#FFFFFF",
                    width=6,
                    height=1,
                    bd=0,
                    borderwidth=0,
                )
                name_box.place(x=150, y=318, anchor=NW)
                name_box.bind("<KeyPress>", lambda x: "break")
                name_box.focus_set()

                # 刷新列表
                self.refresh(father.socket)

                self.window.mainloop()

    def __main__(self):
        login = Client.Login(self)
        login.__main__()


if __name__ == "__main__":
    Client().__main__()
