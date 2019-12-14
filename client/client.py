from socket import *
import json
from tkinter import *
from tkinter.filedialog import askopenfilename
import threading
import struct
import uuid
from Crypto.Cipher import AES
import hashlib,datetime

SENDERPORT = 1501
HOST = "127.0.0.1"  # 'chat.loopy.tech'
PORT = 8945
BUFFERSIZE = 2048
ADDR = (HOST, PORT)

class Crypt:

    @staticmethod
    def __key():
        sha256 = hashlib.sha256()
        sha256.update(str(datetime.date.today()).encode('utf-8'))
        return sha256.hexdigest()[16:32].encode()
        

    @staticmethod
    def en(text):
        key = Crypt.__key()
        text += '\0' *(16 - (len(text.encode()) % 16))
        return AES.new(key, AES.MODE_CBC, key).encrypt(text.encode())
     
    @staticmethod
    def de(text):
        key = Crypt.__key()
        plain_text = AES.new(key, AES.MODE_CBC, key).decrypt(text)
        return plain_text.decode().rstrip('\0')
class Client:
    def __init__(self):
        self.is_connect = False

    def connect(self):
        """连接服务器"""
        if not self.is_connect:
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect(ADDR)
            self.is_connect = True

    def disconnect(self):
        """断开服务器"""
        self.client_socket.close()

    @staticmethod
    def error_window(info):
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
        Label(error_window, text=info).pack(padx=5, pady=20, fill="x")
        button = Button(error_window, text="确定", command=error_window.destroy)
        button.place(relx=0.3, rely=0.5, relwidth=0.4, relheight=0.3)
        error_window.mainloop()

    class Login:
        """登录界面"""

        def __init__(self, father):
            self.father = father

        def login(self, entry, login_window):
            """登录操作"""
            username = entry.get()
            self.father.username = username
            data = {"type": "login", "username": username}
            raw_data = Crypt.en(json.dumps(data))
            try:
                self.father.connect()
            except Exception as e:
                self.father.error_window("网络连接异常，无法连接到服务器")
                return False
            else:
                socket = self.father.client_socket
                socket.send(raw_data)
                raw_data = Crypt.de(socket.recv(BUFFERSIZE))
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
            mywindow = Tk()
            # mycanvas=Canvas(mywindow,width=580,height=400,bg='red')
            # mycanvas.pack()
            # mywindow.attributes("bg",red)
            screenwidth = mywindow.winfo_screenwidth()
            screenheight = mywindow.winfo_screenheight()
            width = 580
            height = 400
            alignstr = "%dx%d+%d+%d" % (
                width,
                height,
                (screenwidth - width) / 2,
                (screenheight - height) / 2,
            )
            mywindow.geometry(alignstr)
            mywindow.title("登录")
            mywindow.resizable(width=False, height=False)
            # frame = Frame(mywindow)
            # frame.pack(expand=YES, fill=BOTH)
            lable_ = Label(mywindow, font="Arial, 20", text="请输入用户名", anchor="n").pack(
                padx=10, pady=15, fill="x"
            )
            entry = Entry(mywindow, font=17)
            entry.place(relx=0.05, rely=0.15, relwidth=0.9, relheight=0.1)
            entry.bind("<Key-Return>", lambda x: self.login(entry, mywindow))
            button = Button(
                mywindow,
                text="登录",
                font=50,
                command=lambda: self.login(entry, mywindow),
            )
            button.place(relx=0.4, rely=0.3, relheight=0.1, relwidth=0.2)

            mywindow.mainloop()

        def __main__(self):
            self.window()

    class MainFrame:
        """聊天主窗口"""

        def __init__(self, father):
            self.father = father
            self.socket = father.client_socket  # may raise a Exception
            self.recv_socket = None
            self.send_socket = None

        class ListenThread(threading.Thread):
            """Socket监听线程，对收到的信息作出相应反馈"""

            def __init__(self, socket, father):
                threading.Thread.__init__(self)
                self.father = father
                self.socket = socket

            def run(self):
                while True:
                    try:
                        raw_data = Crypt.de(self.socket.recv(BUFFERSIZE))
                        data = json.loads(raw_data)
                    except:
                        break
                    switcher = {
                        "list": self.list,
                        "private_msg": self.chat,
                        "group_msg": self.chat,
                        "ping": self.ping,
                        "file": self.recv_file,
                        "ack": lambda x: None,
                    }
                    switcher[data["type"]](data)

            def send_ack(self):
                self.socket.send(Crypt.en(json.dumps({"type": "ack"})))

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
                listbox.delete(0, END)  # 清空现有列表
                for l in username_list:
                    listbox.insert(END, l)  # 插入新列表

            def chat(self, data):
                """接收聊天信息并打印"""
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
                """点击刷新按钮"""
                data = {"type": "list"}
                raw_data = Crypt.en(json.dumps(data))
                socket.send(raw_data)

            def send_file(self, socket, label_target):
                """点击发送文件按钮"""
                target = label_target["text"]
                filename = askopenfilename()
                # print(filename)
                ext = filename.split(".")[-1]
                with open(filename, "rb") as f:
                    data = f.read()
                size = len(data)
                if target == "群聊":
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
                    t = "[->" + target + "] " + "File Sent" + "\n"
                raw_data = Crypt.en(json.dumps(header))
                socket.send(raw_data)

                self.recv_ack(socket)

                socket.send(data)
                text_box = self.father.text_box
                text_box.insert(END, t)

            @staticmethod
            def recv_ack(socket):
                raw_data = Crypt.de(socket.recv(BUFFERSIZE))
                if json.loads(raw_data)["type"] == "ack":
                    return

            def send(self, socket, label_target, entry_input):
                """点击发送按钮"""
                text = entry_input.get()
                target = label_target["text"]
                username = self.father.father.username
                if target == "群聊":
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
                    t = "[->" + target + "]" + text + "\n"
                    text_box.insert(END, t)
                raw_data = Crypt.en(json.dumps(data))
                socket.send(raw_data)
                entry_input.delete(0, END)

            @staticmethod
            def change_target(listbox, label_target):
                """双击选择列表"""
                try:
                    label_target["text"] = listbox.get(listbox.curselection())
                except:
                    pass

            def __main__(self):
                father = self.father
                mywindow = Tk()
                screenwidth = mywindow.winfo_screenwidth()
                screenheight = mywindow.winfo_screenheight()
                width = 600
                height = 400
                alignstr = "%dx%d+%d+%d" % (
                    width,
                    height,
                    (screenwidth - width) / 2,
                    (screenheight - height) / 2,
                )
                mywindow.geometry(alignstr)
                mywindow.title("聊天室")
                mywindow.resizable(width=False, height=False)
                # 背景
                f = Frame(mywindow, bg="#EEEEEE", width=600, height=400)
                # f.place(x=0, y=0)
                f.pack()
                # 聊天内容框
                text_box = Text(f, bg="#FFFFFF", width=60, height=22, bd=0,)
                text_box.place(x=10, y=10, anchor=NW)
                text_box.bind("<KeyPress>", lambda x: "break")
                father.text_box = text_box
                text_box.focus_set()
                # 右侧选择聊天对象
                Label(f, text="双击选择发送对象:", bg="#EEEEEE").place(x=460, y=10, anchor=NW)
                listbox = Listbox(f, width=13, height=13, bg="#FFFFFF")
                listbox.place(x=460, y=35, anchor=NW)
                father.listbox = listbox
                button_refresh = Button(
                    f,
                    text="刷新列表",
                    bd=1,
                    relief=FLAT,
                    command=lambda: self.refresh(father.socket),
                )
                button_refresh.place(x=515, y=290, anchor=CENTER)
                button_clear = Button(
                    f, text="清屏", command=lambda: text_box.delete(0.0, END)
                )
                button_clear.place(x=560, y=372, anchor=CENTER)
                # 下方内容输入
                label_target = Label(f, text="群聊", bg="#FFFFFF", width=8)
                label_target.place(x=12, y=360)
                listbox.bind(
                    "<Double-Button-1>",
                    lambda x: self.change_target(listbox, label_target),
                )
                self.label_target = label_target
                entry_input = Entry(f, width=37)
                entry_input.place(x=90, y=358)
                entry_input.bind(
                    "<Key-Return>",
                    lambda x: self.send(father.socket, label_target, entry_input),
                )
                self.et_input = entry_input
                # 发送按钮
                button_send = Button(
                    f,
                    text="确认",
                    command=lambda: self.send(father.socket, label_target, entry_input),
                )
                button_send.place(x=480, y=371, anchor=CENTER)
                # ! button send file
                button_send_file = Button(
                    f,
                    text="发送文件",
                    command=lambda: self.send_file(father.socket, label_target),
                )
                button_send_file.place(x=515, y=330, anchor=CENTER)

                # 刷新列表
                self.refresh(father.socket)

                mywindow.mainloop()

                father.socket.shutdown(2)

        def __main__(self):
            # 开启监听线程
            self._ListenThread = self.ListenThread(self.socket, self)
            self._ListenThread.start()

            # 建立窗口
            self._window = self.Window(self)
            self._window.__main__()

    def __main__(self):
        login = Client.Login(self)
        login.__main__()


if __name__ == "__main__":
    Client().__main__()
