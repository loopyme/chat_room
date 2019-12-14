from socket import *
import json
from tkinter import *
from tkinter.filedialog import askopenfilename
import threading
import struct
import uuid

SENDERPORT = 1501
MYPORT = 1234
MYGROUP = "224.1.1.1"
HOST = "127.0.0.1"  # 'chat.loopy.tech'
PORT = 8945
BUFFERSIZE = 1024 * 1024 * 2
ADDR = (HOST, PORT)
MYTTL = 255


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
            raw_data = json.dumps(data).encode()
            try:
                self.father.connect()
            except Exception as e:
                self.father.error_window("网络连接异常，无法连接到服务器")
                return False
            else:
                socket = self.father.client_socket
                socket.send(raw_data)
                raw_data = socket.recv(BUFFERSIZE).decode()
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
            lable = Label(mywindow, font="Arial, 20", text="请输入用户名", anchor="n").pack(
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
                        raw_data = self.socket.recv(BUFFERSIZE).decode()
                        data = json.loads(raw_data)
                    except:
                        break
                    switcher = {
                        "list": self.list,
                        "private_msg": self.chat,
                        "group_msg": self.chat,
                        "ping": self.ping,
                        "file": self.recv_file,
                    }
                    switcher[data["type"]](data)

            def recv_file(self, data):

                print("[RECV_FILE]")

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

                print(file_name, file_remain_size)

                with open(file_name, "wb") as f:
                    f.write(bin_data)

                text_box = self.father.text_box
                t = "[" + file_sender + "->]" + "发给了你一个文件：" + file_name[2:] + "\n"
                text_box.insert(END, t)

            def list(self, data):
                """刷新列表"""
                listbox = self.father.listbox
                list = ["群聊"]
                list += data["list"]
                listbox.delete(0, END)  # 清空现有列表
                for l in list:
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
                raw_data = json.dumps(data).encode()
                socket.send(raw_data)

            def change_address(self):
                def set_address(entry1, entry2, entry3, self, mywindow):
                    global MYPORT, MYGROUP
                    if self.father.recv_socket:
                        # 停止之前的地址
                        self.father.BroadListenThread.stop()
                        self.father.send_socket.sendto("".encode(), (MYGROUP, MYPORT))

                    try:
                        # 发送socket
                        MYGROUP = entry1.get()
                        MYPORT = int(entry2.get())
                        SENDERPORT = int(entry3.get())
                        s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
                        s.bind((HOST, SENDERPORT))
                        ttl_bin = struct.pack("@i", MYTTL)
                        s.setsockopt(IPPROTO_IP, IP_MULTICAST_TTL, ttl_bin)
                        s.setsockopt(
                            IPPROTO_IP,
                            IP_ADD_MEMBERSHIP,
                            inet_aton(MYGROUP) + inet_aton(HOST),
                        )  # 加入到组播组
                        self.father.send_socket = s

                        # 监听socket
                        so = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
                        so.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
                        so.bind((HOST, MYPORT))
                        so.setsockopt(
                            IPPROTO_IP,
                            IP_ADD_MEMBERSHIP,
                            inet_aton(MYGROUP) + inet_aton(HOST),
                        )
                        so.setblocking(FALSE)
                        self.father.recv_socket = so

                    except Exception as e:
                        self.father.father.error_window("该地址不可使用")
                    else:
                        BroadListenThread = self.father.BroadListenThread(self.father)
                        BroadListenThread.start()
                        self.father.BroadListenThread = BroadListenThread
                        mywindow.destroy()

                """修改组播地址"""
                mywindow = Tk()
                mywindow.geometry("270x120")
                mywindow.title("请修改组播设置")
                Label(mywindow, text="组播地址: ").grid(row=0, column=0)
                Label(mywindow, text="监听端口: ").grid(row=1, column=0)
                Label(mywindow, text="本地端口: ").grid(row=2, column=0)
                entry1 = Entry(mywindow)
                entry1.grid(row=0, column=1)
                entry1.insert(END, MYGROUP)
                entry2 = Entry(mywindow)
                entry2.grid(row=1, column=1)
                entry2.insert(END, MYPORT)
                entry3 = Entry(mywindow)
                entry3.grid(row=2, column=1)
                entry3.insert(END, SENDERPORT)
                Button(
                    mywindow,
                    text="确定",
                    command=lambda: set_address(entry1, entry2, entry3, self, mywindow),
                ).grid(row=3, column=0, columnspan=2)

                mywindow.mainloop()

            def send_broad(self, msg, entry_input, username):
                send_socket = self.father.send_socket
                if not send_socket:
                    self.change_address()
                else:
                    data = {"type": "broadChat", "msg": msg, "from": username}
                    raw_data = json.dumps(data).encode()
                    send_socket.sendto(raw_data, (MYGROUP, MYPORT))

                    # 清空输入框
                    entry_input.delete(0, END)

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
                    t = "[-> All] " + "File Sent" + "\n"
                else:
                    header = {
                        "type": "private_file",
                        "size": size,
                        "ext": ext,
                        "to": target,
                    }
                    t = "[->" + target + "] " + "File Sent" + "\n"
                raw_data = json.dumps(header).encode()
                socket.send(raw_data)
                import time

                time.sleep(3)
                socket.send(data)
                text_box = self.father.text_box
                text_box.insert(END, t)

            def send(self, socket, label_target, entry_input):
                """点击发送按钮"""
                text = entry_input.get()
                target = label_target["text"]
                username = self.father.father.username
                if target == "群聊":
                    data = {"type": "group_msg", "msg": text, "from": username}
                elif target == "组播":
                    self.send_broad(text, entry_input, username)
                    return
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
                raw_data = json.dumps(data).encode()
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
                try:
                    father.BroadListenThread.stop()
                    father.send_socket.sendto("", (MYGROUP, MYPORT))  # fake send
                except:
                    pass

        def __main__(self):
            # 开启监听线程
            listen_thread = self.ListenThread(self.socket, self)
            listen_thread.start()
            self.ListenThread = listen_thread

            # 建立窗口
            window = self.Window(self)
            window.__main__()
            self.window = window

    def __main__(self):
        # pass
        login = Client.Login(self)
        login.__main__()


if __name__ == "__main__":
    client = Client()
    client.__main__()
