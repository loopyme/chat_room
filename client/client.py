from socket import *
import json
from tkinter import *
import tkinter.messagebox
from tkinter.filedialog import askopenfilename
import threading
import struct
import uuid
from urllib.parse import quote, unquote

SENDERPORT = 1501
#HOST = "127.0.0.1"  # 'chat.loopy.tech'
HOST = "192.168.43.189"
PORT = 8945
BUFFERSIZE = 2048
ADDR = (HOST, PORT)


class Cryptor:

    @staticmethod
    def en(text):
        """
        Encrypt: Encode the string into a byte-stream, then add it to a multiple of 16, then obtained a \
        symmetric encryption key that is updated daily and then encrypt the string with the key.It is worth noting \
        that '\0' is used in the completion.

        :param text: str String to be encrypted
        :return: byte Encrypted byte stream
        """
        temp = quote(text)
        return bytes(temp,encoding = "utf-8")
    @staticmethod
    def de(byte):
        """
        Decrypt: Obtained the symmetric encrypted key, decrypt the byte stream and removed '\0',finally decoded\
         it into a string

        :param byte: byte Byte stream to be decrypted
        :return: str Decrypted string
        """
        temp = str(byte,encoding = "utf-8")
        return unquote(temp)

class Client:
    def __init__(self):
        self.connected = False

    def connect(self):
        """连接服务器"""
        if not self.connected:
            self.client_socket = socket(AF_INET, SOCK_STREAM)
            self.client_socket.connect(ADDR)
            self.connected = True

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

        def login(self, username, password,operate,login_window):
            """登录操作"""
            self.father.username = username
            data = {"type": operate, "username": username,"password": password}
            raw_data = Cryptor.en(json.dumps(data))
            try:
                self.father.connect()
            except Exception as e:
                self.father.error_window("网络连接异常，无法连接到服务器")
                return False
            else:
                socket = self.father.client_socket
                socket.send(raw_data)
                raw_data = Cryptor.de(socket.recv(BUFFERSIZE))
                recv_data = json.loads(raw_data)
                if (
                        recv_data["type"] == "login"
                ):
                    if(
                        recv_data["username"] == username
                        and recv_data["password"] == password
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
                else:
                    if(
                        recv_data["username"] == username
                        and recv_data["password"] == password
                        and recv_data["status"] == True
                    ):
                        #register success!
                        tkinter.messagebox.showinfo("Tip",recv_data["info"])
                    else:
                        #register  failed
                        if(recv_data["info"]):
                            self.father.error_window(recv_data["info"])
                        else:
                            self.father.error_window("未知注册错误")




        def window(self):
            """登录窗口GUI"""
            window = Tk()
            screenwidth = window.winfo_screenwidth()
            screenheight = window.winfo_screenheight()
            width = 500
            height = 400
            alignstr = "%dx%d+%d+%d" % (
                width,
                height,
                (screenwidth - width) / 2,
                (screenheight - height) / 2,
            )
            window.geometry(alignstr)
            window.title("登录/注册")
            window.resizable(width=False, height=False)
            #插图
            img_gif = PhotoImage(file = './client/cqu.gif')
            label_img = Label(window, image = img_gif)
            label_img.pack()
            label_img.place(relx=0.06, rely=0.01)
            label_img.borderwidth = 0
            #标题
            lable = Label(window, font=("Wawati SC", 30), text="欢迎来到CQU聊天室", anchor="n")
            lable.place(relx=0.19, rely=0.3)
            # 标签 账号密码
            Label(window,text='用户名:').place(x=100,y=170)
            Label(window,text='密码:').place(x=100,y=210)
            # 用户名输入框
            entry_usr_name=Entry(window)
            entry_usr_name.place(x=160,y=170)
            #密码输入框
            entry_usr_pwd=Entry(window,show='*')
            entry_usr_pwd.place(x=160,y=210)
            #登陆按钮
            button = Button(
                window,
                text="登录",
                font=50,
                command=lambda: self.login(entry_usr_name.get(), entry_usr_pwd.get(),"login",window),
            )
            button.place(relx=0.2, rely=0.6, relheight=0.1, relwidth=0.15)
            #注册按钮
            button = Button(
                window,
                text="注册",
                font=50,
                command=lambda: self.login(entry_usr_name.get(), entry_usr_pwd.get(),"register",window),
            )
            button.place(relx=0.4, rely=0.6, relheight=0.1, relwidth=0.15)
            #退出按钮
            button = Button(
                window,
                text="退出",
                font=50,
                command=window.destroy
            )
            button.place(relx=0.6, rely=0.6, relheight=0.1, relwidth=0.15)

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
                        raw_data = Cryptor.de(self.socket.recv(BUFFERSIZE))
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
                self.socket.send(Cryptor.en(json.dumps({"type": "ack"})))
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
                raw_data = Cryptor.en(json.dumps(data))
                socket.send(raw_data)

            def send_file(self, socket, listbox):
                """点击发送文件按钮"""
                all_items = listbox.get(0, END) # tuple with text of all items in Listbox
                sel_idx = listbox.curselection() # tuple with indexes of selected items
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
                raw_data = Cryptor.en(json.dumps(header))
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
                all_items = listbox.get(0, END) # tuple with text of all items in Listbox
                sel_idx = listbox.curselection() # tuple with indexes of selected items
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
                raw_data = Cryptor.en(json.dumps(data))
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
                self.window.title("iCoonda Chat Room [Your name: {}]".format(grandfather.username))
                self.window.resizable(width=False, height=False)
                # 背景
                f = Frame(self.window, bg="#40E0D0", width=600, height=400)
                # f.place(x=0, y=0)
                f.pack()


                # ! 聊天内容框

                text_box = Text(f, bg="#FFFFFF", width=60, height=22, bd=0)
                text_box.place(x=150, y=30, width = 400, height = 260)
                text_box.bind("<KeyPress>", lambda x: "break")
                father.text_box = text_box
                text_box.focus_set()



                # ! 右侧选择聊天对象
                # Label(f, text="双击选择发送对象:", bg="#EEEEEE").place(x=460, y=10, anchor=NW)
                listbox = Listbox(f, width=13, height=18, bg="#FFFFFF", borderwidth=0, highlightthickness=0, selectmode=EXTENDED)
                listbox.place(x=20, y=50, anchor=NW)
                # listbox.
                father.listbox = listbox
                # 刷新列表
                # button_refresh = Button(
                #     f,
                #     text="刷新列表",
                #     bd=1,
                #     relief=FLAT,
                #     command=lambda: self.refresh(father.socket),
                # )
                # button_refresh.place(x=300-jjj, y=372, anchor=CENTER)

                # 下方内容输入框
                # label_target = Label(f, text="群聊", bg="#FFFFFF", width=8, height=1)
                # label_target.place(x=150, y=320)

                listbox.bind(
                    "<Double-Button-1>",
                    lambda x: self.didSelectOneItem(listbox, label_target),
                )

                # self.label_target = label_target
                entry_input = Entry(f, width=30)
                entry_input.place(x=160, y=330)
                entry_input.bind(
                    "<Key-Return>",
                    lambda x: self.send(father.socket, listbox, entry_input),
                )
                self.et_input = entry_input

                # # 清屏按钮
                # button_clear = Button(
                #     f, text="清屏", command=lambda: text_box.delete(0.0, END)
                # )
                # button_clear.place(x=480, y=372, anchor=CENTER)

                # 发送按钮
                button_send = Button(
                    f,
                    text="发送",
                    command=lambda: self.send(father.socket, listbox, entry_input),
                )
                button_send.place(x=470, y=340, anchor=CENTER)

                # ! 退出按钮🔘
                button_send = Button(f, text="退出", command=self.father.exit, )
                button_send.place(x=550, y=380, anchor=CENTER)

                # ! button send file
                # 发送文件
                button_send_file = Button(
                    f,
                    text="发送文件",
                    command=lambda: self.send_file(father.socket, listbox),
                )
                button_send_file.place(x=550, y=340, anchor=CENTER)

                # ! Coonda
                coon_bg = PhotoImage(file = './client/ican.gif')
                img_bg = Label(self.window, image=coon_bg, bg=None)
                img_bg.pack()

                img_bg.place(x=10, y=10)
                img_bg.borderwidth = 0

                # 刷新列表
                #self.refresh(father.socket)

                self.window.mainloop()

    def __main__(self):
        login = Client.Login(self)
        login.__main__()


if __name__ == "__main__":
    Client().__main__()
