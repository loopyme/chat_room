# chat_room

**文档见[这里](http://api.loopy.tech/chatroom/)**

Chat_room 基于python3-socket实现，前端靠TK.作为课程项目，虽然比较简单(并且丑陋)，但加密聊天室的功能都基本具备，它能实现：
 - 发送消息（私发/群发）
 - 发送文件（私发/群发）
 - 自动获取在线用户列表（也能手动刷新）
 - 加密传输（消息使用AES对称加密，AES的密钥则使用RSA加密以完成同步）


有几个分支，那些分支上都或多或少加了一些有(gui)趣(yi)的功能或者美丽的前端，但基本都能跑起来．loopyme分支的服务器端在`chat.loopy.tech`服务器的8950端口常年nohup.

![](https://github.com/loopyme/chat_room/blob/loopyme/client.png?raw=true)

> 加解密的工具我抽了出来，发布了个pip包：[项目地址](https://github.com/loopyme/loopyCrypto),[文档](http://api.loopy.tech/loopyCrypto/)
