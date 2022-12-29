# 项目介绍

**BurpHeaderHelper**是基于Burpsuite的插件，通过自定义规则的来**对Http请求头进行增删改操作**。

# 使用说明

加载插件: `Extender` -> `Burp Extensions` -> `Add` -> `Select File...` -> `Next` -> `BurpHeaderHelper-xxx.jar`

![image](https://user-images.githubusercontent.com/30547741/201566106-e7c3c2aa-8147-422f-acf2-568feaf551fd.png)

说一下遇到的场景

![image](https://user-images.githubusercontent.com/30547741/201565817-481feaa9-b5cb-4c78-b188-f620611dbe16.png)

在Burp拦包时候发现浏览器总会有携带一些不必要的头信息(或许吧!)，通过一些浏览器的插件可以去除这些头信息，但是实际的情况是总会有这些冒出来(可能是插件不给力或者我使用方式不对?)！

![image](https://user-images.githubusercontent.com/30547741/201566474-3b2726ad-926d-4634-bc92-32afebb62131.png)

编写规则来去除 `Sec-Ch-Ua-Mobile` `Sec-Ch-Ua-Platform` `Sec-Fetch-Site` 这几个头信息，**并点击状态为启用**。

![image](https://user-images.githubusercontent.com/30547741/201567700-9a1987de-28b1-4919-bda8-efe23f281235.png)

在Repeater模块上重放数据包

![image](https://user-images.githubusercontent.com/30547741/201567735-a0e22d49-6f3a-4099-94c8-6c155f3652d5.png)

在服务器上查看对应的请求，可以看到相应的几个头信息都被去除。

<img width="1169" alt="image" src="https://user-images.githubusercontent.com/30547741/201567786-91647846-af65-4db3-b49e-6965070473b1.png">

编写完规则后，要进行保存，这样下次启动时将加载配置。

![image](https://user-images.githubusercontent.com/30547741/201568133-be089f7f-8c16-40e4-8dff-d39651929794.png)

Ps: **保存后会在插件当前目录下生成config.json文件，不要随意更改哦！**

# 界面预览

![image](https://user-images.githubusercontent.com/30547741/201623743-b8439c9a-ddfc-44c7-8dc9-38ef27727fd8.png)

![image](https://user-images.githubusercontent.com/30547741/201623796-84fff274-1d6f-44c0-b1a2-faaa99c3dbd6.png)

# TODO

* ~~随机UserAgent~~
* ~~RepeaterResponse自动解码unicode、url编码、html编码~~
* 分块传输
* 默认配置(fakeip, 常见信息泄露头)
