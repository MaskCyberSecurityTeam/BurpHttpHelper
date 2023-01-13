- [Http增删改](#http增删改)
  - [Header](#header)
  - [Cookie](#cookie)
- [随机UserAgent](#随机useragent)
- [RepeaterResponse自动解码](#repeaterresponse自动解码)
- [丢弃数据包](#丢弃数据包)

# Http增删改

BurpHttpHelper中已经默认提供了一些常见的指纹头

![image](https://user-images.githubusercontent.com/30547741/212247594-97e8d6ec-69d9-4326-8373-0c2ebb916e3b.png)

## Header

下图为服务器视角，接收到来自客户端的请求包，下边是一个demo例子，修改host头位demo.com。

<img width="1120" alt="image" src="https://user-images.githubusercontent.com/30547741/212247986-5410ce9a-22e4-4f16-825b-23d9cf910fe6.png">

**添加完规则后，需要勾选启用。**

![image](https://user-images.githubusercontent.com/30547741/212248095-0824720e-3a25-4ca5-92dd-ebb55f823bd0.png)

![image](https://user-images.githubusercontent.com/30547741/212248235-6ecbdd79-3347-44b4-9e1b-111b5dd53be7.png)

<img width="1170" alt="image" src="https://user-images.githubusercontent.com/30547741/212251127-ced622f7-c5cb-4cb0-8eaa-e3c2e50c8689.png">

## Cookie

打开添加窗口

![image](https://user-images.githubusercontent.com/30547741/212254157-784345c3-b552-41f5-a204-6d8665c87e9c.png)

Type选择为Cookie即可

![image](https://user-images.githubusercontent.com/30547741/212251356-4a032659-36ff-4ce6-a7ab-1448209bbb72.png)

![image](https://user-images.githubusercontent.com/30547741/212253266-ec200050-f875-4050-88d7-252d11bc001e.png)

服务器接收到的数据包如下

<img width="1156" alt="image" src="https://user-images.githubusercontent.com/30547741/212253460-4eea2002-8dfb-49d4-a65c-db0f58f69854.png">

# 随机UserAgent

在UA面板中勾选: `电脑(PC)` `手机(Mobile)` 有些网站上电脑UA和手机UA呈现页面不同，这里根据实际情况自己选择。

![image](https://user-images.githubusercontent.com/30547741/212234482-3ac17b06-f50a-4398-b9ac-bbe024262e29.png)

在规则面板中勾选随机UA头

![image](https://user-images.githubusercontent.com/30547741/212234262-6e6f5b62-c5c0-44b0-9b27-bce4bbbf20ae.png)

服务器接收到的数据包将为不同的UserAgent

<img width="1315" alt="image" src="https://user-images.githubusercontent.com/30547741/212234348-f94b56f7-8b71-4193-a114-4c007d62f752.png">

BurpHttpHelper中已经内置提供了一些UserAgent，可以自行通过添加UserAgent字符串进行扩展。

![image](https://user-images.githubusercontent.com/30547741/212234880-10f61436-5c80-4b27-8209-0a7a34f58697.png)

# RepeaterResponse自动解码

目前支持解码: `unicode` `url编码` `html编码`

`BurpHttpHeader` -> `勾选RepeaterResponse自动解码(Repeater Response Auto Decode)`

![image](https://user-images.githubusercontent.com/30547741/212233279-90164b48-48c3-42b9-b002-959356e31769.png)

解码前

![image](https://user-images.githubusercontent.com/30547741/212233229-97514469-4014-4f1b-8e2e-455e4d4f56b1.png)

解码后

![image](https://user-images.githubusercontent.com/30547741/212233500-015657a1-a42d-477d-a957-a8000bc5606d.png)

# 丢弃数据包

有时候不想一些请求发送到目标服务器，可以通过丢弃数据包面板进行配置。

`Extensions` -> `BurpHttpHelper` -> `丢弃该数据包`

**注意: 丢弃数据包功能，不适用于Repeater模块功能。(因为Repeater本身是用于重放，如果进行过滤，这违反了它的设计。)**

![image](https://user-images.githubusercontent.com/30547741/212231788-db6a765c-dd4b-4a79-a744-7ba27a60ca69.png)

在丢弃数据包面板(DropPacketPanel)中可以查看该过滤的数据包信息(该模块还未完善，后续会进行完善。)

![image](https://user-images.githubusercontent.com/30547741/212232464-1d854a7e-0e97-41b3-ba96-6c7f3770387b.png)
