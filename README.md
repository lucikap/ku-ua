# ku-ua

## 用于修改数据包中User-Agent字段的内核模块（类似于ua2f，但他是在内核中完成的）

## 优点：

1. 相对于ua2f来说他理论上不会太影响网速（特别是对于低端的路由来说）
2. 也许不会影响多拨和acc硬件加速？
3. 不会影响xbox和b站、微博等软件的使用（他并不会修改所有的包，只是针对性的修改携带设备信息的包）
4. 可以自定义你想要的User-Agent，这需要你同时安装luci-app-ku-ua（这并不会太麻烦）
5. 这个模块仅仅依赖netfilter，而这是大多Linux包括openwrt都会自带的网络框架，因此编译时并不需要你去勾选太多依赖项和因此带来增加内存负担的烦恼（我真牛逼）

。。。情人眼里出西施，在我眼里他的优点不仅于此，但是打字太费手

## 缺点：

1. 这是一个内核模块，众所周知，如果内核模块出现问题，那么系统就可能宕机，虽然重启能解决百分之九十九的问题，但我仍不能保证这个模块的安全性（虽然我没有遇到过死机的情况）
2. 由于内核模块需要内核版本与模块的版本一致，多以大部分情况下仍需要去手动编译（做这个插件的初衷是为了能直接安装ipk包，但是发现不能实现这个目标时我立马转变了思维：不能让科技的门槛变得太低。。。开玩笑）
3. 欢迎补充

##食用方法
```shell
#进入openwrt源码所在目录
git clone https://github.com/lucikap/ku-ua.git package/ku-ua

make menuconfig
#勾选内核模块
Kernel modules  --->
	Other modules  --->
		<*> kmod-ku-ua
#勾选界面支持（如果不需要自定义可以不选）
LuCI  --->
	3. Applications  --->
		<*> luci-app-ku-ua
#开始编译
make -j12 V=99
```

如果你有精力，甚至可以帮我写个更为精美和实用的README.md（我的邮箱169296793@qq.com）
##欢迎充电

![ed4a58c8d971716c3a5368d5ab18709](https://github.com/lucikap/ku-ua/assets/133383664/a4b0b626-dbd9-46b3-b74b-500f32253bd2)
![ed4a58c8d971716c3a5368d5ab18709](https://github.com/lucikap/ku-ua/assets/133383664/11fd6bfb-da8c-4109-a32a-0f11e9bd8a3b)
