# AutoRoute

根据apnic的信息，自动分离本地和vpn的路由信息。

仅适用于windows系统。

直接调用WindowsAPI，比route add命令快的多，添加一万条路由信息一秒内搞定。

同步备份已添加的信息，可自动删除。

轻量代码，一个cpp搞定，无外部依赖项。

