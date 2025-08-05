# InstallSvchostService

这是一个Windows命令行工具，用于将DLL安装为Windows的Svchost服务或卸载已安装的服务。该工具可以方便地管理基于Svchost.exe的Windows服务。

## 功能特点

- 将DLL安装为Windows Svchost服务
- 自动创建并配置服务的注册表项
- 自动设置Svchost服务组
- 支持指定自定义服务组名称或自动生成随机服务组名称
- 卸载已安装的服务并清理相关注册表项
- 服务的启动、停止管理

## 编译步骤

### 使用MinGW-w64编译

1. 确保已安装MinGW-w64
   ```
   # 在Arch Linux上安装
   sudo pacman -S mingw-w64-gcc
   
   # 在Ubuntu上安装
   sudo apt install mingw-w64
   ```

2. 编译项目
   ```bash
   # 进入项目目录
   cd /path/to/InstallSvchostService
   
   # 使用MinGW-w64编译64位Windows可执行文件
   x86_64-w64-mingw32-g++ -o InstallSvchostService.exe main.cpp -std=c++17 -static -static-libgcc -static-libstdc++ -ladvapi32 -municode
   
   # 可选：编译32位Windows可执行文件
   i686-w64-mingw32-g++ -o InstallSvchostService_x86.exe main.cpp -std=c++17 -static -static-libgcc -static-libstdc++ -ladvapi32 -municode
   ```

3. 编译后将生成`InstallSvchostService.exe`可执行文件，可直接在Windows系统中运行

## 使用方法

### 安装服务
```
InstallSvchostService.exe /install <服务名称> <DLL路径> <显示名称> [服务组名称]
```

参数说明:
- `<服务名称>`: 要创建的服务的名称
- `<DLL路径>`: 服务DLL的完整路径
- `<显示名称>`: 在服务管理器中显示的服务名称
- `[服务组名称]`: 可选参数，Svchost服务组名称，如不提供则自动生成

示例:
```
InstallSvchostService.exe /install MyService C:\Windows\System32\myservice.dll "My Custom Service" MyServiceGroup
```

### 卸载服务
```
InstallSvchostService.exe /uninstall <服务名称>
```

参数说明:
- `<服务名称>`: 要卸载的服务的名称

示例:
```
InstallSvchostService.exe /uninstall MyService
```

## 注意事项

- 需要以管理员权限运行此程序
- 安装服务时会修改系统注册表，请确保有足够权限
- 此工具主要用于Windows系统服务的管理，非系统管理员请谨慎使用
- 当卸载服务时，工具会尝试停止正在运行的服务并清理相关注册表项

## 许可证

本项目采用MIT许可证，详情请参阅[LICENSE](LICENSE)文件。
请遵守相关法律法规，合理使用本工具，避免对系统造成损害。
