# 🦀 青蟹 (Project OAA-Desktop)

## 1. 项目简介

本项目是一款基于 **Python** 和 **PyQt5** 开发的桌面端轻量化工具，旨在通过爬取学校教务系统的数据，为学生提供直观、置顶的课程提醒。

由**青蟹 (Project OAA)**衍生出来的附属产品，纯trae开发

目前**青蟹 (Project OAA**)仅支持安卓版本，点击下载安卓版本:https://github.com/suse-edu-cn/SUSE-OAA-APP 

------

## 2. 核心技术栈

| **模块**          | **用途**                                      |
| ----------------- | --------------------------------------------- |
| **PyQt5**         | 构建 GUI 界面、处理多线程及系统托盘           |
| **Requests**      | 处理教务系统的登录请求及课表数据获取          |
| **PyCryptodome**  | 处理 RSA 加密登录逻辑（用于保护密码传输安全） |
| **BeautifulSoup** | 解析 HTML 页面以提取必要的 Session 信息       |

------

## 3. 功能特性

- **模拟登录**：支持 RSA 加密登录，自动处理教务系统的验证机制。
- **实时悬浮**：提供半透明、无边框的桌面悬浮窗，支持鼠标穿透或固定位置。
- **课程匹配**：自动根据当前系统时间匹配对应的节次（如：第 1 节 08:30 - 09:15）。
- **数据缓存**：支持本地 `json` 缓存，避免频繁登录教运系统。

------

## 4. 关键代码实现

### 4.1 课程时间定义

代码中精确定义了 2025 年后的课程时间表：

Python

```
DAILY_SCHEDULE = [
    {"name": "1", "start": "08:30", "end": "09:15"},
    {"name": "2", "start": "09:20", "end": "10:05"},
    {"name": "3", "start": "10:25", "end": "11:10"},
    # ... 后续节次以此类推
]
```

### 4.2 异步启动逻辑

为了防止 UI 界面在登录或获取数据时卡死，采用了 `QTimer` 和 `QThread` 结合的方式：

Python

```
# 核心修复：使用 QTimer.singleShot 将 UI 创建任务抛给主线程事件循环
QTimer.singleShot(100, lambda: self.start_main_app(data, start_date))
```

------

## 5. 项目结构展示

1. **LoginWindow**: 处理用户凭据输入与 RSA 加密验证。
2. **ScheduleThread**: 负责后台爬取 JSON 格式的课表原数据。
3. **FloatingWindow**: 渲染最终的 UI 效果，包含当前课程高亮显示。

------

## 6. 使用说明

1. 确保已安装依赖：`pip install PyQt5 requests pycryptodome beautifulsoup4`

2. 运行 `OAA.py`。

3. 在登录界面输入教务系统的账号密码。

4. 程序启动后将常驻系统托盘，并弹出悬浮窗。

5. 也可以从releases里获取安装包直接安装。

   