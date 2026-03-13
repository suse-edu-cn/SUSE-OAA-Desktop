import sys
import json
import time
import base64
import datetime
import requests
import re
import os
from urllib.parse import urlparse

from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, 
                             QLineEdit, QPushButton, QMessageBox, QDesktopWidget,
                             QFrame, QHBoxLayout, QScrollArea, QTableWidget,
                             QTableWidgetItem, QHeaderView, QComboBox, QGridLayout,
                             QCheckBox, QMenu, QAction, QSystemTrayIcon, QStyle, QSizeGrip,
                             QSlider, QDialog, QListWidget, QListWidgetItem, QTimeEdit,
                             QDateEdit, QDateTimeEdit, QTextEdit)
from PyQt5.QtCore import Qt, QPoint, QTimer, QThread, pyqtSignal, QSize, QDate, QTime, QDateTime
from PyQt5.QtGui import QFont, QColor, QPalette, QCursor, QIcon, QPixmap, QPainter

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5, AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from bs4 import BeautifulSoup

# ==================== 配置 ====================

BASE_URL = "https://jwgl.suse.edu.cn"

# 2025年后的课程时间表
DAILY_SCHEDULE = [
    {"name": "1", "start": "08:30", "end": "09:15"},
    {"name": "2", "start": "09:20", "end": "10:05"},
    {"name": "3", "start": "10:25", "end": "11:10"},
    {"name": "4", "start": "11:15", "end": "12:00"},
    {"name": "午休", "start": "12:00", "end": "14:00"},
    {"name": "5", "start": "14:00", "end": "14:45"},
    {"name": "6", "start": "14:50", "end": "15:35"},
    {"name": "7", "start": "15:55", "end": "16:40"},
    {"name": "8", "start": "16:45", "end": "17:30"},
    {"name": "9", "start": "19:00", "end": "19:45"},
    {"name": "10", "start": "19:50", "end": "20:35"},
    {"name": "11", "start": "20:40", "end": "21:25"}
]

# 颜色配置
COLORS = [
    "#FFB7B2", "#FFDAC1", "#E2F0CB", "#B5EAD7", "#C7CEEA",
    "#F8BBD0", "#E1BEE7", "#D1C4E9", "#C5CAE9", "#BBDEFB",
    "#B3E5FC", "#B2EBF2", "#B2DFDB", "#C8E6C9", "#DCEDC8",
    "#F0F4C3", "#FFF9C4", "#FFECB3", "#FFE0B2", "#FFCCBC"
]

# ==================== 工具类 ====================

def find_resource(filename):
    """
    查找资源文件（支持递归查找子目录）
    """
    # 确定基准目录
    if getattr(sys, 'frozen', False):
        # 如果是打包后的exe，基准目录是exe所在目录
        base_dir = os.path.dirname(sys.executable)
    else:
        # 如果是源码运行，基准目录是脚本所在目录
        base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 1. 首先检查基准目录
    target_path = os.path.join(base_dir, filename)
    if os.path.exists(target_path):
        return target_path
        
    # 2. 遍历所有子目录查找
    for root, dirs, files in os.walk(base_dir):
        if filename in files:
            return os.path.join(root, filename)
            
    # 3. 如果还没找到，尝试检查一下当前工作目录
    if os.path.exists(filename):
        return os.path.abspath(filename)
        
    return None

class RSAEncryptor:
    @staticmethod
    def encrypt(plain_text, modulus_b64, exponent_b64):
        try:
            modulus_bytes = base64.b64decode(modulus_b64)
            exponent_bytes = base64.b64decode(exponent_b64)
            modulus = int.from_bytes(modulus_bytes, byteorder='big')
            exponent = int.from_bytes(exponent_bytes, byteorder='big')
            key = RSA.construct((modulus, exponent))
            cipher = PKCS1_v1_5.new(key)
            encrypted_bytes = cipher.encrypt(plain_text.encode('utf-8'))
            return base64.b64encode(encrypted_bytes).decode('utf-8')
        except Exception as e:
            print(f"Encryption error: {e}")
            raise

class LocalEncryptor:
    """本地加密工具类"""
    _KEY_SRC = "suse_jwgl_helper_2024_secure_key"

    @staticmethod
    def _get_key():
        # 生成 32 字节 (256位) 密钥
        return hashlib.sha256(LocalEncryptor._KEY_SRC.encode('utf-8')).digest()

    @staticmethod
    def encrypt(text):
        if not text: return ""
        try:
            # 使用 CBC 模式 + 随机 IV
            key = LocalEncryptor._get_key()
            iv = os.urandom(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_text = pad(text.encode('utf-8'), AES.block_size)
            encrypted_bytes = cipher.encrypt(padded_text)
            # 拼接 IV + 密文，并转为 Base64
            combined = iv + encrypted_bytes
            return base64.b64encode(combined).decode('utf-8')
        except Exception as e:
            print(f"Local Encrypt error: {e}")
            return text

    @staticmethod
    def decrypt(text):
        if not text: return ""
        try:
            # 尝试解密
            combined = base64.b64decode(text)
            # 提取 IV (前16字节)
            if len(combined) < 16: return text # 长度不足，可能是明文
            iv = combined[:16]
            encrypted_bytes = combined[16:]
            
            key = LocalEncryptor._get_key()
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(encrypted_bytes)
            return unpad(decrypted_padded, AES.block_size).decode('utf-8')
        except Exception:
            # 解密失败，假定为明文（兼容旧版本配置）
            return text

class SuseJwglClient:
    def __init__(self):
        self.session = None
        self._init_session()

    def _init_session(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        })

    def close_session(self):
        if self.session:
            self.session.close()
            self.session = None

    def get_csrf_token(self):
        if not self.session: self._init_session()
        url = f"{BASE_URL}/xtgl/login_slogin.html"
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            token_input = soup.find('input', {'id': 'csrftoken'})
            if token_input:
                return token_input.get('value')
        except Exception as e:
            print(f"Get CSRF error: {e}")
        return None

    def get_rsa_key(self):
        if not self.session: self._init_session()
        timestamp = int(time.time() * 1000)
        url = f"{BASE_URL}/xtgl/login_getPublicKey.html?time={timestamp}"
        response = self.session.get(url, timeout=10)
        return response.json()

    def login(self, username, password):
        if not self.session: self._init_session()
        try:
            csrf_token = self.get_csrf_token()
            if not csrf_token:
                return False, "无法获取 CSRF Token，请检查网络"

            rsa_key = self.get_rsa_key()
            modulus = rsa_key['modulus']
            exponent = rsa_key['exponent']
            encrypted_pwd = RSAEncryptor.encrypt(password, modulus, exponent)

            timestamp = int(time.time() * 1000)
            login_url = f"{BASE_URL}/xtgl/login_slogin.html?time={timestamp}"
            
            data = {
                "csrftoken": csrf_token,
                "yhm": username,
                "mm": encrypted_pwd
            }
            headers = {"Referer": f"{BASE_URL}/xtgl/login_slogin.html"}
            response = self.session.post(login_url, data=data, headers=headers, timeout=10)
            
            if "用户登录" not in response.text and "用户名或密码不正确" not in response.text:
                 if response.url != login_url or "我的桌面" in response.text or "index_initMenu.html" in response.text:
                     return True, "登录成功"
                 test_url = f"{BASE_URL}/xtgl/index_initMenu.html"
                 test_resp = self.session.get(test_url)
                 if "用户登录" not in test_resp.text:
                     return True, "登录成功"
            
            soup = BeautifulSoup(response.text, 'html.parser')
            tips = soup.find('p', {'id': 'tips'})
            msg = tips.text.strip() if tips else "登录失败，可能是账号或密码错误"
            return False, msg
        except Exception as e:
            return False, str(e)

    def get_schedule(self, year, semester):
        if not self.session: self._init_session()
        url = f"{BASE_URL}/kbcx/xskbcx_cxXsKb.html?gnmkdm=N2151"
        data = {"xnm": year, "xqm": semester, "kzlx": "ck"}
        headers = {"X-Requested-With": "XMLHttpRequest"}
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                return response.json()
        except Exception as e:
            print(f"Get schedule error: {e}")
        return None

    def get_calendar_start_date(self):
        if not self.session: self._init_session()
        url = f"{BASE_URL}/xtgl/index_cxAreaSix.html"
        data = {"localeKey": "zh_CN", "gnmkdm": "index"}
        headers = {"X-Requested-With": "XMLHttpRequest"}
        try:
            response = self.session.post(url, data=data, headers=headers, timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                tbody = soup.find('tbody')
                if tbody:
                    first_tr = tbody.find('tr')
                    if first_tr:
                        first_td = first_tr.find('td')
                        if first_td and first_td.get('id'):
                            return first_td.get('id')
        except Exception:
            pass
        return None

# ==================== 界面组件 ====================

class NotificationPopup(QDialog):
    """右下角弹窗提醒"""
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        # 移除透明背景属性，改为完全不透明
        # self.setAttribute(Qt.WA_TranslucentBackground) 
        self.setFixedSize(320, 160)
        
        # 样式
        self.setStyleSheet("""
            QDialog {
                background-color: #2c313a;
                border: none;
                border-radius: 0px; 
            }
            QLabel { color: white; }
            QPushButton {
                background: transparent;
                color: #abb2bf;
                border: none;
                font-size: 16px;
            }
            QPushButton:hover { color: white; }
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 6, 8, 6) # 极限减小边距
        layout.setSpacing(4)
        
        # 顶部：日期时间 + 关闭按钮
        header_layout = QHBoxLayout()
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
        time_lbl = QLabel(now_str)
        time_lbl.setStyleSheet("color: #61afef; font-size: 15px; font-weight: bold;") # 增大字体
        header_layout.addWidget(time_lbl)
        
        header_layout.addStretch()
        
        close_btn = QPushButton("×")
        close_btn.setFixedSize(24, 24)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.clicked.connect(self.close)
        header_layout.addWidget(close_btn)
        
        layout.addLayout(header_layout)
        
        # 内容区域
        content_layout = QVBoxLayout()
        content_layout.setSpacing(2) # 进一步减小间距
        
        reminder_type = data.get('type')
        
        if reminder_type == 'course':
            # 提示语
            alert_lbl = QLabel("🔔 还有25分钟就要上课了")
            alert_lbl.setStyleSheet("color: #e5c07b; font-size: 17px; font-weight: bold;") # 增大字体
            content_layout.addWidget(alert_lbl)
            
            # 课程名称
            course_name = data.get('course_name', '未知课程')
            name_lbl = QLabel(course_name)
            name_lbl.setWordWrap(True)
            name_lbl.setStyleSheet("color: white; font-size: 26px; font-weight: bold; margin-top: 4px;") # 增大字体
            content_layout.addWidget(name_lbl)
            
            # 地点 | 老师
            location = data.get('location', '未知地点')
            teacher = data.get('teacher', '未知教师')
            info_lbl = QLabel(f"🚩 {location} | 🧑‍🏫 {teacher}")
            info_lbl.setStyleSheet("color: #abb2bf; font-size: 16px; margin-top: 4px;") # 增大字体
            content_layout.addWidget(info_lbl)
            
        else:
            # Custom Reminder (Tips)
            title_lbl = QLabel("Tips:")
            title_lbl.setStyleSheet("font-weight: bold; font-size: 24px; color: #e5c07b;") # Large font, yellow
            content_layout.addWidget(title_lbl)
            
            # Content
            content_text = data.get('content', '')
            msg_lbl = QLabel(content_text)
            msg_lbl.setWordWrap(True)
            
            # Font size adjustment
            has_location = bool(data.get('location'))
            # 这里的字体大小被要求至少和 Tips 一样大 (Tips 是 24px)
            # 我们给内容设置 24px，地点设置 20px
            font_size = 24 
            msg_lbl.setStyleSheet(f"color: white; font-size: {font_size}px; font-weight: bold; margin-top: 5px;")
            
            # We can't easily limit lines in QLabel, but we rely on layout constraints.
            # If it's too long, it will push content down.
            # Given fixed size, we might want to truncate text if it's extremely long.
            # But user said "Content must be presented... unless exceeds two lines".
            # For now, let's assume reasonable length or let it clip if huge.
            content_layout.addWidget(msg_lbl)
            
            if has_location:
                loc_text = data.get('location')
                loc_lbl = QLabel(f"📍 {loc_text}")
                # Elide location if too long (simple char limit for now as placeholder)
                if len(loc_text) > 20:
                    loc_text = loc_text[:18] + "..."
                    loc_lbl.setText(f"📍 {loc_text}")
                    
                loc_lbl.setStyleSheet("color: #abb2bf; font-size: 20px; margin-top: 5px; font-weight: bold;")
                content_layout.addWidget(loc_lbl)

        content_layout.addStretch()
        layout.addLayout(content_layout)

    def show_animation(self):
        # 获取屏幕几何信息
        screen_geo = QApplication.desktop().availableGeometry()
        x = screen_geo.width() - self.width() - 20
        y = screen_geo.height() - self.height() - 20
        self.move(x, y)
        self.show()

class CustomReminderDialog(QDialog):
    """自定义提醒设置窗口"""
    def __init__(self, start_dt, existing_data=None, parent=None):
        super().__init__(parent)
        self.setWindowTitle("设置提醒")
        self.setFixedSize(360, 420)
        self.setStyleSheet("""
            QDialog { background-color: #f5f7fa; font-family: 'Microsoft YaHei UI'; }
            QLabel { color: #333; font-size: 14px; font-weight: bold; }
            QLineEdit, QDateTimeEdit, QTextEdit {
                padding: 8px;
                border: 1px solid #dcdfe6;
                border-radius: 4px;
                background: white;
                font-size: 14px;
            }
            QPushButton {
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton#Save { background-color: #409eff; color: white; border: none; }
            QPushButton#Save:hover { background-color: #66b1ff; }
            QPushButton#Delete { background-color: #f56c6c; color: white; border: none; }
            QPushButton#Delete:hover { background-color: #ff7875; }
            QPushButton#Cancel { background-color: #ffffff; color: #606266; border: 1px solid #dcdfe6; }
            QPushButton#Cancel:hover { color: #409eff; border-color: #c6e2ff; background-color: #ecf5ff; }
        """)
        
        self.result_data = None
        self.is_delete = False
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # 提醒时间
        layout.addWidget(QLabel("提醒时间:"))
        self.time_edit = QDateTimeEdit(start_dt)
        self.time_edit.setDisplayFormat("yyyy-MM-dd HH:mm")
        self.time_edit.setCalendarPopup(True)
        layout.addWidget(self.time_edit)
        
        # 提醒事项
        layout.addWidget(QLabel("提醒事项:"))
        self.content_edit = QTextEdit()
        self.content_edit.setPlaceholderText("请输入提醒内容...")
        layout.addWidget(self.content_edit)
        
        # 地点（可选）
        layout.addWidget(QLabel("地点 (可选):"))
        self.location_edit = QLineEdit()
        self.location_edit.setPlaceholderText("请输入地点")
        layout.addWidget(self.location_edit)
        
        layout.addStretch()
        
        # 按钮区
        btn_layout = QHBoxLayout()
        
        if existing_data:
            delete_btn = QPushButton("删除", objectName="Delete")
            delete_btn.setCursor(Qt.PointingHandCursor)
            delete_btn.clicked.connect(self.handle_delete)
            btn_layout.addWidget(delete_btn)
            
            # 填充现有数据
            if 'time' in existing_data:
                try:
                    dt = datetime.datetime.strptime(existing_data['time'], "%Y-%m-%d %H:%M")
                    self.time_edit.setDateTime(dt)
                except: pass
            self.content_edit.setText(existing_data.get('content', ''))
            self.location_edit.setText(existing_data.get('location', ''))
            
        btn_layout.addStretch()
        
        cancel_btn = QPushButton("取消", objectName="Cancel")
        cancel_btn.setCursor(Qt.PointingHandCursor)
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        save_btn = QPushButton("保存", objectName="Save")
        save_btn.setCursor(Qt.PointingHandCursor)
        save_btn.clicked.connect(self.handle_save)
        btn_layout.addWidget(save_btn)
        
        layout.addLayout(btn_layout)

    def handle_save(self):
        content = self.content_edit.toPlainText().strip()
        if not content:
            QMessageBox.warning(self, "提示", "请输入提醒事项内容")
            return
            
        self.result_data = {
            'time': self.time_edit.dateTime().toString("yyyy-MM-dd HH:mm"),
            'content': content,
            'location': self.location_edit.text().strip(),
            'type': 'custom',
            'title': '自定义提醒'
        }
        self.accept()

    def handle_delete(self):
        confirm = QMessageBox.question(self, "确认删除", "确定要删除这条提醒吗？", QMessageBox.Yes | QMessageBox.No)
        if confirm == QMessageBox.Yes:
            self.is_delete = True
            self.accept()

class ReminderManagerWindow(QWidget):
    """提醒管理窗口"""
    def __init__(self, reminder_manager):
        super().__init__()
        self.manager = reminder_manager
        self.current_week = self.manager.calculate_current_week()
        self.initUI()
        
    def test_notification(self):
        """测试弹窗功能"""
        try:
            test_data = {
                'type': 'course',
                'title': '测试提醒',
                'course_name': '测试课程：高等数学',
                'location': '第二教学楼 201',
                'teacher': '张三',
                'content': '这是一条测试用的提醒消息，用于验证弹窗功能是否正常。'
            }
            # 调用 FloatingWindow 的 show_notification 方法
            if hasattr(self.manager, 'show_notification'):
                self.manager.show_notification(test_data)
            else:
                QMessageBox.warning(self, "错误", "无法调用弹窗功能")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"测试弹窗失败: {str(e)}")

    def initUI(self):
        self.setWindowTitle("提醒任务管理")
        self.resize(1000, 700)
        self.setStyleSheet("""
            QWidget { background-color: #f5f7fa; font-family: 'Microsoft YaHei UI'; }
            QTableWidget { 
                background-color: white; 
                border: 1px solid #e1e4e8;
                gridline-color: #f0f0f0;
            }
            QHeaderView::section {
                background-color: #fafbfc;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #e1e4e8;
                font-weight: bold;
                color: #586069;
            }
            QComboBox {
                padding: 5px 10px;
                border: 1px solid #d1d5da;
                border-radius: 4px;
                background: white;
                min-width: 100px;
            }
            QLabel { color: #333; }
        """)
        
        layout = QVBoxLayout(self)
        
        # 顶部控制栏
        top_bar = QHBoxLayout()
        title = QLabel("学期提醒任务")
        title.setStyleSheet("font-size: 16px; font-weight: bold;")
        top_bar.addWidget(title)
        
        top_bar.addStretch()
        
        self.week_combo = QComboBox()
        for i in range(1, 26):
            self.week_combo.addItem(f"第 {i} 周", i)
        
        # 默认选中当前周
        index = self.week_combo.findData(self.current_week)
        if index >= 0:
            self.week_combo.setCurrentIndex(index)
            
        self.week_combo.currentIndexChanged.connect(self.load_reminders)
        top_bar.addWidget(QLabel("切换周次:"))
        top_bar.addWidget(self.week_combo)
        
        # 测试弹窗按钮
        test_btn = QPushButton("测试弹窗")
        test_btn.setCursor(Qt.PointingHandCursor)
        test_btn.clicked.connect(self.test_notification)
        top_bar.addWidget(test_btn)
        
        refresh_btn = QPushButton("刷新列表")
        refresh_btn.clicked.connect(self.load_reminders)
        top_bar.addWidget(refresh_btn)
        
        layout.addLayout(top_bar)
        
        # 提醒说明
        tips_label = QLabel("提示：只有未开始且未过期的课程才会触发提醒。冲突的课程不会提醒（灰色显示）。\n"
                            "为了确保提醒生效，请保持程序运行（可最小化到托盘）。")
        tips_label.setStyleSheet("color: #666; font-size: 12px; margin-bottom: 5px;")
        layout.addWidget(tips_label)
        
        # 提醒表格
        self.table = QTableWidget()
        self.table.setRowCount(12)  # 11节课 + 顶部预留
        self.table.setColumnCount(7) # 周一到周日
        self.table.setHorizontalHeaderLabels(["周一", "周二", "周三", "周四", "周五", "周六", "周日"])
        self.table.setVerticalHeaderLabels([s["name"] for s in DAILY_SCHEDULE if s["name"] != "午休"] + [""])
        
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setSelectionMode(QTableWidget.NoSelection)
        self.table.cellClicked.connect(self.on_cell_clicked)
        
        layout.addWidget(self.table)
        
        self.load_reminders()

    def test_notification(self):
        """测试弹窗功能"""
        try:
            test_data = {
                'type': 'course',
                'title': '测试提醒',
                'course_name': '测试课程：高等数学',
                'location': '第二教学楼 201',
                'teacher': '张三',
                'content': '这是一条测试用的提醒消息，用于验证弹窗功能是否正常。'
            }
            # 调用 FloatingWindow 的 show_notification 方法
            if hasattr(self.manager, 'show_notification'):
                self.manager.show_notification(test_data)
            else:
                QMessageBox.warning(self, "错误", "无法调用弹窗功能")
        except Exception as e:
            QMessageBox.critical(self, "错误", f"测试弹窗失败: {str(e)}")

    def on_cell_clicked(self, row, col):
        """处理单元格点击"""
        # 获取单元格数据
        item = self.table.item(row, col)
        
        # 1. 检查是否是课程提醒（不可编辑）
        # 通过检查 item 是否关联了课程数据，或者背景色
        # 我们可以在 load_reminders 时将数据绑定到 item 的 UserRole
        if item:
            data = item.data(Qt.UserRole)
            if data:
                if data.get('type') == 'course':
                    QMessageBox.information(self, "提示", "课程提醒是自动生成的，无法修改。")
                    return
                elif data.get('type') == 'custom':
                    # 修改自定义提醒
                    self.edit_custom_reminder(data)
                    return
        
        # 2. 如果是空白或没有数据，则创建新提醒
        # 计算该单元格对应的默认时间
        selected_week = self.week_combo.currentData()
        
        # 获取本周周一
        if not self.manager.start_date_str:
            now = datetime.datetime.now()
            start_date = datetime.datetime(now.year, 9, 1) if now.month >= 8 else datetime.datetime(now.year, 2, 20)
        else:
            try:
                start_date = datetime.datetime.strptime(self.manager.start_date_str, "%Y-%m-%d")
            except: 
                start_date = datetime.datetime.now()
        
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start_date = start_date + datetime.timedelta(days=selected_week * 7)
        
        target_date = week_start_date + datetime.timedelta(days=col)
        
        # 获取该行对应的开始时间
        # 行号 0-11 对应 DAILY_SCHEDULE 中除了午休外的第 0-11 个slot
        slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
        if row < len(slots):
            time_str = slots[row]["start"]
            target_dt = datetime.datetime.combine(target_date.date(), datetime.datetime.strptime(time_str, "%H:%M").time())
            
            # 检查该时间段是否已有课程占用
            if self.check_course_conflict(target_dt):
                QMessageBox.warning(self, "无法创建", "当前时间段已有课程安排，无法创建自定义提醒。")
                return
            
            self.create_custom_reminder(target_dt)

    def check_course_conflict(self, dt):
        """检查指定时间是否与课程冲突"""
        # 获取当天的课程
        # get_daily_courses 返回的是合并后的课程信息，包含 start_time, end_time
        daily_courses = self.manager.get_daily_courses(dt)
        time_str = dt.strftime("%H:%M")
        
        for item in daily_courses:
            if item['start_time'] <= time_str <= item['end_time']:
                return True
        return False

    def create_custom_reminder(self, default_dt):
        dialog = CustomReminderDialog(default_dt, parent=self)
        
        # 计算唤起该弹窗的课程 slot 的 start time
        origin_slot_start = None
        time_str = default_dt.strftime("%H:%M")
        slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
        for slot in slots:
            if slot['start'] == time_str:
                origin_slot_start = slot['start']
                break
        
        if dialog.exec_() == QDialog.Accepted:
            new_data = dialog.result_data
            
            # 验证是否成功显示在格子里
            # 简单检查时间是否在任何有效格子范围内
            time_str = new_data['time'].split(' ')[1]
            valid_slot = False
            for slot in slots:
                slot_start = slot['start']
                slot_end = slot['end']
                
                if slot_start <= time_str <= slot_end:
                    valid_slot = True
                    break
                
                try:
                    s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                    t_dt = datetime.datetime.strptime(time_str, "%H:%M")
                    diff = (s_dt - t_dt).total_seconds()
                    if 0 < diff <= 15 * 60:
                        valid_slot = True
                        break
                except: pass
                
            if not valid_slot:
                QMessageBox.warning(self, "注意", "提醒任务已创建，但因时间不在任何课程格子范围内（或提前超过15分钟），可能无法在课表视图中显示。")
                # 即使不在格子内，我们也要尝试添加
                success, msg = self.manager.add_custom_reminder(new_data, origin_slot_start)
                if not success:
                    QMessageBox.warning(self, "添加失败", msg)
            else:
                success, msg = self.manager.add_custom_reminder(new_data, origin_slot_start)
                if not success:
                    QMessageBox.warning(self, "添加失败", msg)
            
            self.load_reminders() # 刷新

    def edit_custom_reminder(self, old_data):
        # 解析时间
        try:
            dt = datetime.datetime.strptime(old_data['time'], "%Y-%m-%d %H:%M")
        except:
            dt = datetime.datetime.now()
            
        # 计算 old_data 所属的 slot start time
        origin_slot_start = None
        time_str = dt.strftime("%H:%M")
        slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
        for slot in slots:
            slot_start = slot['start']
            slot_end = slot['end']
            
            # 检查是否在 slot 内 (或者提前15分钟)
            match = False
            if slot_start <= time_str <= slot_end:
                match = True
            else:
                try:
                    s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                    t_dt = datetime.datetime.strptime(time_str, "%H:%M")
                    diff = (s_dt - t_dt).total_seconds()
                    if 0 < diff <= 15 * 60:
                        match = True
                except: pass
            
            if match:
                origin_slot_start = slot_start
                break
            
        dialog = CustomReminderDialog(dt, existing_data=old_data, parent=self)
        if dialog.exec_() == QDialog.Accepted:
            if dialog.is_delete:
                self.manager.delete_custom_reminder(old_data)
            else:
                new_data = dialog.result_data
                
                # 验证时间范围（同上）
                time_str = new_data['time'].split(' ')[1]
                valid_slot = False
                slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
                for slot in slots:
                    slot_start = slot['start']
                    slot_end = slot['end']
                    if slot_start <= time_str <= slot_end:
                        valid_slot = True
                        break
                    try:
                        s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                        t_dt = datetime.datetime.strptime(time_str, "%H:%M")
                        diff = (s_dt - t_dt).total_seconds()
                        if 0 < diff <= 15 * 60:
                            valid_slot = True
                            break
                    except: pass
                
                if not valid_slot:
                    QMessageBox.warning(self, "注意", "提醒任务已修改，但因时间不在任何课程格子范围内，可能无法在课表视图中显示。")
                    success, msg = self.manager.update_custom_reminder(old_data, new_data, origin_slot_start)
                    if not success:
                        QMessageBox.warning(self, "修改失败", msg)
                else:
                    success, msg = self.manager.update_custom_reminder(old_data, new_data, origin_slot_start)
                    if not success:
                        QMessageBox.warning(self, "修改失败", msg)
                
            self.load_reminders() # 刷新

    def load_reminders(self):
        self.table.clearContents()
        self.table.clearSpans()
        selected_week = self.week_combo.currentData()
        
        # 计算该周每一天的日期
        if not self.manager.start_date_str:
            now = datetime.datetime.now()
            start_date = datetime.datetime(now.year, 9, 1) if now.month >= 8 else datetime.datetime(now.year, 2, 20)
        else:
            try:
                start_date = datetime.datetime.strptime(self.manager.start_date_str, "%Y-%m-%d")
            except: 
                start_date = datetime.datetime.now()
        
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start_date = start_date + datetime.timedelta(days=selected_week * 7)
        
        # 更新表头显示日期
        weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        header_labels = []
        for i in range(7):
            current_date = week_start_date + datetime.timedelta(days=i)
            date_str = current_date.strftime("%m-%d")
            header_labels.append(f"{date_str}\n{weekdays[i]}")
        self.table.setHorizontalHeaderLabels(header_labels)
        
        schedule_map = {}
        kb_list = self.manager.kb_list # 获取课表数据
        
        for course in kb_list:
            if not self.manager.is_week_active(course.get('zcd'), selected_week):
                continue
            
            day = int(course.get('xqj', 0)) - 1 # 0-6
            jcs = course.get('jcs', '')
            
            # 解析节次
            sections = []
            if '-' in jcs:
                start, end = map(int, jcs.split('-'))
                sections = list(range(start, end + 1))
            else:
                try:
                    sections = [int(jcs)]
                except: continue
                
            for sec in sections:
                row = sec - 1
                if 0 <= row < 12 and 0 <= day < 7:
                    schedule_map[(row, day)] = course
        
        # 3. 合并自定义提醒到表格
        # custom_reminders 是按具体日期存储的
        # 我们需要遍历 custom_reminders，如果它的日期属于 selected_week，则显示
        
        for item in self.manager.custom_reminders:
            try:
                dt = datetime.datetime.strptime(item['time'], "%Y-%m-%d %H:%M")
                
                # 检查日期是否在本周范围内
                # week_start_date 是本周周一
                week_end_date = week_start_date + datetime.timedelta(days=7)
                
                if week_start_date <= dt < week_end_date:
                    # 计算列 (0-6)
                    col = (dt - week_start_date).days
                    
                    # 计算行 (根据时间匹配 slot)
                    # 找到最近的 slot 或者覆盖的 slot
                    # 简单处理：根据时间找到对应的节次
                    time_str = dt.strftime("%H:%M")
                    
                    target_row = -1
                    slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
                    
                    # 严格匹配逻辑：
                    # 提醒时间必须位于某个格子（课程节次）的时间范围内 [start, end]
                    # 或者，为了方便，允许在 start 前 15 分钟内
                    
                    for i, slot in enumerate(slots):
                        slot_start = slot['start']
                        slot_end = slot['end']
                        
                        # 检查是否在时间范围内
                        if slot_start <= time_str <= slot_end:
                            target_row = i
                            break
                        
                        # 允许稍微提前一点 (例如提前15分钟算作这一节)
                        # 这主要用于那些设置在8:15提醒8:30上课的情况
                        try:
                            s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                            t_dt = datetime.datetime.strptime(time_str, "%H:%M")
                            diff = (s_dt - t_dt).total_seconds()
                            if 0 < diff <= 15 * 60:
                                target_row = i
                                break
                        except: pass

                    if target_row != -1:
                        # 检查是否有课程覆盖
                        if (target_row, col) not in schedule_map:
                            # 存入 map，标记为 custom
                            schedule_map[(target_row, col)] = item

            except Exception as e:
                print(f"Render custom reminder error: {e}")

        # 渲染表格
        now = datetime.datetime.now()
        
        for col in range(7):
            # 计算该列对应的实际日期
            col_date = week_start_date + datetime.timedelta(days=col)
            
            row = 0
            while row < 12:
                course = schedule_map.get((row, col))
                if course:
                    # 查找连续课程
                    span = 1
                    while row + span < 12:
                        next_course = schedule_map.get((row + span, col))
                        if next_course and \
                           next_course.get('kcmc') == course.get('kcmc') and \
                           next_course.get('cdmc') == course.get('cdmc'):
                            span += 1
                        else:
                            break
                    
                    # 填充内容
                    # 获取该节课的开始时间
                    start_time = "00:00"
                    
                    if isinstance(course, dict) and 'kcmc' in course:
                        # 课程提醒
                        for slot in DAILY_SCHEDULE:
                            if slot['name'] == str(row + 1):
                                start_time = slot['start']
                                break
                        
                        # 计算提醒时间
                        is_expired = False
                        is_conflict = False
                        remind_time_str = "??"
                        
                        try:
                            start_dt = datetime.datetime.combine(col_date.date(), datetime.datetime.strptime(start_time, "%H:%M").time())
                            remind_dt = start_dt - datetime.timedelta(minutes=25)
                            remind_time_str = remind_dt.strftime("%H:%M")
                            
                            if remind_dt < now:
                                is_expired = True
                                
                            # 冲突检测
                            # 我们需要在 ReminderManagerWindow 中重新模拟冲突检测，因为这里只是展示
                            # 获取当天所有课程的时间段
                            daily_courses_time = []
                            temp_row = 0
                            while temp_row < 12:
                                temp_c = schedule_map.get((temp_row, col))
                                if temp_c and isinstance(temp_c, dict) and 'kcmc' in temp_c:
                                    temp_span = 1
                                    while temp_row + temp_span < 12:
                                        temp_next = schedule_map.get((temp_row + temp_span, col))
                                        if temp_next and temp_next.get('kcmc') == temp_c.get('kcmc') and temp_next.get('cdmc') == temp_c.get('cdmc'):
                                            temp_span += 1
                                        else:
                                            break
                                    
                                    temp_s_time = "00:00"
                                    temp_e_time = "00:00"
                                    for slot in DAILY_SCHEDULE:
                                        if slot['name'] == str(temp_row + 1): temp_s_time = slot['start']
                                        if slot['name'] == str(temp_row + temp_span): temp_e_time = slot['end']
                                    
                                    daily_courses_time.append((temp_s_time, temp_e_time))
                                    temp_row += temp_span
                                else:
                                    temp_row += 1
                            
                            # 检查提醒时间是否在其他课程时间内
                            remind_time_check = remind_time_str
                            for s, e in daily_courses_time:
                                # 排除自己
                                if s == start_time: continue 
                                if s <= remind_time_check <= e:
                                    is_conflict = True
                                    break
                                    
                        except:
                            pass

                        text = f"⏰ 提醒时间: {remind_time_str}\n\n{course.get('kcmc')}\n@{course.get('cdmc')}"
                        
                        if is_expired or is_conflict:
                            bg_color = QColor("#e0e0e0") # 灰色背景
                            text_color = QColor("#888888") # 灰色文字
                            if is_conflict:
                                text += "\n(时间冲突-已取消)"
                        else:
                            color_idx = abs(hash(course.get('kcmc', ''))) % len(COLORS)
                            bg_color = QColor(COLORS[color_idx])
                            text_color = QColor("black")
                        
                        item = QTableWidgetItem(text)
                        item.setData(Qt.UserRole, {'type': 'course', 'data': course}) # 绑定数据
                        
                    else:
                        # 自定义提醒
                        try:
                            dt = datetime.datetime.strptime(course['time'], "%Y-%m-%d %H:%M")
                            time_display = dt.strftime("%H:%M")
                            
                            content = course.get('content', '')
                            # 内容截断
                            if len(content) > 5:
                                disp_content = content[:5] + "..."
                            else:
                                disp_content = content
                                
                            text = f"📝 {time_display}\n{disp_content}"
                                
                            bg_color = QColor("#fff3cd") # 浅黄色背景
                            text_color = QColor("#856404") # 深黄色文字
                            
                            if dt < now:
                                bg_color = QColor("#e0e0e0")
                                text_color = QColor("#888888")
                                text += "\n(过期)"
                                
                            item = QTableWidgetItem(text)
                            item.setData(Qt.UserRole, course) # 绑定数据
                        except:
                            item = QTableWidgetItem("Error")

                    item.setBackground(bg_color)
                    item.setForeground(text_color)
                    item.setTextAlignment(Qt.AlignCenter)
                    item.setFont(QFont("Microsoft YaHei UI", 9))
                    self.table.setItem(row, col, item)
                    
                    if span > 1:
                        self.table.setSpan(row, col, span, 1)
                    
                    row += span
                else:
                    # Empty cell, set item to allow clicking and ensure consistent look
                    item = QTableWidgetItem("")
                    self.table.setItem(row, col, item)
                    row += 1

class WeekScheduleWindow(QWidget):
    """完整周课表窗口"""
    def __init__(self, schedule_data, start_date_str, current_week):
        super().__init__()
        self.schedule_data = schedule_data
        self.kb_list = schedule_data.get('kbList', [])
        self.start_date_str = start_date_str
        self.current_week = current_week
        
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle("完整课表")
        self.resize(1000, 700)
        self.setStyleSheet("""
            QWidget { background-color: #f5f7fa; }
            QTableWidget { 
                background-color: white; 
                border: 1px solid #e1e4e8;
                gridline-color: #f0f0f0;
            }
            QHeaderView::section {
                background-color: #fafbfc;
                padding: 8px;
                border: none;
                border-bottom: 1px solid #e1e4e8;
                font-weight: bold;
                color: #586069;
            }
            QComboBox {
                padding: 5px 10px;
                border: 1px solid #d1d5da;
                border-radius: 4px;
                background: white;
                min-width: 100px;
            }
        """)
        
        layout = QVBoxLayout()
        self.setLayout(layout)
        
        # 顶部控制栏
        top_bar = QHBoxLayout()
        
        title = QLabel("课程表")
        title.setFont(QFont("Microsoft YaHei", 16, QFont.Bold))
        top_bar.addWidget(title)
        
        top_bar.addStretch()
        
        self.week_combo = QComboBox()
        for i in range(1, 26):
            self.week_combo.addItem(f"第 {i} 周", i)
        self.week_combo.setCurrentIndex(self.current_week - 1)
        self.week_combo.currentIndexChanged.connect(self.refresh_table)
        top_bar.addWidget(QLabel("切换周次:"))
        top_bar.addWidget(self.week_combo)
        
        layout.addLayout(top_bar)
        
        # 课表表格
        self.table = QTableWidget()
        self.table.setRowCount(12)  # 11节课 + 表头
        self.table.setColumnCount(7) # 周一到周日
        self.table.setHorizontalHeaderLabels(["周一", "周二", "周三", "周四", "周五", "周六", "周日"])
        self.table.setVerticalHeaderLabels([s["name"] for s in DAILY_SCHEDULE if s["name"] != "午休"] + [""])
        
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setSelectionMode(QTableWidget.NoSelection)
        
        layout.addWidget(self.table)
        
        self.refresh_table()
        
    def refresh_table(self):
        self.table.clearContents()
        self.table.clearSpans() # 清除之前的合并
        selected_week = self.week_combo.currentData()
        
        # 计算该周每一天的日期
        if not self.schedule_data: # 实际上是在 FloatingWindow 中传入的 schedule_data
             start_date_str = self.start_date_str
        else:
             start_date_str = self.start_date_str

        if not start_date_str:
            now = datetime.datetime.now()
            start_date = datetime.datetime(now.year, 9, 1) if now.month >= 8 else datetime.datetime(now.year, 2, 20)
        else:
            try:
                start_date = datetime.datetime.strptime(start_date_str, "%Y-%m-%d")
            except: 
                start_date = datetime.datetime.now()
        
        # 第0周的第一天（假设周一）
        # 修正：根据 calculate_current_week 逻辑，第0周是 [start, start+7)，第1周是 [start+7, start+14)
        # 所以 selected_week 的周一 = start_date + selected_week * 7
        
        week_start_date = start_date + datetime.timedelta(days=selected_week * 7)
        
        # 更新表头显示日期
        weekdays = ["周一", "周二", "周三", "周四", "周五", "周六", "周日"]
        header_labels = []
        for i in range(7):
            current_date = week_start_date + datetime.timedelta(days=i)
            date_str = current_date.strftime("%m-%d")
            header_labels.append(f"{date_str}\n{weekdays[i]}")
        self.table.setHorizontalHeaderLabels(header_labels)
        
        # 生成课表映射
        # map[(weekday, section)] = course
        schedule_map = {}
        
        for course in self.kb_list:
            if not self.is_week_active(course.get('zcd'), selected_week):
                continue
            
            day = int(course.get('xqj', 0)) - 1 # 0-6
            jcs = course.get('jcs', '')
            
            # 解析节次
            sections = []
            if '-' in jcs:
                start, end = map(int, jcs.split('-'))
                sections = list(range(start, end + 1))
            else:
                try:
                    sections = [int(jcs)]
                except: continue
                
            for sec in sections:
                # 映射到表格行 (注意 DAILY_SCHEDULE 包含午休，需要过滤)
                # 简单映射：第n节对应第n-1行
                row = sec - 1
                if 0 <= row < 12 and 0 <= day < 7:
                    # 检查是否已有课程（冲突处理：这里简单覆盖，实际可优化）
                    schedule_map[(row, day)] = course
        
        # 渲染表格并合并
        # 按列遍历（周一到周日）
        for col in range(7):
            row = 0
            while row < 12:
                course = schedule_map.get((row, col))
                if course:
                    # 查找连续相同的课程
                    span = 1
                    while row + span < 12:
                        next_course = schedule_map.get((row + span, col))
                        if next_course and \
                           next_course.get('kcmc') == course.get('kcmc') and \
                           next_course.get('cdmc') == course.get('cdmc'):
                            span += 1
                        else:
                            break
                    
                    # 填充单元格
                    color_idx = abs(hash(course.get('kcmc', ''))) % len(COLORS)
                    bg_color = QColor(COLORS[color_idx])
                    
                    text = f"{course.get('kcmc')}\n@{course.get('cdmc')}\n{course.get('xm')}"
                    item = QTableWidgetItem(text)
                    item.setBackground(bg_color)
                    item.setTextAlignment(Qt.AlignCenter)
                    item.setFont(QFont("Microsoft YaHei UI", 9)) # 使用更好的字体
                    self.table.setItem(row, col, item)
                    
                    # 执行合并
                    if span > 1:
                        self.table.setSpan(row, col, span, 1)
                    
                    row += span # 跳过已处理的行
                else:
                    row += 1

    def is_week_active(self, weeks_str, current_week):
        # 复用 FloatingWindow 的逻辑
        if not weeks_str: return False
        is_odd_only = "单" in weeks_str
        is_even_only = "双" in weeks_str
        clean_str = weeks_str.replace("周", "").replace("单", "").replace("双", "").replace("(", "").replace(")", "").replace("（", "").replace("）", "")
        
        for part in clean_str.split(","):
            try:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if start <= current_week <= end:
                        if is_odd_only and current_week % 2 == 0: return False
                        if is_even_only and current_week % 2 != 0: return False
                        return True
                elif int(part) == current_week:
                    return True
            except: continue
        return False

class CountdownCard(QFrame):
    """独立显示的倒计时卡片"""
    def __init__(self, course_name, start_time, end_time=None, is_last_class=False, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                border: none;
            }
        """)
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(5)
        
        # 标题
        self.is_last_class = is_last_class
        title_text = "今天解放倒计时" if is_last_class else "下一节课倒计时"
        
        # 如果提供了结束时间，说明正在上课，倒计时目标就是下课
        self.target_time = end_time if end_time else start_time
        
        title_lbl = QLabel(title_text)
        title_lbl.setStyleSheet("color: #c678dd; font-size: 14px; font-weight: bold; background: transparent; border: none;")
        layout.addWidget(title_lbl)
        
        layout.addSpacing(5) # 增加间距
        
        # 倒计时大字
        self.timer_lbl = QLabel("--:--:--")
        self.timer_lbl.setStyleSheet("color: #e5c07b; font-weight: bold; font-size: 36px; font-family: 'Microsoft YaHei UI', monospace; background: transparent; border: none;")
        self.timer_lbl.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.timer_lbl)
        
        # 课程信息
        if isinstance(course_name, dict):
            # 课程名称
            name_text = course_name.get('kcmc', '')
            name_lbl = QLabel(name_text)
            name_lbl.setStyleSheet("color: white; font-size: 20px; font-weight: bold; margin-top: 5px; background: transparent; border: none;")
            name_lbl.setAlignment(Qt.AlignCenter)
            name_lbl.setWordWrap(True)
            layout.addWidget(name_lbl)
            
            # 上课地点和老师
            detail_text = f"{course_name.get('cdmc', '')} | 👤 {course_name.get('xm', '')}"
            detail_lbl = QLabel(detail_text)
            detail_lbl.setStyleSheet("color: #98c379; font-size: 16px; margin-top: 2px; background: transparent; border: none;")
            detail_lbl.setAlignment(Qt.AlignCenter)
            detail_lbl.setWordWrap(True)
            layout.addWidget(detail_lbl)
        else:
            # 如果只是名字字符串
            info_text = str(course_name)
            self.course_info = QLabel(info_text)
            self.course_info.setStyleSheet("color: white; font-size: 18px; margin-top: 5px; background: transparent; border: none;")
            self.course_info.setAlignment(Qt.AlignCenter)
            self.course_info.setWordWrap(True) # 允许自动换行
            layout.addWidget(self.course_info)
        
        self.setLayout(layout)
        
        self.update_timer()
        
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_timer)
        self.timer.start(1000)

    def update_timer(self):
        now = datetime.datetime.now()
        target_dt = datetime.datetime.combine(now.date(), datetime.datetime.strptime(self.target_time, "%H:%M").time())
        
        if target_dt < now:
             self.timer_lbl.setText("即将下课" if self.target_time > "12:00" else "即将上课") # 简单判断
             return
             
        diff = target_dt - now
        minutes, seconds = divmod(diff.seconds, 60)
        hours, minutes = divmod(minutes, 60)
        
        self.timer_lbl.setText(f"{hours:02d}:{minutes:02d}:{seconds:02d}")

class LiberatedCard(QFrame):
    """今天已解放卡片"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QFrame {
                background-color: rgba(255, 255, 255, 0.05);
                border-radius: 12px;
                border: none;
            }
        """)
        layout = QVBoxLayout()
        # 增加上下内边距以匹配倒计时卡片的高度
        layout.setContentsMargins(15, 35, 15, 35)
        layout.setAlignment(Qt.AlignCenter)
        
        lbl = QLabel("今天已经解放🎉🎉🎉")
        # 字体大小设置较大，配合WordWrap自适应宽度
        lbl.setStyleSheet("color: #e5c07b; font-weight: bold; font-size: 26px; background: transparent; border: none;")
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setWordWrap(True)
        
        layout.addWidget(lbl)
        self.setLayout(layout)

class CourseCard(QFrame):
    """单个课程卡片组件"""
    def __init__(self, course, slot_str, time_str, is_current=False, is_past=False, parent=None, next_start_time=None):
        super().__init__(parent)
        # 卡片背景样式：深色半透明，圆角
        # 已结束的课程使用更暗淡的背景
        if is_past:
             bg_color = 'rgba(255, 255, 255, 0.02)'
             border_style = 'none'
        elif is_current:
             bg_color = 'rgba(64, 169, 255, 0.1)'
             border_style = '1px solid rgba(64, 169, 255, 0.3)'
        else:
             bg_color = 'rgba(255, 255, 255, 0.05)'
             border_style = 'none'
             
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {bg_color};
                border-radius: 12px;
                border: {border_style};
            }}
        """)
        
        # 文本颜色调整
        if is_past:
            text_color_primary = '#666666' # 灰色
            text_color_secondary = '#444444' # 深灰
            slot_color = '#666666'
        else:
            text_color_primary = 'white'
            text_color_secondary = '#abb2bf'
            slot_color = '#61afef' if is_current else '#e5c07b'

        # 主布局
        main_layout = QHBoxLayout()
        main_layout.setContentsMargins(20, 15, 20, 15)
        main_layout.setSpacing(15)
        self.setLayout(main_layout)
        
        # 左侧区域：节次和时间
        left_widget = QWidget()
        left_widget.setStyleSheet("background: transparent; border: none;")
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        left_layout.setAlignment(Qt.AlignCenter)
        
        # 节次
        slot_lbl = QLabel(slot_str)
        slot_lbl.setFont(QFont("Microsoft YaHei UI", 16, QFont.Bold))
        slot_lbl.setStyleSheet(f"color: {slot_color}; background: transparent; border: none;")
        slot_lbl.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(slot_lbl)
        
        # 时间范围
        time_lbl = QLabel(time_str)
        time_lbl.setFont(QFont("Microsoft YaHei UI", 10))
        time_lbl.setStyleSheet(f"color: {text_color_secondary}; background: transparent; border: none;")
        time_lbl.setAlignment(Qt.AlignCenter)
        left_layout.addWidget(time_lbl)
        
        main_layout.addWidget(left_widget)
        
        # 垂直分隔线
        line = QFrame()
        line.setFrameShape(QFrame.VLine)
        line.setFrameShadow(QFrame.Sunken)
        line.setStyleSheet(f"background-color: {'rgba(255, 255, 255, 0.05)' if is_past else 'rgba(255, 255, 255, 0.2)'}; width: 1px; border: none;")
        main_layout.addWidget(line)
        
        # 右侧区域：课程信息
        right_widget = QWidget()
        right_widget.setStyleSheet("background: transparent; border: none;")
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(5, 0, 0, 0)
        right_layout.setSpacing(5)
        right_layout.setAlignment(Qt.AlignVCenter)
        
        # 课程名称
        name = course.get('kcmc', '未知课程') if course else "自由时间"
        name_lbl = QLabel(name)
        name_lbl.setFont(QFont("Microsoft YaHei UI", 14, QFont.Bold))
        name_lbl.setStyleSheet(f"color: {text_color_primary}; background: transparent; border: none;")
        name_lbl.setWordWrap(True)
        right_layout.addWidget(name_lbl)
        
        # 地点和教师
        if course:
            # 整合地点和教师信息到一个标签，以支持自动换行
            info_text = f"🚩 {course.get('cdmc', '未知地点')} | 🧑‍🏫 {course.get('xm', '未知教师')}"
            
            info_lbl = QLabel(info_text)
            info_lbl.setFont(QFont("Microsoft YaHei UI", 12))
            info_lbl.setStyleSheet(f"color: {'#666666' if is_past else '#98c379'}; background: transparent; border: none;")
            info_lbl.setWordWrap(True) # 关键：允许换行
            right_layout.addWidget(info_lbl)

        main_layout.addWidget(right_widget, stretch=1)

class FloatingWindow(QWidget):
    def __init__(self, schedule_data, start_date_str, username=""):
        super().__init__()
        self.schedule_data = schedule_data
        self.kb_list = schedule_data.get('kbList', [])
        self.start_date_str = start_date_str
        self.username = username
        self.current_week = self.calculate_current_week()
        self.week_window = None
        self.reminder_window = None # 修复：初始化 reminder_window
        self.bg_opacity = 245  # 默认背景不透明度
        self.reminders = [] # 存储所有提醒
        self.custom_reminders = [] # 存储自定义提醒
        self.load_custom_reminders()
        self.triggered_reminders = set() # 存储已触发的提醒ID
        
        self.initUI()
        self.initTray() # 初始化托盘
        self.setup_timer()
        
    def load_custom_reminders(self):
        """加载自定义提醒"""
        try:
            if os.path.exists("custom_reminders.json"):
                with open("custom_reminders.json", "r", encoding='utf-8') as f:
                    data = json.load(f)
                    
                if isinstance(data, list):
                    # 旧格式兼容
                    self.custom_reminders = data
                elif isinstance(data, dict):
                    # 新格式：按用户名获取
                    self.custom_reminders = data.get(self.username, [])
                else:
                    self.custom_reminders = []
        except Exception as e:
            print(f"Load custom reminders error: {e}")
            self.custom_reminders = []

    def save_custom_reminders(self):
        """保存自定义提醒"""
        try:
            all_reminders = {}
            if os.path.exists("custom_reminders.json"):
                with open("custom_reminders.json", "r", encoding='utf-8') as f:
                    try:
                        data = json.load(f)
                        if isinstance(data, list):
                            all_reminders = {"unknown": data}
                        else:
                            all_reminders = data
                    except: pass
            
            if self.username:
                all_reminders[self.username] = self.custom_reminders
                
                with open("custom_reminders.json", "w", encoding='utf-8') as f:
                    json.dump(all_reminders, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Save custom reminders error: {e}")

    def add_custom_reminder(self, data, origin_slot_start=None):
        # 验证新任务的时间，获取对应的 slot
        time_str = data['time'].split(' ')[1]
        reminder_dt = datetime.datetime.strptime(data['time'], "%Y-%m-%d %H:%M")
        now = datetime.datetime.now()
        
        target_slot = None
        
        # 找到所属的 slot
        slots = [s for s in DAILY_SCHEDULE if s["name"] != "午休"]
        for slot in slots:
            slot_start = slot['start']
            slot_end = slot['end']
            
            # 严格在范围内
            if slot_start <= time_str <= slot_end:
                target_slot = slot
                break
            
            # 或者提前15分钟
            try:
                s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                t_dt = datetime.datetime.strptime(time_str, "%H:%M")
                diff = (s_dt - t_dt).total_seconds()
                if 0 < diff <= 15 * 60:
                    target_slot = slot
                    break
            except: pass
            
        if target_slot:
            reminders_to_remove = []
            conflict = False
            
            # 遍历现有任务
            for item in list(self.custom_reminders): # 使用副本以安全删除
                try:
                    item_dt = datetime.datetime.strptime(item['time'], "%Y-%m-%d %H:%M")
                    # 检查是否是同一天
                    if item_dt.date() != reminder_dt.date():
                        continue
                        
                    item_time_str = item_dt.strftime("%H:%M")
                    
                    # 检查是否在同一个 slot
                    is_same_slot = False
                    slot_start = target_slot['start']
                    slot_end = target_slot['end']
                    
                    if slot_start <= item_time_str <= slot_end:
                        is_same_slot = True
                    else:
                        try:
                            s_dt = datetime.datetime.strptime(slot_start, "%H:%M")
                            t_dt = datetime.datetime.strptime(item_time_str, "%H:%M")
                            diff = (s_dt - t_dt).total_seconds()
                            if 0 < diff <= 15 * 60:
                                is_same_slot = True
                        except: pass
                        
                    if is_same_slot:
                        # 发现同一 slot 的任务
                        if item_dt < now:
                            # 已过期，标记删除
                            reminders_to_remove.append(item)
                        else:
                            # 未过期，检查是否是“唤起课程”
                            # 如果 origin_slot_start 被提供，且等于当前冲突任务所属的 slot start
                            # 则认为是“同一课程唤起”，允许覆盖（即删除旧的）
                            
                            is_origin_match = False
                            if origin_slot_start:
                                # 检查 item 是否属于 origin_slot_start 对应的 slot
                                # 其实就是检查 target_slot.start 是否等于 origin_slot_start
                                if target_slot['start'] == origin_slot_start:
                                    is_origin_match = True
                            
                            if is_origin_match:
                                # 是同一唤起源，允许覆盖 -> 删除旧的
                                reminders_to_remove.append(item)
                            else:
                                # 不是同一唤起源 -> 冲突
                                conflict = True
                except: pass
            
            if conflict:
                return False, "该时间段内已存在有效的自定义提醒任务"
                
            # 删除过期的或允许覆盖的
            for item in reminders_to_remove:
                if item in self.custom_reminders:
                    self.custom_reminders.remove(item)
                    
        self.custom_reminders.append(data)
        self.save_custom_reminders()
        self.generate_daily_reminders() # 重新生成
        return True, "添加成功"

    def update_custom_reminder(self, old_data, new_data, origin_slot_start=None):
        # 更新其实就是删除旧的，添加新的
        # 但我们需要先检查新的能否添加
        
        # 1. 暂时移除旧的
        if old_data in self.custom_reminders:
            self.custom_reminders.remove(old_data)
            
        # 2. 尝试添加新的，并传入 origin_slot_start
        success, msg = self.add_custom_reminder(new_data, origin_slot_start)
        
        if not success:
            # 如果失败，把旧的加回来
            self.custom_reminders.append(old_data)
            self.save_custom_reminders() # 恢复保存
            return False, msg
            
        return True, "更新成功"

    def delete_custom_reminder(self, data):
        if data in self.custom_reminders:
            self.custom_reminders.remove(data)
            self.save_custom_reminders()
            self.generate_daily_reminders()

    def generate_daily_reminders(self):
        """根据当天课表生成提醒（始终生成今天和明天的）"""
        if not hasattr(self, 'kb_list') or not self.kb_list:
            return
            
        now = datetime.datetime.now()
        today_str = now.strftime("%Y-%m-%d")
        tomorrow = now + datetime.timedelta(days=1)
        tomorrow_str = tomorrow.strftime("%Y-%m-%d")
        
        # Clear old course and custom reminders
        # 注意：这里我们保留 custom_reminders 数据源不变，只是清空 self.reminders 列表
        self.reminders = []
        
        # 1. Custom Reminders (Full List)
        # 将所有自定义提醒加入到 reminders 列表
        for item in self.custom_reminders:
            try:
                # 检查是否过期（仅保留未来的或近期的）
                # 不过为了让列表显示，我们暂时全部加入，列表显示时再过滤周次
                # 但这里是 generate_daily_reminders，主要用于弹窗？
                # 不，self.reminders 也被 ReminderManagerWindow 用来显示。
                # 但 ReminderManagerWindow 主要是按周次显示课程。
                # 自定义提醒是按具体日期的。
                
                # 为了能在 ReminderManagerWindow 中显示，我们需要将它们全部加入
                # 冲突检测将在后面统一处理（如果需要）
                
                self.reminders.append(item)
            except: pass
        
        # 定义需要处理的日期列表
        target_dates = [now, tomorrow]
        
        # 2. Course Reminders
        for current_date in target_dates:
            date_str = current_date.strftime("%Y-%m-%d")
            weekday = current_date.isoweekday()
            
            # 1. 合并课程
            merged_courses = []
            current_group = None
            
            for slot in DAILY_SCHEDULE:
                if slot["name"] == "午休": continue
                
                course = self.find_course(weekday, slot["name"])
                
                if not course:
                    if current_group:
                        merged_courses.append(current_group)
                        current_group = None
                    continue
                    
                if current_group and \
                   current_group['course'].get('kcmc') == course.get('kcmc') and \
                   current_group['course'].get('cdmc') == course.get('cdmc'):
                    # 合并
                    current_group['end_slot'] = slot['name']
                    current_group['end_time'] = slot['end']
                else:
                    if current_group:
                        merged_courses.append(current_group)
                    current_group = {
                        'start_slot': slot['name'],
                        'end_slot': slot['name'],
                        'start_time': slot['start'],
                        'end_time': slot['end'],
                        'course': course
                    }
            
            if current_group:
                merged_courses.append(current_group)
                
            # 2. 生成提醒
            for item in merged_courses:
                course = item['course']
                start_time_str = item['start_time']
                start_dt = datetime.datetime.combine(current_date.date(), datetime.datetime.strptime(start_time_str, "%H:%M").time())
                
                # 计算提醒时间：上课前25分钟
                remind_dt = start_dt - datetime.timedelta(minutes=25)
                
                # 冲突检测：检查提醒时间是否处于其他课程的上课时间段内
                # 无论是今天还是明天的提醒，只要和其他课程冲突，都标记为“失效”
                # 注意：这里需要检查该日期的所有课程时间
                
                is_conflict = False
                remind_time_str_check = remind_dt.strftime("%H:%M")
                
                for other_item in merged_courses:
                    if other_item == item: continue
                    # 检查提醒时间点是否在其他课程的时间段 [start, end] 内
                    if other_item['start_time'] <= remind_time_str_check <= other_item['end_time']:
                        is_conflict = True
                        break
                
                # 还需要检查是否与自定义提醒冲突（如果自定义提醒时间也在上课时间内）
                # 其实自定义提醒创建时已经检查了冲突，所以这里只需要检查课程之间的冲突，
                # 或者课程提醒是否与自定义提醒冲突？
                # 用户没提这个，暂时只保留课程间冲突检测
                
                # 如果有冲突，我们依然添加到列表中，但在 check_reminders 时不触发弹窗
                # 并且在 ReminderManagerWindow 中显示为灰色
                
                # 过期检测：只有当提醒时间确实已经过去（小于当前时间-2分钟）才跳过
                # 留2分钟缓冲，防止刚过一分钟就消失，导致界面上看也是过期的
                if remind_dt < now - datetime.timedelta(minutes=2) and not is_conflict:
                    continue
                    
                remind_time_str = remind_dt.strftime("%Y-%m-%d %H:%M")
                
                # 查重
                exists = False
                title = f"上课提醒: {course.get('kcmc')}"
                for r in self.reminders:
                    if r['time'] == remind_time_str and r['title'] == title:
                        exists = True
                        break
                
                if not exists:
                    slot_info = f"{item['start_slot']}-{item['end_slot']}节" if item['start_slot'] != item['end_slot'] else f"{item['start_slot']}节"
                    self.reminders.append({
                        'type': 'course',
                        'time': remind_time_str,
                        'title': title,
                        'content': f"时间: {start_time_str} ({slot_info})\n地点: {course.get('cdmc')}\n老师: {course.get('xm')}",
                        'course_name': course.get('kcmc'),
                        'location': course.get('cdmc'),
                        'teacher': course.get('xm'),
                        'is_conflict': is_conflict # 标记冲突状态
                    })
        
        # 排序
        self.reminders.sort(key=lambda x: x['time'])

    def check_reminders(self):
        """检查是否有需要触发的提醒"""
        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M")
        
        # 为了防止多次触发，我们记录已触发的
        if not hasattr(self, 'triggered_reminders'):
             self.triggered_reminders = set()

        for r in self.reminders:
            # 如果标记为冲突，则直接跳过，不触发弹窗
            if r.get('is_conflict', False):
                continue
                
            # 简单的唯一标识
            rid = f"{r['time']}_{r['title']}"
            
            # 1. 精确时间匹配（当前分钟）
            if r['time'] == now_str and rid not in self.triggered_reminders:
                # 触发提醒
                self.show_notification(r)
                self.triggered_reminders.add(rid)
                continue
            
            # 2. 补救措施：如果提醒时间在过去1分钟内，且未触发过，也触发（防止定时器刚好错过整分）
            # 解析 r['time']
            try:
                r_dt = datetime.datetime.strptime(r['time'], "%Y-%m-%d %H:%M")
                # 计算差异
                diff = (now - r_dt).total_seconds()
                # 如果超过了0秒但小于60秒（即刚刚过期不到1分钟），且没触发过
                if 0 < diff < 60 and rid not in self.triggered_reminders:
                     self.show_notification(r)
                     self.triggered_reminders.add(rid)
            except: pass

    def show_notification(self, data):
        # 弹窗
        popup = NotificationPopup(data, None) # parent=None以独立于主窗口
        
        if not hasattr(self, 'popups'):
            self.popups = []
        
        # 清理已关闭的弹窗引用
        self.popups = [p for p in self.popups if p.isVisible()]
        
        self.popups.append(popup)
        popup.show_animation()

    def get_all_reminders(self):
        self.generate_daily_reminders() # 确保是最新的
        return self.reminders

    def open_reminder_window(self):
        if not hasattr(self, 'reminder_window') or not self.reminder_window:
            self.reminder_window = ReminderManagerWindow(self)
        
        # 确保窗口显示、恢复（如果最小化）并置顶
        self.reminder_window.showNormal() # 恢复窗口（如果最小化）
        self.reminder_window.activateWindow() # 激活窗口
        self.reminder_window.raise_() # 提升到最前
        self.reminder_window.load_reminders()

    def add_reminder(self, reminder):
        """添加提醒"""
        self.reminders.append(reminder)
        self.reminders.sort(key=lambda x: x['time'])
        
    def remove_reminder(self, reminder):
        """删除提醒"""
        if reminder in self.reminders:
            self.reminders.remove(reminder)
    def initTray(self):
        # 初始化托盘图标
        self.tray_icon = QSystemTrayIcon(self)
        
        # 设置图标
        logo_path = find_resource("logo.png")
        if logo_path:
            self.tray_icon.setIcon(QIcon(logo_path))
        else:
            # 创建一个默认图标（避免在Windows上不显示）
            pixmap = QPixmap(64, 64)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            
            # 画一个圆形背景
            painter.setBrush(QColor("#409eff"))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(4, 4, 56, 56)
            
            # 画文字
            painter.setPen(QColor("white"))
            font = QFont("Microsoft YaHei", 24, QFont.Bold)
            painter.setFont(font)
            painter.drawText(pixmap.rect(), Qt.AlignCenter, "课")
            
            painter.end()
            self.tray_icon.setIcon(QIcon(pixmap))
        
        # 托盘菜单
        tray_menu = QMenu()
        restore_action = QAction("显示主界面", self)
        restore_action.triggered.connect(self.showNormal)
        tray_menu.addAction(restore_action)
        
        quit_action = QAction("退出", self)
        quit_action.triggered.connect(self.logout_and_quit)
        tray_menu.addAction(quit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.on_tray_activated)
        self.tray_icon.show()

    def on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.showNormal()
            self.activateWindow()

    def hide_to_tray(self):
        self.hide()
        # 仅在第一次隐藏时提示
        if not hasattr(self, 'tray_tip_shown'):
            self.tray_icon.showMessage(
                "SUSE 教务助手",
                "程序已隐藏到托盘，提醒功能仍在运行",
                QSystemTrayIcon.Information,
                2000
            )
            self.tray_tip_shown = True

    def closeEvent(self, event):
        # 移除隐藏到托盘逻辑，直接接受关闭
        event.accept()

    def initUI(self):
        # 真正意义上的悬浮窗设置
        # Qt.Tool: 使窗口作为工具窗口，不显示在任务栏
        # Qt.FramelessWindowHint: 无边框
        # Qt.WindowStaysOnTopHint: 窗口置顶
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(main_layout)
        
        # 主容器
        self.container = QFrame()
        self.update_container_style()
        self.container.setObjectName("Container")
        main_layout.addWidget(self.container)
        
        content_layout = QVBoxLayout(self.container)
        content_layout.setContentsMargins(20, 15, 20, 20)
        content_layout.setSpacing(15)
        
        # 顶部栏
        header_layout = QHBoxLayout()
        
        self.date_label = QLabel(f"第{self.current_week}周")
        self.date_label.setFont(QFont("Microsoft YaHei UI", 14, QFont.Bold))
        self.date_label.setStyleSheet("color: #c678dd;")
        header_layout.addWidget(self.date_label)
        
        header_layout.addStretch()
        
        # 按钮样式
        btn_style = """
            QPushButton { color: #abb2bf; border: none; font-size: 16px; background: rgba(255,255,255,0.1); border-radius: 6px; padding: 4px; }
            QPushButton:hover { background: rgba(255,255,255,0.25); color: white; }
        """
        
        # 窗口置顶按钮 (锁)
        # 初始状态下是非置顶的
        self.lock_btn = QPushButton("🔓") # 默认为未置顶状态（开锁）
        self.lock_btn.setFixedSize(32, 32)
        self.lock_btn.setToolTip("窗口置顶")
        self.lock_btn.setCursor(Qt.PointingHandCursor)
        self.lock_btn.setStyleSheet(btn_style)
        self.lock_btn.setCheckable(True)
        self.lock_btn.setChecked(False) # 默认未选中
        self.lock_btn.clicked.connect(lambda: self.toggle_top_window())
        header_layout.addWidget(self.lock_btn)
        
        # 展开按钮
        expand_btn = QPushButton("⛶")
        expand_btn.setFixedSize(32, 32)
        expand_btn.setToolTip("查看完整课表")
        expand_btn.setCursor(Qt.PointingHandCursor)
        expand_btn.setStyleSheet(btn_style)
        expand_btn.clicked.connect(self.show_week_schedule)
        header_layout.addWidget(expand_btn)

        # 最小化按钮
        min_btn = QPushButton("－") # 使用全角减号使其更明显
        min_btn.setFixedSize(32, 32)
        min_btn.setToolTip("隐藏到托盘")
        min_btn.setCursor(Qt.PointingHandCursor)
        min_btn.setStyleSheet(btn_style)
        min_btn.clicked.connect(self.hide_to_tray)
        header_layout.addWidget(min_btn)

        # 菜单按钮 (三横线)
        menu_btn = QPushButton("☰")
        menu_btn.setFixedSize(32, 32)
        menu_btn.setToolTip("菜单")
        menu_btn.setCursor(Qt.PointingHandCursor)
        menu_btn.setStyleSheet(btn_style)
        
        # 创建菜单
        self.menu = QMenu(self)
        self.menu.setStyleSheet("""
            QMenu {
                background-color: #2c313a;
                color: #abb2bf;
                border: 1px solid rgba(255,255,255,0.1);
                border-radius: 4px;
            }
            QMenu::item {
                padding: 8px 24px;
                background-color: transparent;
            }
            QMenu::item:selected {
                background-color: #3e4451;
                color: white;
            }
        """)
        
        # 直接在一级菜单添加功能
        refresh_action = QAction("刷新课表", self)
        refresh_action.triggered.connect(self.refresh_from_server)
        self.menu.addAction(refresh_action)
        
        reminder_action = QAction("提醒功能", self)
        reminder_action.triggered.connect(self.open_reminder_window)
        self.menu.addAction(reminder_action)
        
        opacity_action = QAction("调节透明度", self)
        opacity_action.triggered.connect(self.open_opacity_dialog)
        self.menu.addAction(opacity_action)
        
        about_action = QAction("关于", self)
        about_action.triggered.connect(lambda: QMessageBox.information(self, "关于", "青蟹v1.1.3"))
        self.menu.addAction(about_action)
        
        # 分隔线
        self.menu.addSeparator()
        
        # 退出选项
        quit_action = QAction("退出程序", self)
        quit_action.triggered.connect(self.logout_and_quit)
        self.menu.addAction(quit_action)
        
        menu_btn.setMenu(self.menu)
        header_layout.addWidget(menu_btn)
        
        # 关闭按钮
        close_btn = QPushButton("×")
        close_btn.setFixedSize(32, 32)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet(btn_style.replace("hover { background: rgba(255,255,255,0.25);", "hover { background: #e06c75;"))
        close_btn.clicked.connect(QApplication.quit) # 直接退出程序
        header_layout.addWidget(close_btn)
        
        content_layout.addLayout(header_layout)
        
        # 滚动区域显示当天课程
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        # 禁止水平滚动条，垂直滚动条设为自动（仅内容超出时显示）
        self.scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff) # 隐藏垂直滚动条，但保留滚动功能
        self.scroll_area.setStyleSheet("background: transparent; border: none;")
        self.scroll_area.viewport().setStyleSheet("background: transparent;")
        
        self.scroll_content = QWidget()
        self.scroll_content.setObjectName("scroll_content")
        self.scroll_layout = QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(0, 0, 0, 0)
        self.scroll_layout.setSpacing(12)
        # 设置对齐方式，确保内容从顶部开始
        self.scroll_layout.setAlignment(Qt.AlignTop)
        self.scroll_area.setWidget(self.scroll_content)
        
        content_layout.addWidget(self.scroll_area)
        
        # [标记] 初始化与最小尺寸设置开始
        # 设置最小尺寸和初始尺寸，确保内容完整显示且不换行
        # 宽度增加以容纳单行信息，高度适应倒计时+2节课
        min_width = 430
        min_height = 500
        self.setMinimumSize(min_width, min_height)  # [标记] 悬浮窗最小尺寸设置
        self.resize(min_width, min_height)          # [标记] 悬浮窗初始化尺寸设置
        # [标记] 初始化与最小尺寸设置结束
        
        self.center_right()
        
        # 尺寸调整手柄 (放在右下角，父对象设为 self 以调整窗口大小)
        self.sizegrip = QSizeGrip(self) 
        self.sizegrip.setStyleSheet("width: 20px; height: 20px; background: transparent;")
        
        self.update_daily_schedule()

    def logout_and_quit(self):
        """退出并取消自动登录"""
        try:
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    config = json.load(f)
                
                # 取消自动登录，但保留记住密码
                config["auto_login"] = False
                
                with open("config.json", "w") as f:
                    json.dump(config, f)
        except Exception as e:
            print(f"Logout error: {e}")
            
        QApplication.quit()

    def update_container_style(self):
        self.container.setStyleSheet(f"""
            QFrame#Container {{
                background-color: rgba(30, 34, 42, {self.bg_opacity});
                border-radius: 16px;
                border: 1px solid rgba(255, 255, 255, 25);
            }}
            QScrollBar:vertical {{
                border: none;
                background: rgba(0,0,0,0);
                width: 6px;
                margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: rgba(255,255,255,0.2);
                min-height: 20px;
                border-radius: 3px;
            }}
            QScrollArea {{
                background: transparent;
                border: none;
            }}
            QWidget#scroll_content {{
                background: transparent;
            }}
        """)

    def open_opacity_dialog(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("调节透明度")
        dialog.setFixedSize(300, 100)
        dialog.setWindowFlags(Qt.Dialog | Qt.FramelessWindowHint) # Make it frameless to match style
        dialog.setStyleSheet("""
            QDialog {
                background-color: #2c313a; 
                border: 1px solid #3e4451;
                border-radius: 8px;
            }
            QLabel { color: white; font-family: 'Microsoft YaHei UI'; }
            QSlider::groove:horizontal {
                border: 1px solid #3e4451;
                height: 8px;
                background: #21252b;
                margin: 2px 0;
                border-radius: 4px;
            }
            QSlider::handle:horizontal {
                background: #61afef;
                border: 1px solid #61afef;
                width: 18px;
                height: 18px;
                margin: -7px 0;
                border-radius: 9px;
            }
        """)
        
        layout = QVBoxLayout(dialog)
        
        # Header with close button
        header = QHBoxLayout()
        title = QLabel("背景透明度")
        title.setStyleSheet("font-weight: bold;")
        header.addWidget(title)
        header.addStretch()
        close_btn = QPushButton("×")
        close_btn.setFixedSize(24, 24)
        close_btn.setCursor(Qt.PointingHandCursor)
        close_btn.setStyleSheet("QPushButton { color: #abb2bf; border: none; font-size: 16px; } QPushButton:hover { color: white; }")
        close_btn.clicked.connect(dialog.close)
        header.addWidget(close_btn)
        layout.addLayout(header)
        
        slider = QSlider(Qt.Horizontal)
        slider.setRange(20, 255) # Allow almost transparent
        slider.setValue(self.bg_opacity)
        slider.valueChanged.connect(self.set_bg_opacity)
        
        layout.addWidget(slider)
        
        val_label = QLabel(f"{int(self.bg_opacity/255*100)}%")
        val_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(val_label)
        
        slider.valueChanged.connect(lambda v: val_label.setText(f"{int(v/255*100)}%"))
        
        dialog.exec_()

    def set_bg_opacity(self, value):
        self.bg_opacity = value
        self.update_container_style()

    # 确保 sizegrip 始终在右下角
    def resizeEvent(self, event):
        if hasattr(self, 'sizegrip'):
            self.sizegrip.move(self.width() - 20, self.height() - 20)
            
        super().resizeEvent(event)

    def center_right(self):
        # 获取可用屏幕几何信息（排除任务栏）
        screen_geo = QApplication.desktop().availableGeometry()
        # 移动到右侧，留出 50px 边距
        x = screen_geo.width() - self.width() - 50
        y = screen_geo.y() + 100 # 相对顶部偏移 100px
        
        # 确保 x 坐标是相对于屏幕左上角的（处理多屏情况）
        x += screen_geo.x()
        
        self.move(x, y)

    def showEvent(self, event):
        # 确保每次显示时都在屏幕范围内，或者第一次显示时归位
        # 这里我们简单地在第一次显示时调用 center_right
        # 如果需要记忆位置，可以保存配置
        if not hasattr(self, 'first_show'):
            self.center_right()
            self.first_show = True
        super().showEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.drag_pos = event.globalPos() - self.frameGeometry().topLeft()
            event.accept()

    def mouseMoveEvent(self, event):
        if event.buttons() == Qt.LeftButton:
            self.move(event.globalPos() - self.drag_pos)
            event.accept()
    
    def toggle_top_window(self, checked=None):
        if checked is None:
            # 如果是按钮点击，checked 由按钮状态决定
            checked = self.lock_btn.isChecked()
            
        # 始终保持 FramelessWindowHint 和 Tool 属性
        base_flags = Qt.FramelessWindowHint | Qt.Tool
        
        if checked:
            self.setWindowFlags(base_flags | Qt.WindowStaysOnTopHint)
            self.lock_btn.setText("🔒")
            self.lock_btn.setToolTip("取消置顶")
        else:
            self.setWindowFlags(base_flags)
            self.lock_btn.setText("🔓")
            self.lock_btn.setToolTip("窗口置顶")
        self.show()

    def setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_daily_schedule)
        # 将定时器频率提高到 3秒，避免错过整分时刻
        self.timer.start(3000)

    def calculate_current_week(self):
        if not self.start_date_str:
            now = datetime.datetime.now()
            # 默认开学时间（仅作参考）
            start_date = datetime.datetime(now.year, 9, 1) if now.month >= 8 else datetime.datetime(now.year, 2, 20)
        else:
            try:
                start_date = datetime.datetime.strptime(self.start_date_str, "%Y-%m-%d")
            except: return 1
            
        now = datetime.datetime.now()
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        now_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
        
        diff = now_date - start_date
        # 逻辑优化：start_date 是第0周（报到周），真正的第1周从 start_date + 7天开始
        # 所以天数差除以7得到的是从start_date开始过了几周
        # 如果 diff.days < 7，说明还在第0周
        # 如果 7 <= diff.days < 14，说明是第1周，以此类推
        
        # 简单计算：(diff.days // 7) 得到的是完整的周数
        # 比如第0-6天，result=0，对应第0周
        # 第7-13天，result=1，对应第1周
        week = diff.days // 7
        
        return max(0, week) # 允许返回0周，或者根据需求最小为1

    def refresh_from_server(self):
        """从服务器刷新课表"""
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                username = config.get("username", "")
                password = LocalEncryptor.decrypt(config.get("password", ""))
                
            if not username or not password:
                QMessageBox.warning(self, "刷新失败", "未找到保存的账号密码，请重新登录")
                return
                
            self.lock_btn.setEnabled(False) # 借用一下按钮状态表示正在刷新
            
            # 创建新的 client
            self.temp_client = SuseJwglClient()
            self.login_worker = LoginWorker(self.temp_client, username, password)
            self.login_worker.finished.connect(self.on_refresh_login_finished)
            self.login_worker.start()
            
        except Exception as e:
            QMessageBox.warning(self, "刷新失败", str(e))
            
    def on_refresh_login_finished(self, success, msg):
        if not success:
            QMessageBox.warning(self, "刷新失败", f"登录失败: {msg}")
            self.lock_btn.setEnabled(True)
            self.temp_client.close_session()
            return
            
        now = datetime.datetime.now()
        if now.month >= 8:
            year = str(now.year)
            semester = "3"
        elif now.month < 2:
            year = str(now.year - 1)
            semester = "3"
        else:
            year = str(now.year - 1)
            semester = "12"
            
        self.schedule_worker = ScheduleWorker(self.temp_client, year, semester)
        self.schedule_worker.finished.connect(self.on_refresh_schedule_finished)
        self.schedule_worker.start()

    def on_refresh_schedule_finished(self, data, start_date):
        self.lock_btn.setEnabled(True)
        self.temp_client.close_session() # 关闭会话
        
        if not data:
            QMessageBox.warning(self, "刷新失败", "获取课表数据为空")
            return
            
        # 更新数据
        self.schedule_data = data
        self.kb_list = data.get('kbList', [])
        if start_date:
            self.start_date_str = start_date
            
        # 保存缓存
        try:
            cache = {
                "schedule": data,
                "start_date": self.start_date_str,
                "update_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            with open("schedule_cache.json", "w", encoding='utf-8') as f:
                json.dump(cache, f, ensure_ascii=False)
        except: pass
            
        # 重新计算周次并刷新界面
        self.current_week = self.calculate_current_week()
        self.update_daily_schedule()
        
        # 立即重新生成提醒（包括清除旧的和添加新的）
        self.generate_daily_reminders()
        
        QMessageBox.information(self, "刷新成功", "课表已更新")

    def update_daily_schedule(self):
        # 顺便生成和检查提醒
        self.generate_daily_reminders()
        self.check_reminders()
        
        # 清空当前列表
        while self.scroll_layout.count():
            item = self.scroll_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        now = datetime.datetime.now()
        weekday = now.isoweekday()
        now_time = now.strftime("%H:%M")
        
        weekdays = ["一", "二", "三", "四", "五", "六", "日"]
        self.date_label.setText(f"第{self.current_week}周 星期{weekdays[weekday-1]}")
        
        # 获取今日课程
        merged_courses = self.get_daily_courses(now)
        
        # 查找下一节课并显示倒计时
        next_course_time = None
        next_course = None 
        countdown_end_time = None 
        is_last_class = False
        
        # 确定倒计时目标
        for i, item in enumerate(merged_courses):
            start_time = item['start_time']
            end_time = item['end_time']
            
            # 情况1：还没开始上课
            if start_time > now_time:
                next_course_time = start_time
                next_course = item['course']
                break 
            
            # 情况2：正在上课中
            if start_time <= now_time <= end_time:
                next_course_time = start_time 
                countdown_end_time = end_time 
                next_course = item['course']
                
                if i == len(merged_courses) - 1:
                    is_last_class = True
                break
        
        # 渲染逻辑
        if next_course_time:
            # 还有课（或者正在上课）
            countdown = CountdownCard(next_course, next_course_time, end_time=countdown_end_time, is_last_class=is_last_class)
            self.scroll_layout.addWidget(countdown)
            
            # 显示今天的课程列表
            past_courses = []
            future_courses = []
            
            for item in merged_courses:
                is_past = item['end_time'] < now_time
                if is_past:
                    past_courses.append(item)
                else:
                    future_courses.append(item)
            
            for item in future_courses:
                slot_str = f"{item['start_slot']}-{item['end_slot']}节" if item['start_slot'] != item['end_slot'] else f"{item['start_slot']}节"
                time_str = f"{item['start_time']} ~ {item['end_time']}"
                is_current = item['start_time'] <= now_time <= item['end_time']
                
                card = CourseCard(
                    item["course"], 
                    slot_str,
                    time_str,
                    is_current=is_current,
                    is_past=False,
                    next_start_time=item.get("start_time") if not is_current and item.get("start_time") > now_time else None
                )
                self.scroll_layout.addWidget(card)
            
            if past_courses and future_courses:
                 line = QFrame()
                 line.setFrameShape(QFrame.HLine)
                 line.setStyleSheet("background-color: rgba(255, 255, 255, 0.1); margin: 10px 0;")
                 self.scroll_layout.addWidget(line)

            for item in past_courses:
                slot_str = f"{item['start_slot']}-{item['end_slot']}节" if item['start_slot'] != item['end_slot'] else f"{item['start_slot']}节"
                time_str = f"{item['start_time']} ~ {item['end_time']}"
                card = CourseCard(
                    item["course"], 
                    slot_str,
                    time_str,
                    is_current=False,
                    is_past=True, 
                    next_start_time=None
                )
                self.scroll_layout.addWidget(card)
                
        else:
            # 今天已经没有课了（或者本来就没课）
            liberated = LiberatedCard()
            self.scroll_layout.addWidget(liberated)
            
            # 分隔符
            separator = QLabel("--- 明天预告 ---")
            separator.setAlignment(Qt.AlignCenter)
            separator.setStyleSheet("color: #abb2bf; margin: 20px 0 10px 0; font-size: 18px; font-weight: bold;")
            self.scroll_layout.addWidget(separator)
            
            # 获取明天的课程
            tomorrow = now + datetime.timedelta(days=1)
            tomorrow_courses = self.get_daily_courses(tomorrow)
            
            if not tomorrow_courses:
                lbl = QLabel("明天也没有课，太棒了！")
                lbl.setFont(QFont("Microsoft YaHei UI", 12))
                lbl.setStyleSheet("color: #abb2bf; margin-top: 10px;")
                lbl.setAlignment(Qt.AlignCenter)
                self.scroll_layout.addWidget(lbl)
            else:
                for item in tomorrow_courses:
                    slot_str = f"{item['start_slot']}-{item['end_slot']}节" if item['start_slot'] != item['end_slot'] else f"{item['start_slot']}节"
                    time_str = f"{item['start_time']} ~ {item['end_time']}"
                    
                    card = CourseCard(
                        item["course"], 
                        slot_str,
                        time_str,
                        is_current=False,
                        is_past=False, # 明天的课不标记为past
                        next_start_time=None
                    )
                    self.scroll_layout.addWidget(card)
                    
        self.scroll_layout.addStretch()

    def get_week_for_date(self, date_obj):
        if not self.start_date_str:
            now = datetime.datetime.now()
            start_date = datetime.datetime(now.year, 9, 1) if now.month >= 8 else datetime.datetime(now.year, 2, 20)
        else:
            try:
                start_date = datetime.datetime.strptime(self.start_date_str, "%Y-%m-%d")
            except: 
                start_date = datetime.datetime.now() # Fallback
        
        start_date = start_date.replace(hour=0, minute=0, second=0, microsecond=0)
        target_date = date_obj.replace(hour=0, minute=0, second=0, microsecond=0)
        
        diff = target_date - start_date
        week = diff.days // 7
        return max(0, week)

    def get_daily_courses(self, target_date):
        week = self.get_week_for_date(target_date)
        weekday = target_date.isoweekday()
        
        merged_courses = []
        current_group = None
        
        for slot in DAILY_SCHEDULE:
            if slot["name"] == "午休": continue
            
            course = self.find_course(weekday, slot["name"], week_num=week)
            
            if not course:
                if current_group:
                    merged_courses.append(current_group)
                    current_group = None
                continue
                
            if current_group and \
               current_group['course'].get('kcmc') == course.get('kcmc') and \
               current_group['course'].get('cdmc') == course.get('cdmc'):
                # 合并
                current_group['end_slot'] = slot['name']
                current_group['end_time'] = slot['end']
            else:
                if current_group:
                    merged_courses.append(current_group)
                current_group = {
                    'start_slot': slot['name'],
                    'end_slot': slot['name'],
                    'start_time': slot['start'],
                    'end_time': slot['end'],
                    'course': course
                }
        
        if current_group:
            merged_courses.append(current_group)
            
        return merged_courses

    def find_course(self, weekday, section_name, week_num=None):
        if not self.kb_list: return None
        target_week = week_num if week_num is not None else self.current_week
        for course in self.kb_list:
            if not self.is_week_active(course.get('zcd'), target_week): continue
            if str(course.get('xqj')) != str(weekday): continue
            if self.is_section_active(course.get('jcs', ''), section_name):
                return course
        return None

    def is_week_active(self, weeks_str, current_week):
        if not weeks_str: return False
        is_odd_only = "单" in weeks_str
        is_even_only = "双" in weeks_str
        clean_str = weeks_str.replace("周", "").replace("单", "").replace("双", "").replace("(", "").replace(")", "").replace("（", "").replace("）", "")
        for part in clean_str.split(","):
            try:
                if "-" in part:
                    start, end = map(int, part.split("-"))
                    if start <= current_week <= end:
                        if is_odd_only and current_week % 2 == 0: return False
                        if is_even_only and current_week % 2 != 0: return False
                        return True
                elif int(part) == current_week:
                    return True
            except: continue
        return False

    def is_section_active(self, jcs, current_section):
        if not jcs: return False
        try:
            current = int(current_section)
            if "-" in jcs:
                start, end = map(int, jcs.split("-"))
                return start <= current <= end
            return int(jcs) == current
        except: return False
        
    def show_week_schedule(self):
        if not self.week_window:
            self.week_window = WeekScheduleWindow(self.schedule_data, self.start_date_str, self.current_week)
        
        # 确保窗口显示、恢复（如果最小化）并置顶
        self.week_window.showNormal()
        self.week_window.activateWindow()
        self.week_window.raise_()

# LoginWindow 和 LoginWorker, ScheduleWorker 保持不变
class LoginWorker(QThread):
    finished = pyqtSignal(bool, str)
    def __init__(self, client, username, password):
        super().__init__()
        self.client = client
        self.username = username
        self.password = password
    def run(self):
        success, msg = self.client.login(self.username, self.password)
        self.finished.emit(success, msg)

class ScheduleWorker(QThread):
    finished = pyqtSignal(dict, str)
    def __init__(self, client, year, semester):
        super().__init__()
        self.client = client
        self.year = year
        self.semester = semester
    def run(self):
        data = self.client.get_schedule(self.year, self.semester)
        start_date = self.client.get_calendar_start_date()
        # 获取完数据后关闭会话
        self.client.close_session()
        self.finished.emit(data if data else {}, start_date if start_date else "")

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.client = SuseJwglClient()
        self.migrate_cache_files()
        self.initUI()
        self.load_config()

    def migrate_cache_files(self):
        """迁移旧版缓存到多账号格式"""
        try:
            # 1. 获取最后登录的账号
            last_user = "unknown"
            if os.path.exists("config.json"):
                try:
                    with open("config.json", "r") as f:
                        config = json.load(f)
                        last_user = config.get("username", "unknown")
                        
                        # 检查是否是旧版 config 结构（没有 users 字段）
                        if "users" not in config and "username" in config:
                            new_config = {
                                "last_login_user": last_user,
                                "users": [
                                    {
                                        "username": config["username"],
                                        "password": config.get("password", ""),
                                        "schedule_id": f"schedule_{config['username']}",
                                        "remember": config.get("remember", False),
                                        "auto_login": config.get("auto_login", False)
                                    }
                                ]
                            }
                            with open("config.json", "w") as fw:
                                json.dump(new_config, fw, indent=4)
                except: pass

            # 2. 迁移 schedule_cache.json
            if os.path.exists("schedule_cache.json"):
                try:
                    with open("schedule_cache.json", "r", encoding='utf-8') as f:
                        data = json.load(f)
                    
                    # 检查是否是旧格式（包含 schedule 键）
                    if "schedule" in data:
                        # 这是一个单用户旧缓存
                        schedule_id = f"schedule_{last_user}"
                        new_data = {
                            schedule_id: {
                                "username": last_user,
                                "data": data,
                                "update_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            }
                        }
                        with open("schedule_cache.json", "w", encoding='utf-8') as f:
                            json.dump(new_data, f, ensure_ascii=False)
                    # 检查是否是中间版本（key是username）
                    elif any(k for k in data.keys() if k != "unknown" and isinstance(data[k], dict) and "schedule" in data[k]):
                        # 转换成新格式: key -> schedule_id
                        new_data = {}
                        for user, cache_content in data.items():
                            if user == "unknown" or not user: continue
                            s_id = f"schedule_{user}"
                            
                            # 确保不是已经是新格式了
                            if user.startswith("schedule_"):
                                new_data[user] = cache_content
                                continue
                                
                            new_data[s_id] = {
                                "username": user,
                                "data": cache_content, # 这里包含 schedule 和 start_date
                                "update_time": cache_content.get("update_time", "")
                            }
                        with open("schedule_cache.json", "w", encoding='utf-8') as f:
                            json.dump(new_data, f, ensure_ascii=False)
                    
                except Exception as e:
                    print(f"Migrate schedule cache error: {e}")

            # 3. 迁移 custom_reminders.json
            # 保持原样，或者也跟 schedule_id 绑定？既然用户只强调了课表和账号绑定，提醒先维持 username 绑定即可，或者也加上 schedule_id 映射
            # 考虑到简单性，提醒仍然跟 username 绑定，这不违反用户需求。
        except Exception as e:
            print(f"Migration error: {e}")

    def initUI(self):
        self.setWindowTitle("SUSE 教务系统助手")
        self.setFixedSize(360, 480) # 增加高度以容纳新选项
        
        # 设置背景和字体
        self.setStyleSheet("""
            QWidget {
                background-color: #ffffff;
                font-family: 'Microsoft YaHei UI', 'Segoe UI', sans-serif;
            }
            QCheckBox {
                spacing: 8px;
                color: #666;
                font-size: 13px;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(40, 40, 40, 40)
        layout.setSpacing(20)

        # 标题区域
        title_lbl = QLabel("教务系统登录")
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("""
            font-size: 24px;
            font-weight: bold;
            color: #333333;
            margin-bottom: 5px;
        """)
        layout.addWidget(title_lbl)
        
        subtitle_lbl = QLabel("欢迎回来，请登录您的账号")
        subtitle_lbl.setAlignment(Qt.AlignCenter)
        subtitle_lbl.setStyleSheet("""
            font-size: 14px;
            color: #888888;
            margin-bottom: 15px;
        """)
        layout.addWidget(subtitle_lbl)

        # 输入框样式
        input_style = """
            QLineEdit {
                padding: 0 15px;
                min-height: 45px;
                border: 2px solid #eef0f5;
                border-radius: 8px;
                background-color: #f7f9fc;
                font-size: 14px;
                color: #333;
            }
            QLineEdit:focus {
                border: 2px solid #409eff;
                background-color: #ffffff;
            }
            QLineEdit:hover {
                background-color: #ffffff;
                border: 2px solid #dcdfe6;
            }
            QLineEdit[echoMode="2"] {
                lineedit-password-character: 42;
            }
        """

        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("请输入学号")
        self.user_input.setStyleSheet(input_style)
        # 增加账号输入完成后的自动填充逻辑
        self.user_input.editingFinished.connect(self.auto_fill_password)
        layout.addWidget(self.user_input)

        self.pwd_input = QLineEdit()
        self.pwd_input.setPlaceholderText("请输入密码")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setStyleSheet(input_style)
        layout.addWidget(self.pwd_input)

        # 记住密码和自动登录选项
        options_layout = QHBoxLayout()
        
        self.remember_cb = QCheckBox("记住密码")
        self.remember_cb.setCursor(Qt.PointingHandCursor)
        self.remember_cb.setStyleSheet("""
            QCheckBox {
                spacing: 8px;
                color: #666;
                font-size: 13px;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 4px;
                border: 2px solid #ccc;
                background: white;
            }
            QCheckBox::indicator:checked {
                border: 2px solid #409eff;
                background-color: #409eff;
                /* 调整 viewBox 为 "0 0 24 24"，路径点改为 "4 12 9 17 20 6"，描边宽度设为 3 */
                image: url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSIzIiBzdHJva2UtbGluZWNhcD0icm91bmQiIHN0cm9rZS1saW5lam9pbj0icm91bmQiPjxwb2x5bGluZSBwb2ludHM9IjQgMTIgOSAxNyAyMCA2IiAvPjwvc3ZnPg==);
            }
            QCheckBox::indicator:hover {
                border: 2px solid #409eff;
            }
        """)
        options_layout.addWidget(self.remember_cb)
        
        options_layout.addStretch()
        
        self.auto_login_cb = QCheckBox("自动登录")
        self.auto_login_cb.setCursor(Qt.PointingHandCursor)
        self.auto_login_cb.setStyleSheet(self.remember_cb.styleSheet())
        self.auto_login_cb.toggled.connect(lambda checked: self.remember_cb.setChecked(True) if checked else None)
        options_layout.addWidget(self.auto_login_cb)
        
        layout.addLayout(options_layout)

        # 登录按钮
        self.login_btn = QPushButton("登 录")
        self.login_btn.setCursor(Qt.PointingHandCursor)
        self.login_btn.setStyleSheet("""
            QPushButton {
                background-color: #409eff;
                color: white;
                border: none;
                border-radius: 8px;
                padding: 12px;
                font-size: 16px;
                font-weight: bold;
                letter-spacing: 2px;
                margin-top: 10px;
            }
            QPushButton:hover {
                background-color: #66b1ff;
            }
            QPushButton:pressed {
                background-color: #3a8ee6;
            }
            QPushButton:disabled {
                background-color: #a0cfff;
            }
        """)
        self.login_btn.clicked.connect(self.handle_login)
        layout.addWidget(self.login_btn)
        
        # 状态提示
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("color: #f56c6c; font-size: 12px; min-height: 20px;")
        layout.addWidget(self.status_label)
        
        layout.addStretch()
        self.setLayout(layout)

    def auto_fill_password(self):
        """输入账号后自动填充密码"""
        username = self.user_input.text().strip()
        if not username: return
        
        try:
            found = False
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    config = json.load(f)
                    
                if "users" in config:
                    user_conf = next((u for u in config["users"] if u["username"] == username), None)
                    if user_conf:
                        found = True
                        if user_conf.get("remember", False):
                            self.pwd_input.setText(LocalEncryptor.decrypt(user_conf.get("password", "")))
                            self.remember_cb.setChecked(True)
                            self.auto_login_cb.setChecked(user_conf.get("auto_login", False))
                        else:
                            self.pwd_input.clear()
                            self.remember_cb.setChecked(False)
                            self.auto_login_cb.setChecked(False)
            
            if not found:
                self.pwd_input.clear()
                self.remember_cb.setChecked(False)
                self.auto_login_cb.setChecked(False)
        except: pass

    def load_config(self):
        try:
            with open("config.json", "r") as f:
                config = json.load(f)
                
            # 优先使用新结构
            if "users" in config:
                last_user = config.get("last_login_user", "")
                self.user_input.setText(last_user)
                
                # 查找对应的用户配置
                user_conf = next((u for u in config["users"] if u["username"] == last_user), None)
                if user_conf:
                    if user_conf.get("remember", False):
                        self.pwd_input.setText(LocalEncryptor.decrypt(user_conf.get("password", "")))
                        self.remember_cb.setChecked(True)
                        if user_conf.get("auto_login", False):
                            self.auto_login_cb.setChecked(True)
                            QTimer.singleShot(500, self.handle_login)
            
            # 兼容旧结构
            elif "username" in config:
                if config.get("remember", False):
                    self.user_input.setText(config.get("username", ""))
                    self.pwd_input.setText(LocalEncryptor.decrypt(config.get("password", "")))
                    self.remember_cb.setChecked(True)
                    if config.get("auto_login", False):
                        self.auto_login_cb.setChecked(True)
                        QTimer.singleShot(500, self.handle_login)
        except:
            pass

    def save_config(self):
        username = self.user_input.text().strip()
        password = self.pwd_input.text().strip()
        remember = self.remember_cb.isChecked()
        auto_login = self.auto_login_cb.isChecked()
        
        try:
            config = {}
            if os.path.exists("config.json"):
                with open("config.json", "r") as f:
                    try:
                        config = json.load(f)
                    except: pass
            
            # 确保是新结构
            if "users" not in config:
                config["users"] = []
            
            config["last_login_user"] = username
            
            # 更新或添加用户
            user_entry = next((u for u in config["users"] if u["username"] == username), None)
            
            if user_entry:
                user_entry["password"] = LocalEncryptor.encrypt(password) if remember else ""
                user_entry["remember"] = remember
                user_entry["auto_login"] = auto_login
                # 确保有 schedule_id
                if "schedule_id" not in user_entry:
                    user_entry["schedule_id"] = f"schedule_{username}"
            else:
                config["users"].append({
                    "username": username,
                    "password": LocalEncryptor.encrypt(password) if remember else "",
                    "remember": remember,
                    "auto_login": auto_login,
                    "schedule_id": f"schedule_{username}"
                })
            
            with open("config.json", "w") as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            print(f"Save config failed: {e}")

    def handle_login(self):
        username = self.user_input.text().strip()
        password = self.pwd_input.text().strip()
        if not username or not password:
            self.status_label.setText("请输入账号和密码")
            return

        self.save_config() # 保存配置

        self.login_btn.setEnabled(False)
        self.login_btn.setText("登录中...")
        self.status_label.setText("正在连接...")
        
        self.worker = LoginWorker(self.client, username, password)
        self.worker.finished.connect(self.on_login_finished)
        self.worker.start()

    def on_login_finished(self, success, msg):
        if success:
            self.status_label.setText("登录成功，正在获取数据...")
            now = datetime.datetime.now()
            # 自动计算学年学期
            if now.month >= 8:
                year = str(now.year)
                semester = "3"
            elif now.month < 2:
                year = str(now.year - 1)
                semester = "3"
            else:
                year = str(now.year - 1)
                semester = "12"
            
            self.schedule_worker = ScheduleWorker(self.client, year, semester)
            self.schedule_worker.finished.connect(self.on_schedule_fetched)
            self.schedule_worker.start()
        else:
            # 尝试加载缓存
            cache_data = self.load_schedule_cache()
            if cache_data:
                self.status_label.setText("登录失败，使用离线缓存...")
                self.start_main_app(cache_data['schedule'], cache_data['start_date'])
                return
                
            self.login_btn.setEnabled(True)
            self.login_btn.setText("立即登录")
            self.status_label.setText(msg)
            self.status_label.setStyleSheet("color: #ff4d4f")

    def save_schedule_cache(self, data, start_date):
        """保存课表缓存"""
        try:
            username = self.user_input.text().strip()
            if not username: return
            
            # 生成唯一 ID
            schedule_id = f"schedule_{username}"
            
            # 读取现有缓存
            all_cache = {}
            if os.path.exists("schedule_cache.json"):
                with open("schedule_cache.json", "r", encoding='utf-8') as f:
                    try:
                        all_cache = json.load(f)
                        # 简单的旧格式兼容检查
                        if "schedule" in all_cache:
                            all_cache = {schedule_id: {"username": "unknown", "data": all_cache}}
                    except: pass
            
            # 增量添加/更新
            # 如果 schedule_id 不存在，这本身就是一种增量添加
            # 如果存在，则更新其内容
            all_cache[schedule_id] = {
                "username": username,
                "data": { # 保持内部结构，方便扩展
                    "schedule": data,
                    "start_date": start_date
                },
                "update_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            with open("schedule_cache.json", "w", encoding='utf-8') as f:
                json.dump(all_cache, f, ensure_ascii=False)
        except Exception as e:
            print(f"Save schedule cache error: {e}")

    def load_schedule_cache(self):
        """加载课表缓存"""
        try:
            username = self.user_input.text().strip()
            schedule_id = f"schedule_{username}"
            
            if os.path.exists("schedule_cache.json"):
                with open("schedule_cache.json", "r", encoding='utf-8') as f:
                    all_cache = json.load(f)
                    
                # 兼容旧格式
                if "schedule" in all_cache:
                    return all_cache
                
                # 新格式：通过 schedule_id 查找
                if schedule_id in all_cache:
                    return all_cache[schedule_id].get("data")
                
                # 兼容中间版本（key是username）
                if username in all_cache and "data" not in all_cache[username]:
                     return all_cache[username] # 这是上一轮修改产生的格式
                     
        except Exception as e:
            print(f"Load schedule cache error: {e}")
        return None

    def on_schedule_fetched(self, data, start_date):
        if not data:
            self.login_btn.setEnabled(True)
            self.login_btn.setText("立即登录")
            self.status_label.setText("获取课表失败")
            return
            
        # 保存缓存
        self.save_schedule_cache(data, start_date)
        
        self.status_label.setText("正在启动悬浮窗...")
        
        # 核心修复：使用 QTimer.singleShot 将 UI 创建任务抛给主线程事件循环 
        # 避免在子线程回调中直接初始化复杂的 UI 和托盘图标 
        QTimer.singleShot(100, lambda: self.start_main_app(data, start_date))

    def start_main_app(self, data, start_date):
        try:
            # 1. 创建并全局引用新窗口 
            global main_window
            username = self.user_input.text().strip()
            main_window = FloatingWindow(data, start_date, username)
            main_window.show()
            
            # 2. 确保它不会被销毁 
            global windows
            if 'windows' not in globals():
                windows = []
            windows.append(main_window)
            
            # 3. 彻底解绑登录窗口 
            self.hide()
            # 注意：不要立即 deleteLater，等新窗口稳定后再释放 
            QTimer.singleShot(2000, self.deleteLater)
            
        except Exception as e:
            print(f"启动失败: {e}")
            self.status_label.setText(f"启动失败: {e}")
            self.login_btn.setEnabled(True)

if __name__ == '__main__':
    # 启用高 DPI 缩放支持
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps)
    
    app = QApplication(sys.argv)
    # 防止窗口隐藏后程序直接退出
    app.setQuitOnLastWindowClosed(False)
    
    # 全局变量，防止垃圾回收
    windows = []
    
    window = LoginWindow()
    window.show()
    sys.exit(app.exec_())
