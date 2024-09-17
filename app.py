import psutil
from flask import Flask, render_template, request, jsonify, abort, redirect, url_for
from flask_socketio import SocketIO, emit
import time
from threading import Thread
import math
import concurrent.futures
import ipaddress

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
socketio = SocketIO(app)

# Словник для зберігання кількості HTTP-запитів від кожного IP
http_ip_dict = {}

# Словник для зберігання кількості TCP/UDP-з'єднань від кожного IP
tcp_ip_dict = {}

# Чорний список IP-адрес
blocked_ips = set()

# Максимальна кількість запитів на IP
MAX_REQUESTS_PER_MINUTE = 10000

# Очищаємо лічильники запитів що 100 сек
def clear_request_counters():
    while True:
        time.sleep(100)
        http_ip_dict.clear()

# Функція для перевірки, чи IP є локальним
def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        # Перевіряємо, чи адреса належить до приватної або локальної мережі
        return ip_obj.is_private or ip_obj.is_loopback
    except ValueError:
        return False

# Функція для збору активних TCP/UDP-з'єднань і метрик сервера
def background_thread():
    while True:
        tcp_ip_dict.clear()  # Очищуємо словник TCP/UDP-з'єднань
        cpu_usage = psutil.cpu_percent(interval=1)
        memory_info = psutil.virtual_memory()
        memory_usage = memory_info.percent
        net_io = psutil.net_io_counters()
        sent = net_io.bytes_sent
        recv = net_io.bytes_recv

        # Відстежуємо всі активні TCP/UDP-з'єднання
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    if is_local_ip(ip):  # Фільтруємо лише локальні IP
                        if ip in tcp_ip_dict:
                            tcp_ip_dict[ip] += 1  # Збільшуємо кількість запитів
                        else:
                            tcp_ip_dict[ip] = 1  # Додаємо новий IP
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            pass  # Ігноруємо процеси, до яких немає доступу

        # Надсилаємо дані на фронтенд
        socketio.emit('update_data', {
            'cpu': cpu_usage,
            'memory': memory_usage,
            'sent': sent,
            'recv': recv,
            'http_ip_dict': http_ip_dict,  # Словник HTTP-запитів
            'tcp_ip_dict': tcp_ip_dict  # Словник локальних TCP/UDP-з'єднань
        })
        time.sleep(1)

# Запускаємо фоновий потік для відстеження з'єднань та метрик сервера
def start_background_thread():
    thread = Thread(target=background_thread)
    thread.daemon = True
    thread.start()

# Функція для перевірки чи IP не заблокований
def check_ip_block(user_ip):
    if user_ip in blocked_ips:
        abort(403, description="Access denied: Your IP is blocked.")

# Функція для складних обчислень
def complex_calculation(start, end):
    result = 0
    for i in range(start, end):
        result += math.sqrt(i) ** 3 + math.sin(i) + math.sqrt(i) ** 3 + math.sin(i) ** 3 # Додаємо обчислення
    return result

@app.route('/')
def index():
    user_ip = request.remote_addr
    check_ip_block(user_ip)  # Перевіряємо чи IP не заблокований

    # Відслідковуємо кількість запитів від користувача
    if user_ip in http_ip_dict:
        http_ip_dict[user_ip] += 1
        if http_ip_dict[user_ip] > MAX_REQUESTS_PER_MINUTE:
            blocked_ips.add(user_ip)  # Додаємо IP в чорний список
            return jsonify({"error": "Too many requests, your IP is blocked."}), 429
    else:
        http_ip_dict[user_ip] = 1

    return render_template('index.html')

# Новий ендпойнт для виконання складних обчислень
@app.route('/heavy-calculation')
def heavy_calculation():
    user_ip = request.remote_addr
    check_ip_block(user_ip)  # Перевіряємо чи IP не заблокований

    # Відслідковуємо кількість запитів від користувача
    if user_ip in http_ip_dict:
        http_ip_dict[user_ip] += 1
        if http_ip_dict[user_ip] > MAX_REQUESTS_PER_MINUTE:
            blocked_ips.add(user_ip)  # Додаємо IP в чорний список
            return jsonify({"error": "Too many requests, your IP is blocked."}), 429
    else:
        http_ip_dict[user_ip] = 1

    # Виконуємо обчислення в 8 потоках для максимального навантаження на CPU
    chunks = [(i * 12500000, (i+1) * 12500000) for i in range(8)]  # 100 мільйонів ітерацій розбиті на 8 потоків
    result = 0
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_results = [executor.submit(complex_calculation, chunk[0], chunk[1]) for chunk in chunks]
        for future in concurrent.futures.as_completed(future_results):
            result += future.result()

    return jsonify({"result": result})

# Адміністративна сторінка для блокування IP
@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if request.method == 'POST':
        # Отримуємо IP з форми
        ip_to_block = request.form.get('ip')
        if ip_to_block:
            blocked_ips.add(ip_to_block)  # Додаємо IP в чорний список
        return redirect(url_for('admin'))

    return render_template('admin.html', blocked_ips=blocked_ips)

if __name__ == '__main__':
    start_background_thread()  # Запускаємо потік при старті

    # Запускаємо фоновий потік для очищення лічильників
    Thread(target=clear_request_counters, daemon=True).start()

    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
