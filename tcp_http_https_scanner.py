import socket
import threading
import ssl
import queue

# Максимальное количество потоков для сканирования портов
MAX_THREADS = 10

def scan_port(target, port):
    """Сканирует один порт и проверяет HTTP/HTTPS."""
    try:
        # print(f"Scanning port {port}...")  # Отладочное сообщение
        # Сканирование TCP-порта
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((target, port))
        if result == 0:
            print(f"Port {port} is open.")  # Отладочное сообщение
            port_info = {"port": port, "services": [], "paths": []}
            # Проверка HTTP
            if check_http(sock, target, port):
                print(f"Port {port} supports HTTP.")  # Отладочное сообщение
                port_info["services"].append("http")
                # Перебор файлов и директорий (многопоточный режим)
                scan_files_and_dirs(target, port, "http", port_info["paths"])
            # Проверка HTTPS
            if check_https(sock, target, port):
                print(f"Port {port} supports HTTPS.")  # Отладочное сообщение
                port_info["services"].append("https")
                # Перебор файлов и директорий (многопоточный режим)
                scan_files_and_dirs(target, port, "https", port_info["paths"])
            # Возвращаем информацию о порте
            if port_info["services"]:
                return port_info
        sock.close()  # Закрываем сокет после использования
    except Exception as e:
        print(f"Error scanning port {port}: {e}")
        if 'sock' in locals():
            sock.close()  # Закрываем сокет в случае ошибки
    return None

def check_http(sock, target, port):
    """Проверяет, поддерживает ли порт HTTP."""
    try:
        # Отправляем HTTP-запрос
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(1024).decode()
        if "HTTP/1.1" in response or "HTTP/1.0" in response:
            return True
    except Exception:
        pass
    return False

def check_https(sock, target, port):
    """Проверяет, поддерживает ли порт HTTPS."""
    try:
        # Создаем SSL-контекст
        context = ssl.create_default_context()
        with context.wrap_socket(sock, server_hostname=target) as ssock:
            # Проверяем, что соединение установлено
            return True
    except Exception:
        pass
    return False

def scan_files_and_dirs(target, port, protocol, paths):
    """Перебирает файлы и директории на сервере."""
    base_url = f"{protocol}://{target}:{port}"
    paths_to_scan = ["/", "/admin", "/login", "/static", "/manager"]  # Пример путей для сканирования

    # Очередь для многопоточного выполнения
    path_queue = queue.Queue()
    for path in paths_to_scan:
        path_queue.put(path)

    def worker():
        while not path_queue.empty():
            path = path_queue.get()
            try:
                print(f"Checking path {path} on port {port}...")  # Отладочное сообщение
                status, response_code, response_content = check_path(base_url, path)
                paths.append({
                    "path": path,
                    "status": status,
                    "response_code": response_code,
                    "response_content": response_content
                })
            except Exception as e:
                print(f"Error checking path {path}: {e}")
                # Переход в однопоточный режим при ошибке
                paths.append({
                    "path": path,
                    "status": "error",
                    "response_code": None,
                    "response_content": None
                })
                path_queue.task_done()
                break
            path_queue.task_done()

    # Многопоточный режим
    threads = []
    for _ in range(5):  # Количество потоков для перебора путей
        thread = threading.Thread(target=worker)
        thread.start()
        threads.append(thread)

    # Ожидание завершения всех потоков
    for thread in threads:
        thread.join()

def check_path(base_url, path):
    """Проверяет доступность пути на сервере."""
    try:
        full_url = f"{base_url}{path}"
        # Пример: отправка HTTP-запроса (можно использовать библиотеку requests)
        # Здесь используется упрощенный пример с сокетами
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((base_url.split("//")[1].split(":")[0], int(base_url.split(":")[2])))
        request = f"GET {path} HTTP/1.1\r\nHost: {base_url.split('//')[1].split(':')[0]}\r\nConnection: close\r\n\r\n"
        sock.sendall(request.encode())
        response = sock.recv(4096).decode()  # Увеличиваем размер буфера для получения большего ответа
        sock.close()

        # Извлекаем код ответа и содержимое
        response_lines = response.split("\r\n")
        response_code = None
        response_content = None

        if response_lines:
            # Первая строка содержит код ответа (например, "HTTP/1.1 200 OK")
            status_line = response_lines[0]
            if "HTTP" in status_line:
                response_code = status_line.split(" ")[1]  # Извлекаем код (например, 200, 404)
            # Остальные строки — это содержимое ответа
            response_content = "\r\n".join(response_lines[1:])

        if response_code == "200":
            return "accessible", response_code, response_content
        elif response_code == "404":
            return "not_found", response_code, response_content
        else:
            return "unknown", response_code, response_content
    except Exception as e:
        raise e

def run(target, start_port, end_port):
    """Запускает многопоточное сканирование TCP-портов с проверкой HTTP/HTTPS."""
    print(f"Scanning TCP ports on {target} from {start_port} to {end_port}...")
    port_queue = queue.Queue()
    results = {"open_ports": []}

    # Добавляем все порты в очередь
    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    def port_worker():
        while not port_queue.empty():
            port = port_queue.get()
            port_info = scan_port(target, port)
            if port_info:
                results["open_ports"].append(port_info)
            port_queue.task_done()

    # Ограничиваем количество потоков для сканирования портов
    threads = []
    for _ in range(MAX_THREADS):
        thread = threading.Thread(target=port_worker)
        thread.start()
        threads.append(thread)

    # Ожидание завершения всех потоков
    for thread in threads:
        thread.join()

    # Возвращаем результаты
    return results
