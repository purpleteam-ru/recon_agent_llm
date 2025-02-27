import importlib
import os
import sys
import json
from pathlib import Path
import psycopg2
from psycopg2 import sql
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

# Загрузка конфигурации из файла
def load_config():
    """Загружает конфигурацию из файла config.json."""
    try:
        with open("config.json", "r") as config_file:
            config = json.load(config_file)
        return config
    except Exception as e:
        print(f"Error loading config file: {e}")
        return {}

# Настройки подключения к PostgreSQL
DB_CONFIG = load_config()

def create_database():
    """Создает базу данных, если она не существует."""
    try:
        # Подключаемся к серверу PostgreSQL без указания базы данных
        conn = psycopg2.connect(
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"]
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cur = conn.cursor()

        # Проверяем, существует ли база данных
        cur.execute(
            sql.SQL("SELECT 1 FROM pg_database WHERE datname = {}").format(
                sql.Literal(DB_CONFIG["dbname"])
            )
        )
        if not cur.fetchone():
            # Создаем базу данных, если она не существует
            cur.execute(
                sql.SQL("CREATE DATABASE {}").format(
                    sql.Identifier(DB_CONFIG["dbname"])
                )
            )
            print(f"Database '{DB_CONFIG['dbname']}' created.")
        else:
            print(f"Database '{DB_CONFIG['dbname']}' already exists.")

        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error creating database: {e}")

def create_tables():
    """Создает таблицы, если они не существуют."""
    try:
        # Подключаемся к базе данных
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # Создаем таблицу scan_results
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id SERIAL PRIMARY KEY,
                target VARCHAR(255) NOT NULL,
                port INTEGER NOT NULL,
                services TEXT[],
                scan_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Создаем таблицу scan_paths
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scan_paths (
                id SERIAL PRIMARY KEY,
                scan_result_id INTEGER REFERENCES scan_results(id),
                path VARCHAR(255) NOT NULL,
                status VARCHAR(50) NOT NULL,
                response_code VARCHAR(50) NOT NULL,
                response_content TEXT NOT NULL

            )
        """)

        # Фиксируем изменения и закрываем соединение
        conn.commit()
        cur.close()
        conn.close()
        print("Tables created or already exist.")
    except Exception as e:
        print(f"Error creating tables: {e}")

def save_to_db(target, port, services, paths):
    """Сохраняет или обновляет результаты сканирования в базе данных."""
    try:
        # Подключаемся к базе данных
        conn = psycopg2.connect(**DB_CONFIG)
        cur = conn.cursor()

        # Проверяем, существует ли запись с таким IP и портом
        cur.execute(
            """
            SELECT id FROM scan_results
            WHERE target = %s AND port = %s
            """,
            (target, port)
        )
        existing_record = cur.fetchone()

        if existing_record:
            # Если запись существует, обновляем её
            scan_result_id = existing_record[0]
            cur.execute(
                """
                UPDATE scan_results
                SET services = %s, scan_time = CURRENT_TIMESTAMP
                WHERE id = %s
                """,
                (services, scan_result_id)
            )
            print(f"Updated existing record for {target}:{port}")
        else:
            # Если записи нет, добавляем новую
            cur.execute(
                """
                INSERT INTO scan_results (target, port, services)
                VALUES (%s, %s, %s)
                RETURNING id
                """,
                (target, port, services)
            )
            scan_result_id = cur.fetchone()[0]
            print(f"Added new record for {target}:{port}")

        # Удаляем старые пути для этого scan_result_id
        cur.execute(
            """
            DELETE FROM scan_paths
            WHERE scan_result_id = %s
            """,
            (scan_result_id,)
        )

        # Сохраняем новые пути
        for path in paths:
            cur.execute(
                """
                INSERT INTO scan_paths (scan_result_id, path, status, response_code, response_content)
                VALUES (%s, %s, %s, %s, %s)
                """,
                (scan_result_id, path["path"], path["status"], path.get("response_code"), path.get("response_content"))
            )

        # Фиксируем изменения и закрываем соединение
        conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error saving to database: {e}")

class PluginManager:
    def __init__(self, plugin_dir="plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = {}

    def load_plugins(self):
        """Автоматически загружает все плагины из указанной директории."""
        # Преобразуем путь к директории плагинов в абсолютный
        plugin_path = Path(self.plugin_dir).resolve()

        # Добавляем директорию плагинов в путь поиска модулей
        if str(plugin_path) not in sys.path:
            sys.path.append(str(plugin_path))

        # Ищем все Python-файлы в директории плагинов
        for filename in os.listdir(plugin_path):
            if filename.endswith(".py") and not filename.startswith("_"):
                plugin_name = filename[:-3]  # Убираем расширение .py
                try:
                    # Динамически загружаем модуль
                    module = importlib.import_module(plugin_name)
                    self.plugins[plugin_name] = module
                    print(f"Loaded plugin: {plugin_name}")
                except Exception as e:
                    print(f"Failed to load plugin {plugin_name}: {e}")

    def run_plugin(self, plugin_name, **kwargs):
        """Запускает указанный плагин."""
        if plugin_name in self.plugins:
            try:
                # Вызываем функцию `run` плагина
                results = self.plugins[plugin_name].run(**kwargs)
                # Сохраняем результаты в базу данных
                for result in results["open_ports"]:
                    save_to_db(kwargs["target"], result["port"], result["services"], result["paths"])
            except AttributeError:
                print(f"Plugin {plugin_name} does not have a 'run' function.")
        else:
            print(f"Plugin {plugin_name} not found.")

if __name__ == "__main__":
    # Создаем базу данных и таблицы
    create_database()
    create_tables()

    # Создаем менеджер плагинов и загружаем плагины
    plugin_manager = PluginManager()
    plugin_manager.load_plugins()

    # Пример использования плагина
    plugin_manager.run_plugin("tcp_http_https_scanner", target="192.168.8.1", start_port=1, end_port=65535)
