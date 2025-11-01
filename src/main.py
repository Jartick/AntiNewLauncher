import os
import shutil
import getpass
import winreg
import subprocess
import sys
import logging
import time
import hashlib
from pathlib import Path
from typing import List, Set


class VirusRemover:
    def __init__(self):
        self.username = getpass.getuser()
        self.setup_logging()
        self.removed_items = []

    def setup_logging(self):
        """Настройка системы логирования"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'C:/Users/{self.username}/virus_removal.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def run_as_admin(self):
        """Перезапуск с правами администратора"""
        if not self.is_admin():
            self.logger.info("Запрос прав администратора...")
            try:
                subprocess.run([
                    'powershell', 'Start-Process', 'python',
                    f'"{sys.argv[0]}"', '-Verb', 'runas'
                ], check=True)
                sys.exit(0)
            except subprocess.CalledProcessError:
                self.logger.error("Не удалось получить права администратора")
                return False
        return True

    def is_admin(self):
        """Проверка прав администратора"""
        try:
            return subprocess.run(
                ['net', 'session'],
                capture_output=True,
                check=True
            ).returncode == 0
        except (subprocess.CalledProcessError, FileNotFoundError):
            return False

    def calculate_file_hash(self, file_path):
        """Вычисление хеша файла для проверки"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception:
            return None

    def kill_virus_processes(self):
        """Завершение процессов вируса с улучшенным поиском"""
        self.logger.info("Поиск и завершение процессов вируса...")

        virus_processes = [
            "NewLauncher.exe", "Uninstall NewLauncher.exe",
            "malware.exe", "suspicious.exe"  # Добавьте другие имена
        ]

        try:
            # Получаем все процессы
            result = subprocess.run(
                ['tasklist', '/fo', 'csv'],
                capture_output=True,
                text=True,
                check=True
            )

            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.split('","')
                    if len(parts) >= 2:
                        process_name = parts[0].replace('"', '')
                        pid = parts[1].replace('"', '')

                        # Проверяем совпадение с известными именами вирусов
                        if any(virus_name.lower() in process_name.lower()
                               for virus_name in virus_processes):
                            try:
                                subprocess.run(
                                    f'taskkill /f /pid {pid}',
                                    shell=True,
                                    check=True
                                )
                                self.logger.info(f"Завершен процесс: {process_name} (PID: {pid})")
                                time.sleep(1)  # Даем время для завершения
                            except subprocess.CalledProcessError as e:
                                self.logger.warning(f"Не удалось завершить {process_name}: {e}")

        except Exception as e:
            self.logger.error(f"Ошибка при завершении процессов: {e}")

    def find_virus_files(self, directory, patterns):
        """Рекурсивный поиск файлов по шаблонам"""
        found_files = []
        try:
            path = Path(directory)
            for pattern in patterns:
                for file_path in path.rglob(pattern):
                    if file_path.exists():
                        found_files.append(str(file_path))
        except Exception as e:
            self.logger.debug(f"Ошибка поиска в {directory}: {e}")
        return found_files

    def remove_virus_files(self):
        """Удаление файлов вируса с расширенным поиском"""
        self.logger.info("Поиск и удаление файлов вируса...")

        search_patterns = ["*NewLauncher*", "*malware*", "*.tmp", "*.scr"]
        locations_to_search = [
            f"C:/Users/{self.username}/AppData/Local",
            f"C:/Users/{self.username}/AppData/Roaming",
            f"C:/Users/{self.username}/AppData/Local/Temp",
            "C:/Windows/Temp",
            f"C:/Users/{self.username}/Downloads",
            f"C:/Users/{self.username}/Desktop"
        ]

        # Стандартные пути для удаления
        paths_to_remove = [
            f"C:/Users/{self.username}/AppData/Local/Programs/NewLauncher",
            f"C:/Users/{self.username}/AppData/Local/Temp/NewLauncher",
            f"C:/Users/{self.username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/NewLauncher.lnk"
        ]

        # Расширенный поиск файлов
        for location in locations_to_search:
            if os.path.exists(location):
                found_files = self.find_virus_files(location, search_patterns)
                paths_to_remove.extend(found_files)

        # Удаление найденных файлов и папок
        for path in set(paths_to_remove):  # set для удаления дубликатов
            try:
                if os.path.isfile(path):
                    file_hash = self.calculate_file_hash(path)
                    os.remove(path)
                    self.removed_items.append(f"Файл: {path} (MD5: {file_hash})")
                    self.logger.info(f"Удален файл: {path}")

                elif os.path.isdir(path):
                    shutil.rmtree(path)
                    self.removed_items.append(f"Папка: {path}")
                    self.logger.info(f"Удалена папка: {path}")

            except Exception as e:
                self.logger.error(f"Не удалось удалить {path}: {e}")

    def remove_registry_entries(self):
        """Удаление записей реестра с расширенным поиском"""
        self.logger.info("Очистка реестра...")

        registry_keys = [
            # Основные ключи
            r"SOFTWARE\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7",

            # Автозагрузка
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]

        # Проверяем разные разделы реестра
        hives = [
            (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
            (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
        ]

        for hive, hive_name in hives:
            for key_path in registry_keys:
                try:
                    winreg.DeleteKey(hive, key_path)
                    self.removed_items.append(f"Ключ реестра: {hive_name}\\{key_path}")
                    self.logger.info(f"Удален ключ реестра: {hive_name}\\{key_path}")
                except Exception as e:
                    self.logger.debug(f"Не удалось удалить {hive_name}\\{key_path}: {e}")

    def clean_temp_files(self):
        """Очистка временных файлов"""
        self.logger.info("Очистка временных файлов...")

        temp_folders = [
            f"C:/Users/{self.username}/AppData/Local/Temp",
            f"C:/Windows/Temp",
            f"C:/Users/{self.username}/AppData/Local/Microsoft/Windows/INetCache",
            f"C:/Users/{self.username}/AppData/Local/Microsoft/Windows/INetCookies"
        ]

        for temp_folder in temp_folders:
            if os.path.exists(temp_folder):
                try:
                    for item in os.listdir(temp_folder):
                        item_path = os.path.join(temp_folder, item)
                        try:
                            if os.path.isfile(item_path):
                                os.remove(item_path)
                            elif os.path.isdir(item_path):
                                shutil.rmtree(item_path)
                        except Exception:
                            continue
                    self.logger.info(f"Очищена папка: {temp_folder}")
                except Exception as e:
                    self.logger.error(f"Ошибка при очистке {temp_folder}: {e}")

    def run_antivirus_scan(self):
        """Запуск встроенного антивируса"""
        self.logger.info("Запуск проверки Windows Defender...")
        try:
            subprocess.run([
                "powershell", "Start-MpScan", "-ScanType", "QuickScan"
            ], check=True, timeout=300)  # 5 минут таймаут
            self.logger.info("Быстрая проверка завершена")
        except subprocess.TimeoutExpired:
            self.logger.warning("Быстрая проверка превысила время ожидания")
        except Exception as e:
            self.logger.error(f"Ошибка при запуске антивируса: {e}")

    def generate_report(self):
        """Генерация отчета о выполненных действиях"""
        report_path = f"C:/Users/{self.username}/virus_removal_report.txt"

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("ОТЧЕТ ОБ УДАЛЕНИИ ВИРУСА\n")
            f.write("=" * 50 + "\n")
            f.write(f"Дата: {time.ctime()}\n")
            f.write(f"Пользователь: {self.username}\n")
            f.write("\nУДАЛЕННЫЕ ОБЪЕКТЫ:\n")

            for item in self.removed_items:
                f.write(f"- {item}\n")

            f.write("\nРЕКОМЕНДАЦИИ:\n")
            f.write("1. Перезагрузите компьютер\n")
            f.write("2. Проверьте автозагрузку в Диспетчере задач\n")
            f.write("3. Убедитесь, что антивирус активен\n")
            f.write("4. Сохраните этот отчет для дальнейшего анализа\n")

        self.logger.info(f"Отчет сохранен: {report_path}")
        return report_path

    def remove_virus(self):
        """Основная функция удаления вируса"""
        self.logger.info("Запуск процедуры удаления вируса...")

        if not self.run_as_admin():
            self.logger.error("Требуются права администратора!")
            return False

        try:
            self.kill_virus_processes()
            time.sleep(2)  # Пауза между этапами

            self.remove_virus_files()
            time.sleep(1)

            self.remove_registry_entries()
            time.sleep(1)

            self.clean_temp_files()
            time.sleep(1)

            self.run_antivirus_scan()

            report_path = self.generate_report()

            self.logger.info("Очистка завершена успешно!")
            self.logger.info(f"Отчет сохранен: {report_path}")

            return True

        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}")
            return False


def main():
    print("Утилита удаления вируса - Улучшенная версия")
    print("=" * 50)

    remover = VirusRemover()

    if remover.remove_virus():
        print("\n✅ Очистка завершена успешно!")
        print("📄 Отчет сохранен в файле журнала")
    else:
        print("\n❌ Произошли ошибки при очистке")
        print("📄 Проверьте файл журнала для деталей")

    input("\nНажмите Enter для выхода...")


if __name__ == "__main__":
    main()