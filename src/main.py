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
import ctypes
import tempfile


class VirusRemover:
    def __init__(self):
        self.username = getpass.getuser()
        self.setup_logging()
        self.removed_items = []
        self.is_compiled = getattr(sys, 'frozen', False)

    def setup_logging(self):
        """Настройка системы логирования"""
        try:
            log_dir = f'C:/Users/{self.username}/AppData/Local/Temp'
            log_path = os.path.join(log_dir, 'virus_removal.log')

            logging.basicConfig(
                level=logging.INFO,
                format='%(asctime)s - %(levelname)s - %(message)s',
                handlers=[
                    logging.FileHandler(log_path, encoding='utf-8'),
                    logging.StreamHandler()
                ]
            )
            self.logger = logging.getLogger(__name__)
        except Exception as e:
            # Фолбэк логирование
            print(f"Ошибка настройки логгера: {e}")
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.INFO)

    def is_admin(self):
        """Проверка прав администратора через Windows API"""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False

    def run_as_admin(self):
        """Перезапуск с правами администратора"""
        if not self.is_admin():
            self.logger.info("Запрос прав администратора...")
            try:
                if self.is_compiled:
                    # Для скомпилированного exe
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, " ".join(sys.argv), None, 1
                    )
                else:
                    # Для Python скрипта
                    ctypes.windll.shell32.ShellExecuteW(
                        None, "runas", sys.executable, f'"{sys.argv[0]}"', None, 1
                    )
                sys.exit(0)
            except Exception as e:
                self.logger.error(f"Не удалось получить права администратора: {e}")
                return False
        return True

    def wait_for_process_completion(self, timeout=10):
        """Ожидание завершения процессов"""
        time.sleep(min(3, timeout))

    def calculate_file_hash(self, file_path):
        """Вычисление хеша файла для проверки"""
        try:
            hasher = hashlib.md5()
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            self.logger.debug(f"Ошибка вычисления хеша {file_path}: {e}")
            return None

    def kill_virus_processes(self):
        """Завершение процессов вируса с улучшенным поиском"""
        self.logger.info("Поиск и завершение процессов вируса...")

        virus_processes = [
            "NewLauncher.exe", "Uninstall NewLauncher.exe",
            "malware.exe", "suspicious.exe", "virus.exe"
        ]

        try:
            # Используем PowerShell для более надежного поиска
            ps_script = """
            Get-Process | Where-Object { 
                $_.ProcessName -like "*NewLauncher*" -or 
                $_.ProcessName -like "*malware*" -or
                $_.ProcessName -like "*suspicious*" -or
                $_.ProcessName -like "*virus*"
            } | Stop-Process -Force
            """

            subprocess.run([
                "powershell", "-ExecutionPolicy", "Bypass", "-Command", ps_script
            ], capture_output=True, timeout=30)

            self.wait_for_process_completion()
            self.logger.info("Завершение процессов вируса завершено")

        except subprocess.TimeoutExpired:
            self.logger.warning("Таймаут при завершении процессов")
        except Exception as e:
            self.logger.error(f"Ошибка при завершении процессов: {e}")

    def safe_remove_file(self, file_path):
        """Безопасное удаление файла"""
        try:
            if os.path.exists(file_path):
                # Снимаем атрибуты только для чтения
                try:
                    os.chmod(file_path, 0o777)
                except:
                    pass

                file_hash = self.calculate_file_hash(file_path)
                os.remove(file_path)
                self.removed_items.append(f"Файл: {file_path} (MD5: {file_hash})")
                self.logger.info(f"Удален файл: {file_path}")
                return True
        except Exception as e:
            self.logger.error(f"Не удалось удалить файл {file_path}: {e}")
        return False

    def safe_remove_directory(self, dir_path):
        """Безопасное удаление директории"""
        try:
            if os.path.exists(dir_path) and os.path.isdir(dir_path):
                # Рекурсивно меняем права доступа
                for root, dirs, files in os.walk(dir_path):
                    for file in files:
                        try:
                            os.chmod(os.path.join(root, file), 0o777)
                        except:
                            pass

                shutil.rmtree(dir_path)
                self.removed_items.append(f"Папка: {dir_path}")
                self.logger.info(f"Удалена папка: {dir_path}")
                return True
        except Exception as e:
            self.logger.error(f"Не удалось удалить папку {dir_path}: {e}")
        return False

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

        search_patterns = ["*NewLauncher*", "*malware*", "*suspicious*", "*.scr"]
        locations_to_search = [
            f"C:/Users/{self.username}/AppData/Local",
            f"C:/Users/{self.username}/AppData/Roaming",
            f"C:/Users/{self.username}/AppData/Local/Temp",
            "C:/Windows/Temp",
            f"C:/Users/{self.username}/Downloads",
            f"C:/Users/{self.username}/Desktop",
            f"C:/Users/{self.username}/Documents"
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
        removed_count = 0
        for path in set(paths_to_remove):
            try:
                if os.path.isfile(path):
                    if self.safe_remove_file(path):
                        removed_count += 1
                elif os.path.isdir(path):
                    if self.safe_remove_directory(path):
                        removed_count += 1
            except Exception as e:
                self.logger.error(f"Ошибка при обработке {path}: {e}")

        self.logger.info(f"Удалено объектов: {removed_count}")

    def safe_registry_delete(self, hive, key_path):
        """Безопасное удаление ключа реестра"""
        try:
            if hive == winreg.HKEY_CURRENT_USER:
                hive_name = "HKEY_CURRENT_USER"
            else:
                hive_name = "HKEY_LOCAL_MACHINE"

            with winreg.OpenKey(hive, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteKey(key, "")
            self.removed_items.append(f"Ключ реестра: {hive_name}\\{key_path}")
            self.logger.info(f"Удален ключ реестра: {hive_name}\\{key_path}")
            return True
        except FileNotFoundError:
            return False
        except Exception as e:
            self.logger.debug(f"Не удалось удалить ключ {key_path}: {e}")
            return False

    def remove_registry_entries(self):
        """Удаление записей реестра с расширенным поиском"""
        self.logger.info("Очистка реестра...")

        registry_keys = [
            r"SOFTWARE\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        ]

        hives = [
            (winreg.HKEY_CURRENT_USER, "HKEY_CURRENT_USER"),
            (winreg.HKEY_LOCAL_MACHINE, "HKEY_LOCAL_MACHINE")
        ]

        removed_count = 0
        for hive, hive_name in hives:
            for key_path in registry_keys:
                if self.safe_registry_delete(hive, key_path):
                    removed_count += 1

        self.logger.info(f"Удалено ключей реестра: {removed_count}")

    def clean_temp_files(self):
        """Очистка временных файлов"""
        self.logger.info("Очистка временных файлов...")

        temp_folders = [
            f"C:/Users/{self.username}/AppData/Local/Temp",
            f"C:/Windows/Temp",
            f"C:/Users/{self.username}/AppData/Local/Microsoft/Windows/INetCache",
            f"C:/Users/{self.username}/AppData/Local/Microsoft/Windows/INetCookies"
        ]

        cleaned_count = 0
        for temp_folder in temp_folders:
            if os.path.exists(temp_folder):
                try:
                    for item in os.listdir(temp_folder):
                        item_path = os.path.join(temp_folder, item)
                        try:
                            if os.path.isfile(item_path):
                                self.safe_remove_file(item_path)
                                cleaned_count += 1
                            elif os.path.isdir(item_path):
                                self.safe_remove_directory(item_path)
                                cleaned_count += 1
                        except Exception:
                            continue
                    self.logger.info(f"Очищена папка: {temp_folder}")
                except Exception as e:
                    self.logger.error(f"Ошибка при очистке {temp_folder}: {e}")

        self.logger.info(f"Очищено временных файлов: {cleaned_count}")

    def run_antivirus_scan(self):
        """Запуск встроенного антивируса"""
        self.logger.info("Запуск проверки Windows Defender...")
        try:
            result = subprocess.run([
                "powershell", "-ExecutionPolicy", "Bypass", "-Command",
                "Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue"
            ], capture_output=True, text=True, timeout=300)

            if result.returncode == 0:
                self.logger.info("Быстрая проверка завершена")
            else:
                self.logger.warning("Не удалось запустить проверку Windows Defender")

        except subprocess.TimeoutExpired:
            self.logger.warning("Быстрая проверка превысила время ожидания")
        except Exception as e:
            self.logger.error(f"Ошибка при запуске антивируса: {e}")

    def generate_report(self):
        """Генерация отчета о выполненных действиях"""
        try:
            report_dir = f'C:/Users/{self.username}/Desktop'
            if not os.path.exists(report_dir):
                report_dir = f'C:/Users/{self.username}/Documents'

            report_path = os.path.join(report_dir, 'virus_removal_report.txt')

            with open(report_path, 'w', encoding='utf-8') as f:
                f.write("ОТЧЕТ ОБ УДАЛЕНИИ ВИРУСА\n")
                f.write("=" * 50 + "\n")
                f.write(f"Дата: {time.ctime()}\n")
                f.write(f"Пользователь: {self.username}\n")
                f.write(f"Статус: УСПЕШНО\n")
                f.write("\nУДАЛЕННЫЕ ОБЪЕКТЫ:\n")

                for item in self.removed_items:
                    f.write(f"- {item}\n")

                if not self.removed_items:
                    f.write("- Не найдено объектов для удаления\n")

                f.write("\nРЕКОМЕНДАЦИИ:\n")
                f.write("1. Перезагрузите компьютер\n")
                f.write("2. Проверьте автозагрузку в Диспетчере задач\n")
                f.write("3. Убедитесь, что антивирус активен\n")
                f.write("4. Сохраните этот отчет для дальнейшего анализа\n")

            self.logger.info(f"Отчет сохранен: {report_path}")
            return report_path

        except Exception as e:
            self.logger.error(f"Ошибка создания отчета: {e}")
            return None

    def remove_virus(self):
        """Основная функция удаления вируса"""
        self.logger.info("Запуск процедуры удаления вируса...")

        if not self.run_as_admin():
            self.logger.error("Требуются права администратора!")
            input("Нажмите Enter для выхода...")
            return False

        try:
            self.logger.info("=== ЭТАП 1: Завершение процессов ===")
            self.kill_virus_processes()

            self.logger.info("=== ЭТАП 2: Удаление файлов ===")
            self.remove_virus_files()

            self.logger.info("=== ЭТАП 3: Очистка реестра ===")
            self.remove_registry_entries()

            self.logger.info("=== ЭТАП 4: Очистка временных файлов ===")
            self.clean_temp_files()

            self.logger.info("=== ЭТАП 5: Проверка антивирусом ===")
            self.run_antivirus_scan()

            self.logger.info("=== ЭТАП 6: Генерация отчета ===")
            report_path = self.generate_report()

            self.logger.info("Очистка завершена успешно!")
            return True

        except Exception as e:
            self.logger.error(f"Критическая ошибка: {e}")
            return False


def main():
    # Устанавливаем кодировку консоли для Windows
    if sys.platform == "win32":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleOutputCP(65001)  # UTF-8
        except:
            pass

    print("🛡️ Утилита удаления вируса - Улучшенная версия")
    print("=" * 50)

    try:
        remover = VirusRemover()

        if remover.remove_virus():
            print("\n✅ Очистка завершена успешно!")
            print("📄 Отчет сохранен на рабочем столе")
        else:
            print("\n❌ Произошли ошибки при очистке")
            print("📄 Проверьте файл журнала для деталей")

    except Exception as e:
        print(f"\n💥 Критическая ошибка: {e}")
        print("Попробуйте запустить программу от имени администратора")

    # Ожидание ввода только если запущено из exe
    if getattr(sys, 'frozen', False):
        print("\nНажмите Enter для выхода...")
        input()


if __name__ == "__main__":
    main()
