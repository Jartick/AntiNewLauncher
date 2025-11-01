import os
import shutil
import getpass
import winreg
import subprocess
import ctypes
import sys


def is_admin():
    """Проверяет, запущен ли скрипт с правами администратора"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


def run_as_admin():
    """Перезапускает скрипт с правами администратора"""
    print("Требуются права администратора для выполнения очистки...")
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit(0)


def remove_virus():
    username = getpass.getuser()

    # 1. Завершаем процессы вируса
    print("Завершаем процессы вируса...")
    processes = ["NewLauncher.exe", "Uninstall NewLauncher.exe"]
    for process in processes:
        try:
            subprocess.run(f"taskkill /f /im {process}", shell=True, capture_output=True)
        except Exception as e:
            print(f"Ошибка при завершении процесса {process}: {e}")

    # 2. Удаляем файлы вируса
    print("Удаляем файлы вируса...")
    paths_to_remove = [
        f"C:/Users/{username}/AppData/Local/Programs/NewLauncher",
        f"C:/Users/{username}/AppData/Local/Temp/NewLauncher",
        f"C:/Users/{username}/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/NewLauncher.lnk"
    ]

    for path in paths_to_remove:
        try:
            if os.path.isfile(path):
                os.remove(path)
                print(f"Удален файл: {path}")
            elif os.path.isdir(path):
                shutil.rmtree(path)
                print(f"Удалена папка: {path}")
        except Exception as e:
            print(f"Не удалось удалить {path}: {e}")

    # 3. Удаляем записи реестра
    print("Удаляем записи реестра...")
    registry_keys = [
        r"SOFTWARE\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7",
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\8cc7a8e8-ae96-5e65-9129-5a3f65e308e7"
    ]

    for key_path in registry_keys:
        try:
            # Пытаемся удалить из HKEY_CURRENT_USER
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
                print(f"Удален ключ реестра: HKEY_CURRENT_USER\\{key_path}")
        except Exception as e:
            print(f"Не удалось удалить ключ реестра HKEY_CURRENT_USER\\{key_path}: {e}")

        try:
            # Пытаемся удалить из HKEY_LOCAL_MACHINE (требует админских прав)
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_ALL_ACCESS) as key:
                winreg.DeleteKey(winreg.HKEY_LOCAL_MACHINE, key_path)
                print(f"Удален ключ реестра: HKEY_LOCAL_MACHINE\\{key_path}")
        except Exception as e:
            print(f"Не удалось удалить ключ реестра HKEY_LOCAL_MACHINE\\{key_path}: {e}")

    # 4. Дополнительная очистка временных файлов
    print("Очищаем временные файлы...")
    temp_folders = [
        f"C:/Users/{username}/AppData/Local/Temp",
        f"C:/Users/{username}/AppData/Local/Temp/NewLauncher",
        f"C:/Windows/Temp"
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
                        continue  # Пропускаем файлы, которые не удается удалить
            except Exception as e:
                print(f"Ошибка при очистке {temp_folder}: {e}")

    print("Очистка завершена!")

    # 5. Проверяем наличие антивируса
    print("\nРекомендации:")
    print("1. Запустите проверку антивирусом (Windows Defender)")
    print("2. Проверьте автозагрузку в диспетчере задач")
    print("3. Убедитесь, что вирус не восстановился")


if __name__ == "__main__":
    # Проверяем права администратора
    if not is_admin():
        run_as_admin()
    else:
        remove_virus()
        # Пауза чтобы пользователь увидел результаты
        input("\nНажмите Enter для выхода...")
