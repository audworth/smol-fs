from __future__ import annotations

import argparse
import os
import getpass

from smol.constants import DEFAULT_DISK_SIZE
from smol.disk import Disk, DiskError
from smol.scalls import FileSystem
from smol.shell import Shell


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="smolfs",
        description="Файловая система SMOL(inspired by FFS)",
    )
    parser.add_argument(
        "-p", "--path",
        required=True,
        help="Путь к виртуальному диску",
    )
    args = parser.parse_args(argv)

    disk_path = args.path

    if not os.path.exists(disk_path):
        print(f"Создаётся новый том файловой системы SMOL ({disk_path})...")
        admin_pwd = getpass.getpass("Введите пароль для пользователя root: ")
        if not admin_pwd:
            print("Пароль не может быть пустым.")
            return 1
        try:
            disk = Disk.create(disk_path, DEFAULT_DISK_SIZE)
        except DiskError as e:
            print("Произошла ошибка при создании тома: ", e)
            return 1

        fs = FileSystem(disk)
        fs.mkfs_init_system(admin_pwd, admin_username="root")
        fs.current_user = next((u for u in fs.list_users() if u.username == "root"), None)
        if fs.current_user is None:
            print("Произошла ошибка при авторизации в пользователя root")
            return 1
        shell = Shell(fs)
        try:
            shell.run()
        finally:
            disk.close()
        return 0

    try:
        disk = Disk.open(disk_path)
    except DiskError as e:
        print("Произошла ошибка при открытии диска: ", e)
        return 1

    fs = FileSystem(disk)
    fs.reload_users()

    print("Открыт виртуальный диск файловой системы SMOL.")
    print("Доступные пользователи для входа: ")
    for user in fs.list_users():
        print(f"  {user.username} (uid={user.uid})")

    for _ in range(3):
        username = input("Войти как: ").strip()
        password = getpass.getpass(f"Пароль для {username}: ")
        try:
            user = fs.authenticate(username, password)
            print(f"Выполнен вход для: {user.username} (uid={user.uid})")
            break
        except Exception as e:
            print(f"Произошла ошибка при входе: {e}")
    else:
        print("Слишком много некорректных попыток входа.")
        disk.close()
        return 1

    shell = Shell(fs)
    try:
        shell.run()
    finally:
        disk.close()
    return 0


if __name__ == "__main__":
    main()
