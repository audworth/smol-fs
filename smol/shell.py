from __future__ import annotations

import getpass
import shlex
from datetime import datetime
from typing import List

from smol.scalls import (
    FileSystem,
    FsError,
    FsNotFoundError,
    FsExistsError,
    FsPermissionError,
)

RESET = "\033[0m"
BOLD = "\033[1m"
BLUE = "\033[34m"
CYAN = "\033[36m"


def _mode_to_string(mode: int):
    result = ""
    for shift in (6, 3, 0):
        bits = (mode >> shift) & 0b111
        result += "r" if bits & 0b100 else "-"
        result += "w" if bits & 0b010 else "-"
        result += "x" if bits & 0b001 else "-"
    return result


def _file_type_char(mode: int):
    if (mode & 0xF000) == 0x4000:
        return "d"
    return "-"


def _format_ts(ts: int):
    if not ts:
        return "-"
    dt = datetime.fromtimestamp(ts)
    return dt.strftime("%d.%m.%Y %H:%M:%S")


class Shell:
    def __init__(self, fs: FileSystem):
        self.fs = fs

    def _prompt(self):
        user = self.fs.current_user.username if self.fs.current_user else "?"
        return f"{user}@smol:/ $ "

    def run(self):
        print("SMOL-оболочка. Наберите 'help' для списка команд.")
        while True:
            try:
                line = input(self._prompt())
            except EOFError:
                print()
                break
            line = line.strip()
            if not line:
                continue
            try:
                args = shlex.split(line)
            except ValueError as e:
                print(f"Ошибка разбора строки: {e}")
                continue
            cmd = args[0]
            try:
                if cmd in ("exit", "quit"):
                    break
                elif cmd == "help":
                    self.cmd_help(args[1:])
                elif cmd == "ls":
                    self.cmd_ls(args[1:])
                elif cmd == "stat":
                    self.cmd_stat(args[1:])
                elif cmd == "rm":
                    self.cmd_rm(args[1:])
                elif cmd == "touch":
                    self.cmd_touch(args[1:])
                elif cmd == "chmod":
                    self.cmd_chmod(args[1:])
                elif cmd == "chown":
                    self.cmd_chown(args[1:])
                elif cmd == "ch":
                    self.cmd_ch(args[1:])
                elif cmd == "cat":
                    self.cmd_cat(args[1:])
                elif cmd == "cp":
                    self.cmd_cp(args[1:])
                elif cmd == "mv":
                    self.cmd_mv(args[1:])
                elif cmd == "users":
                    self.cmd_users(args[1:])
                elif cmd == "groups":
                    self.cmd_groups(args[1:])
                elif cmd == "whoami":
                    self.cmd_whoami(args[1:])
                elif cmd == "su":
                    self.cmd_su(args[1:])
                elif cmd == "useradd":
                    self.cmd_useradd(args[1:])
                elif cmd == "userdel":
                    self.cmd_userdel(args[1:])
                elif cmd == "groupadd":
                    self.cmd_groupadd(args[1:])
                elif cmd == "groupdel":
                    self.cmd_groupdel(args[1:])
                elif cmd == "usermod":
                    self.cmd_usermod(args[1:])
                elif cmd == "userdelgroup":
                    self.cmd_userdelgroup(args[1:])
                elif cmd == "echo":
                    self.cmd_echo(args[1:])
                elif cmd == "debugfs":
                    self.cmd_debugfs(args[1:])
                else:
                    print(f"Неизвестная команда: {cmd}")
            except FsPermissionError as e:
                print(f"Ошибка прав доступа: {e}")
            except FsNotFoundError as e:
                print(f"Не найдено: {e}")
            except FsExistsError as e:
                print(f"Уже существует: {e}")
            except FsError as e:
                print(f"Ошибка файловой системы: {e}")
            except Exception as e:
                print(f"Внутренняя ошибка: {e}")

    def cmd_help(self, args: List[str]):
        print("Доступные команды:")
        print("  help                            - показать эту справку")
        print("  exit, quit                      - выйти из оболочки")
        print("  ls [-a]                         - показать список файлов")
        print("  stat <путь>                     - подробная информация об объекте")
        print("  cat <путь>                      - вывести содержимое файла")
        print("  echo [строка]                   - вывести строку")
        print("  echo [строка] >> <файл>         - дописать строку в файл")
        print("  touch <путь>                    - создать пустой файл или обновить время")
        print("  rm <путь>                       - удалить файл")
        print("  cp <источник> <цель>            - копировать файл")
        print("  mv <источник> <цель>            - переименовать/переместить файл")
        print("  chmod <режим> <путь>            - изменить права (восьмерично, напр. 644)")
        print("  chown <путь> <пользователь>     - сменить владельца (только root)")
        print("  ch <путь> <группа>              - сменить группу файла (только root)")
        print("  users                           - список пользователей")
        print("  groups                          - список групп")
        print("  useradd <логин>                 - создать пользователя (только root)")
        print("  userdel <логин>                 - удалить пользователя (только root)")
        print("  groupadd <группа>               - создать группу (только root)")
        print("  groupdel <группа>               - удалить группу (только root)")
        print("  usermod <логин> <группа>        - добавить пользователя в группу (только root)")
        print("  userdelgroup <логин> <группа>   - удалить пользователя из группы (только root)")
        print("  su <пользователь>               - переключиться на другого пользователя")
        print("  whoami                          - показать текущего пользователя")
        print("  debugfs                         - показать оффсеты областей тома (для hex-редактора)")

    def cmd_ls(self, args: List[str]):
        all_files = False
        if args and args[0] == "-a":
            all_files = True
        entries = self.fs.ls(all_files=all_files)
        if not entries:
            print("Файлов нет.")
            return
        header = BOLD + "ТИП  ПРАВА       Владелец:Группа        РАЗМЕР      ИМЯ" + RESET
        print(header)
        for name, ino, inode in entries:
            ftype = _file_type_char(inode.mode)
            perms = _mode_to_string(inode.mode & 0o777)
            owner = self.fs.user_name(inode.owner_uid)
            group = self.fs.group_name(inode.group_gid)
            owner_group = f"{owner}:{group}"
            size = inode.size_bytes
            display_name = name
            if name.startswith("."):
                display_name = CYAN + name + RESET
            elif ftype == "d":
                display_name = BLUE + name + RESET
            print(f"{ftype}   {perms}  {owner_group:22s} {size:10d}  {display_name}")

    def cmd_stat(self, args: List[str]):
        if not args:
            print("Использование: stat <путь>")
            return
        path = args[0]
        ino, inode = self.fs.stat(path)
        inode_offset = self.fs.inode_offset_bytes(ino)
        mode_oct = inode.mode & 0o777
        mode_str = _mode_to_string(mode_oct)
        ftype = "каталог" if (inode.mode & 0xF000) == 0x4000 else "файл"
        print(BOLD + f"Информация об объекте «{path}»" + RESET)
        print(f"Инод:           {ino}")
        print(f"Тип:            {ftype}")
        print(f"Права:          {mode_oct:04o} ({mode_str})")
        print(f"Владелец:       uid={inode.owner_uid} gid={inode.group_gid}")
        print(f"Размер:         {inode.size_bytes} байт")
        print(f"Число ссылок:   {inode.nlink}")
        print(f"Время создания: {_format_ts(inode.ctime)}")
        print(f"Время изменения:{_format_ts(inode.mtime)}")
        print(f"Смещение inode: {inode_offset} (0x{inode_offset:08x})")
        data_off = self.fs.data_offset_bytes(inode)
        if data_off is None:
            print("Смещение данных:—")
        else:
            print(f"Смещение данных:{data_off} (0x{data_off:08x})")
        direct_blocks = [b for b in inode.direct_blocks if b]
        if direct_blocks:
            parts = []
            for b in direct_blocks:
                off = self.fs.block_offset_bytes(b)
                parts.append(f"{b}@{off} (0x{off:08x})")
            print("Прямые блоки:   " + ", ".join(parts))
        if inode.indirect_block:
            off = self.fs.block_offset_bytes(inode.indirect_block)
            print(f"Косвенный блок: {inode.indirect_block}@{off} (0x{off:08x})")
        if inode.tail_block:
            base_off = self.fs.block_offset_bytes(inode.tail_block)
            tail_off = self.fs.tail_offset_bytes(inode.tail_block, inode.tail_start_frag)
            print(
                f"Хвост:          блок={inode.tail_block}, "
                f"фрагмент={inode.tail_start_frag}, кол-во={inode.tail_frag_count}, "
                f"смещение={tail_off} (0x{tail_off:08x}, base 0x{base_off:08x})"
            )

    def cmd_rm(self, args: List[str]):
        if not args:
            print("Использование: rm <путь>")
            return
        self.fs.remove(args[0])

    def cmd_touch(self, args: List[str]):
        if not args:
            print("Использование: touch <путь>")
            return
        self.fs.touch(args[0])

    def cmd_chmod(self, args: List[str]):
        if len(args) != 2:
            print("Использование: chmod <режим(восьмеричный)> <путь>")
            return
        mode_str, path = args
        try:
            mode = int(mode_str, 8)
        except ValueError:
            print("Режим должен быть в восьмеричном виде, пример: 644")
            return
        self.fs.chmod(path, mode)

    def cmd_chown(self, args: List[str]):
        if len(args) != 2:
            print("Использование: chown <путь> <пользователь>")
            return
        path, username = args
        users = self.fs.list_users()
        user = next((u for u in users if u.username == username), None)
        if not user:
            print("Пользователь не найден:", username)
            return
        self.fs.chown(path, user)

    def cmd_ch(self, args: List[str]):
        if len(args) != 2:
            print("Использование: ch <путь> <группа>")
            return
        path, group_name = args
        self.fs.chgrp(path, group_name)

    def cmd_cat(self, args: List[str]):
        if not args:
            print("Использование: cat <путь>")
            return
        text = self.fs.read_text(args[0])
        if text:
            print(text, end="")

    def cmd_echo(self, args: List[str]):
        if not args:
            print()
            return
        redir_token = None
        if ">>" in args:
            redir_token = ">>"
        elif ">" in args:
            redir_token = ">"

        if redir_token:
            idx = args.index(redir_token)
            text = " ".join(args[:idx])
            if idx + 1 >= len(args):
                print("Использование: echo [строка] >> <файл>")
                return
            path = args[idx + 1]
            # Всегда добавляем в конец файла, не перезаписывая существующее содержимое
            self.fs.append_text(path, text + "\n")
        else:
            text = " ".join(args)
            print(text)

    def cmd_cp(self, args: List[str]):
        if len(args) != 2:
            print("Использование: cp <источник> <цель>")
            return
        self.fs.copy(args[0], args[1])

    def cmd_mv(self, args: List[str]):
        if len(args) != 2:
            print("Использование: mv <источник> <цель>")
            return
        self.fs.move(args[0], args[1])

    def cmd_users(self, args: List[str]):
        users = self.fs.list_users()
        if not users:
            print("Пользователи не найдены.")
            return
        print(BOLD + "UID  ЛОГИН       ГРУППЫ" + RESET)
        for u in users:
            groups = ",".join(self.fs.group_name(g) for g in sorted(u.groups))
            print(f"{u.uid:3d}  {u.username:10s}  {groups}")

    def cmd_groups(self, args: List[str]):
        groups = self.fs.list_groups()
        if not groups:
            print("Группы не найдены.")
            return
        print(BOLD + "GID  НАЗВАНИЕ" + RESET)
        for gid, name in groups:
            print(f"{gid:3d}  {name}")

    def cmd_whoami(self, args: List[str]):
        if not self.fs.current_user:
            print("?")
        else:
            user = self.fs.current_user
            groups = [self.fs.group_name(g) for g in sorted(user.groups)]
            print(BOLD + "ПОЛЬЗОВАТЕЛЬ   ГРУППЫ" + RESET)
            print(f"{user.username:12s} {','.join(groups)}")

    def cmd_su(self, args: List[str]):
        if not args:
            print("Использование: su <пользователь>")
            return
        username = args[0]
        pwd = getpass.getpass(f"Пароль пользователя {username}: ")
        try:
            user = self.fs.authenticate(username, pwd)
            print(f"Текущий пользователь: {user.username} (uid={user.uid})")
        except FsError as e:
            print(f"Не удалось переключить пользователя: {e}")

    def cmd_useradd(self, args: List[str]):
        if len(args) != 1:
            print("Использование: useradd <логин>")
            return
        username = args[0]
        pwd1 = getpass.getpass("Пароль для нового пользователя: ")
        pwd2 = getpass.getpass("Повторите пароль: ")
        if pwd1 != pwd2:
            print("Пароли не совпадают.")
            return
        if not pwd1:
            print("Пароль не может быть пустым.")
            return
        self.fs.add_user(username, pwd1)
        print(f"Пользователь {username} создан.")

    def cmd_userdel(self, args: List[str]):
        if len(args) != 1:
            print("Использование: userdel <логин>")
            return
        username = args[0]
        self.fs.del_user(username)
        print(f"Пользователь {username} удалён.")

    def cmd_groupadd(self, args: List[str]):
        if len(args) != 1:
            print("Использование: groupadd <группа>")
            return
        group_name = args[0]
        self.fs.add_group(group_name)
        print(f"Группа {group_name} создана.")

    def cmd_groupdel(self, args: List[str]):
        if len(args) != 1:
            print("Использование: groupdel <группа>")
            return
        group_name = args[0]
        self.fs.del_group(group_name)
        print(f"Группа {group_name} удалена.")

    def cmd_usermod(self, args: List[str]):
        if len(args) != 2:
            print("Использование: usermod <логин> <группа>")
            return
        username, group_name = args
        self.fs.add_user_to_group(username, group_name)
        print(f"Пользователь {username} добавлен в группу {group_name}.")

    def cmd_userdelgroup(self, args: List[str]):
        if len(args) != 2:
            print("Использование: userdelgroup <логин> <группа>")
            return
        username, group_name = args
        self.fs.remove_user_from_group(username, group_name)
        print(f"Пользователь {username} удалён из группы {group_name}.")

    def cmd_debugfs(self, args: List[str]):
        layouts = self.fs.debug_layout()
        if not layouts:
            print("Нет групп цилиндров.")
            return
        for layout in layouts:
            print(BOLD + f"Группа цилиндров {layout['cg_id']}" + RESET)
            print(f"  Стартовый блок:       {layout['cg_start_block']}")
            print(f"  Количество блоков:    {layout['cg_size_blocks']}")
            print(
                f"  Суперблок:            блок {layout['superblock_block']}, "
                f"смещение {layout['superblock_offset']} (0x{layout['superblock_offset']:08x})"
            )
            print(
                f"  Заголовок CG:         блок {layout['cg_header_block']}, "
                f"смещение {layout['cg_header_offset']} (0x{layout['cg_header_offset']:08x})"
            )
            if layout["frag_bitmap_block"] is not None:
                print(
                    f"  Битовая карта фрагм.: блок {layout['frag_bitmap_block']}, "
                    f"{layout['frag_bitmap_blocks']} блок(ов), "
                    f"смещение {layout['frag_bitmap_offset']} (0x{layout['frag_bitmap_offset']:08x})"
                )
            else:
                print("  Битовая карта фрагм.: нет")
            print(
                f"  Битовая карта инодов: блок {layout['inode_bitmap_block']}, "
                f"{layout['inode_bitmap_blocks']} блок(ов), "
                f"смещение {layout['inode_bitmap_offset']} (0x{layout['inode_bitmap_offset']:08x})"
            )
            print(
                f"  Таблица инодов:       блок {layout['inode_table_block']}, "
                f"{layout['inode_table_blocks']} блок(ов), "
                f"смещение {layout['inode_table_offset']} (0x{layout['inode_table_offset']:08x})"
            )
            print(
                f"  Данные файлов:        блок {layout['data_block_start']}, "
                f"{layout['data_block_count']} блок(ов), "
                f"смещение {layout['data_offset']} (0x{layout['data_offset']:08x})"
            )
