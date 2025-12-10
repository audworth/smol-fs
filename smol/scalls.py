from __future__ import annotations

import hashlib
import time
import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from smol.constants import (
    FTYPE_MASK,
    FTYPE_REG,
    FTYPE_DIR,
    FTYPE_SYSTEM,
    DEFAULT_FILE_PERMS,
    DEFAULT_DIR_PERMS,
    DEFAULT_SYS_PERMS,
    NAME_ROOT,
    NAME_ROOT_ALIAS,
    NAME_USERS,
    NAME_GROUPS,
    NAME_USER_GROUPS,
    NAME_NAME_INDEX,
)
from smol.disk import Disk, Inode, DiskError


class FsError(Exception):
    pass


class FsPermissionError(FsError):
    pass


class FsNotFoundError(FsError):
    pass


class FsExistsError(FsError):
    pass


@dataclass
class User:
    uid: int
    username: str
    primary_gid: int
    groups: Set[int]

    @property
    def is_root(self):
        return self.uid == 0


class FileSystem:
    def __init__(self, disk: Disk):
        self.disk = disk
        self.sb = disk.sb
        self.current_user: Optional[User] = None
        self._user_by_name: Dict[str, User] = {}
        self._user_by_uid: Dict[int, User] = {}
        self._group_names: Dict[int, str] = {}
        self._name_cache: Optional[Dict[str, int]] = None

    def _has_perm(self, inode: Inode, mask: int):
        if self.current_user is None:
            return False
        if self.current_user.is_root:
            return True
        mode = inode.mode & 0o777
        if self.current_user.uid == inode.owner_uid:
            shift = 6
        elif inode.group_gid in self.current_user.groups:
            shift = 3
        else:
            shift = 0
        perm_bits = (mode >> shift) & 0b111
        return (perm_bits & mask) == mask

    def _require_perm(self, inode: Inode, mask: int, action: str):
        if not self._has_perm(inode, mask):
            raise FsPermissionError(f"Недостаточно прав для операции {action}")

    def _ensure_root(self):
        if not self.current_user or not self.current_user.is_root:
            raise FsPermissionError("Эту операцию может выполнять только root")

    def _load_name_index(self):
        if self._name_cache is not None:
            return dict(self._name_cache)
        ino = self.sb.name_inode
        if ino is None or ino < 0:
            self._name_cache = {}
            return {}
        raw = self.disk.read_file(ino)
        mapping: Dict[str, int] = {}
        if raw:
            text = raw.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    inode_str, name = line.split(":", 1)
                    inode_no = int(inode_str)
                    mapping[name] = inode_no
                except ValueError:
                    continue
        changed = False
        if NAME_ROOT in mapping:
            root_ino = mapping.pop(NAME_ROOT)
            if NAME_ROOT_ALIAS not in mapping:
                mapping[NAME_ROOT_ALIAS] = root_ino
            changed = True
        if changed:
            self._store_name_index(mapping)
        self._name_cache = dict(mapping)
        return mapping

    def _store_name_index(self, mapping: Dict[str, int]):
        self._name_cache = dict(mapping)
        lines = []
        for name, ino in sorted(mapping.items(), key=lambda kv: kv[0]):
            lines.append(f"{ino}:{name}")
        data = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
        self.disk.write_file(self.sb.name_inode, data)

    def mkfs_init_system(self, admin_password: str, admin_username: str = "admin"):
        name_ino = self.disk.alloc_inode()
        name_inode = Inode.empty()
        name_inode.mode = FTYPE_REG | FTYPE_SYSTEM | DEFAULT_SYS_PERMS
        name_inode.owner_uid = 0
        name_inode.group_gid = 0
        name_inode.nlink = 1
        self.disk.write_inode(name_ino, name_inode)
        self.disk.write_file(name_ino, b"")
        self.sb.name_inode = name_ino

        root_ino = self.disk.alloc_inode()
        root_inode = Inode.empty()
        root_inode.mode = FTYPE_DIR | FTYPE_SYSTEM | DEFAULT_DIR_PERMS
        root_inode.owner_uid = 0
        root_inode.group_gid = 0
        root_inode.nlink = 1
        self.disk.write_inode(root_ino, root_inode)

        users_ino = self.disk.alloc_inode()
        users_inode = Inode.empty()
        users_inode.mode = FTYPE_REG | FTYPE_SYSTEM | DEFAULT_SYS_PERMS
        users_inode.owner_uid = 0
        users_inode.group_gid = 0
        users_inode.nlink = 1
        self.disk.write_inode(users_ino, users_inode)

        groups_ino = self.disk.alloc_inode()
        groups_inode = Inode.empty()
        groups_inode.mode = FTYPE_REG | FTYPE_SYSTEM | DEFAULT_SYS_PERMS
        groups_inode.owner_uid = 0
        groups_inode.group_gid = 0
        groups_inode.nlink = 1
        self.disk.write_inode(groups_ino, groups_inode)

        ug_ino = self.disk.alloc_inode()
        ug_inode = Inode.empty()
        ug_inode.mode = FTYPE_REG | FTYPE_SYSTEM | DEFAULT_SYS_PERMS
        ug_inode.owner_uid = 0
        ug_inode.group_gid = 0
        ug_inode.nlink = 1
        self.disk.write_inode(ug_ino, ug_inode)

        self.sb.users_inode = users_ino
        self.sb.groups_inode = groups_ino
        self.sb.user_groups_inode = ug_ino
        self.disk._write_superblock()

        mapping = {
            NAME_ROOT_ALIAS: root_ino,
            NAME_USERS: users_ino,
            NAME_GROUPS: groups_ino,
            NAME_USER_GROUPS: ug_ino,
            NAME_NAME_INDEX: name_ino,
        }
        self._store_name_index(mapping)

        admin_uid = 0
        root_gid = 0
        pwd_hash = hashlib.sha256(admin_password.encode("utf-8")).hexdigest()
        users_text = f"{admin_uid}:{admin_username}:{pwd_hash}\n"
        groups_text = f"{root_gid}:root\n"
        ug_text = f"{admin_uid}:{root_gid}\n"

        self.disk.write_file(users_ino, users_text.encode("utf-8"))
        self.disk.write_file(groups_ino, groups_text.encode("utf-8"))
        self.disk.write_file(ug_ino, ug_text.encode("utf-8"))

        self._name_cache = None
        self.reload_users()

    def reload_users(self):
        self._user_by_name.clear()
        self._user_by_uid.clear()
        self._group_names.clear()

        if self.sb.groups_inode:
            raw = self.disk.read_file(self.sb.groups_inode)
            if raw:
                text = raw.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        gid_str, gname = line.split(":", 1)
                        gid = int(gid_str)
                        self._group_names[gid] = gname
                    except ValueError:
                        continue

        user_groups: Dict[int, Set[int]] = {}
        if self.sb.user_groups_inode:
            raw = self.disk.read_file(self.sb.user_groups_inode)
            if raw:
                text = raw.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        uid_str, gid_str = line.split(":", 1)
                        uid = int(uid_str)
                        gid = int(gid_str)
                        user_groups.setdefault(uid, set()).add(gid)
                    except ValueError:
                        continue

        if self.sb.users_inode:
            raw = self.disk.read_file(self.sb.users_inode)
            if raw:
                text = raw.decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        uid_str, uname, pwd_hash = line.split(":", 2)
                        uid = int(uid_str)
                    except ValueError:
                        continue
                    groups = user_groups.get(uid, set())
                    primary_gid = next(iter(groups)) if groups else 0
                    user = User(
                        uid=uid,
                        username=uname,
                        primary_gid=primary_gid,
                        groups=set(groups or {primary_gid}),
                    )
                    self._user_by_name[uname] = user
                    self._user_by_uid[uid] = user
        if self.current_user and self.current_user.uid in self._user_by_uid:
            self.current_user = self._user_by_uid[self.current_user.uid]

    def authenticate(self, username: str, password: str):
        if not self._user_by_name:
            self.reload_users()
        user = self._user_by_name.get(username)
        if not user:
            raise FsError("Пользователь не найден")
        raw = self.disk.read_file(self.sb.users_inode)
        if not raw:
            raise FsError("Файл пользователей пуст")
        text = raw.decode("utf-8", errors="ignore")
        pwd_hash = hashlib.sha256(password.encode("utf-8")).hexdigest()
        found_hash: Optional[str] = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                uid_str, uname, hsh = line.split(":", 2)
            except ValueError:
                continue
            if uname == username:
                found_hash = hsh
                break
        if found_hash is None or found_hash != pwd_hash:
            raise FsError("Неверный пароль")
        self.current_user = user
        return user

    def list_users(self):
        if not self._user_by_name:
            self.reload_users()
        return sorted(self._user_by_name.values(), key=lambda u: u.uid)

    def list_groups(self):
        if not self._group_names:
            self.reload_users()
        return sorted(self._group_names.items(), key=lambda kv: kv[0])

    def user_name(self, uid: int):
        if not self._user_by_uid:
            self.reload_users()
        user = self._user_by_uid.get(uid)
        return user.username if user else str(uid)

    def group_name(self, gid: int):
        if not self._group_names:
            self.reload_users()
        return self._group_names.get(gid, str(gid))

    def _normalize_path(self, path: str):
        path = path.strip()
        if path == "" or path == "/":
            return NAME_ROOT
        if path.startswith("/"):
            path = path[1:]
        return path

    def _reassign_user_files(self, old_uid: int, new_uid: int, new_gid: int):
        mapping = self._load_name_index()
        for ino in mapping.values():
            inode = self.disk.read_inode(ino)
            if inode.owner_uid == old_uid:
                inode.owner_uid = new_uid
                inode.group_gid = new_gid
                self.disk.write_inode(ino, inode)

    def _reassign_group_files(self, old_gid: int, new_gid: int):
        mapping = self._load_name_index()
        for ino in mapping.values():
            inode = self.disk.read_inode(ino)
            if inode.group_gid == old_gid:
                inode.group_gid = new_gid
                self.disk.write_inode(ino, inode)

    def inode_offset_bytes(self, inode_no: int):
        _, _, block_no, byte_offset = self.disk._inode_location(inode_no)
        return block_no * self.sb.block_size + byte_offset

    def block_offset_bytes(self, block_no: int):
        return block_no * self.sb.block_size

    def tail_offset_bytes(self, block_no: int, start_frag: int):
        return self.block_offset_bytes(block_no) + start_frag * self.sb.fragment_size

    def data_region_offset_bytes(self):
        if not self.disk.cgs:
            return 0
        cg = self.disk.cgs[0]
        return (cg.global_start_block + cg.data_segment_offset) * self.sb.block_size

    def data_offset_bytes(self, inode: Inode):
        if inode.size_bytes <= 0:
            return None
        for blk in inode.direct_blocks:
            if blk:
                return self.block_offset_bytes(blk)
        if inode.indirect_block:
            raw = self.disk._read_block(inode.indirect_block)
            ptrs = struct.unpack("<%dI" % (self.sb.block_size // 4), raw)
            for p in ptrs:
                if p:
                    return self.block_offset_bytes(p)
        if inode.tail_block:
            return self.tail_offset_bytes(inode.tail_block, inode.tail_start_frag)
        return None

    def _lookup(self, path: str):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        if name == NAME_ROOT and name not in mapping and NAME_ROOT_ALIAS in mapping:
            name = NAME_ROOT_ALIAS
        if name not in mapping:
            raise FsNotFoundError(f"Файл не найден: {path}")
        return mapping[name]

    def stat(self, path: str):
        ino = self._lookup(path)
        inode = self.disk.read_inode(ino)
        return ino, inode

    def ls(self, all_files: bool = False):
        mapping = self._load_name_index()
        out: List[Tuple[str, int, Inode]] = []
        for name, ino in mapping.items():
            if not all_files and name.startswith("."):
                continue
            inode = self.disk.read_inode(ino)
            out.append((name, ino, inode))
        out.sort(key=lambda t: t[0])
        return out

    def create_file(self, path: str, mode: int = DEFAULT_FILE_PERMS):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        if name in (NAME_ROOT, NAME_ROOT_ALIAS):
            raise FsError("Нельзя создавать файл/каталог с именем корня")
        if name in mapping:
            raise FsExistsError(f"Файл уже существует: {path}")
        ino = self.disk.alloc_inode()
        inode = Inode.empty()
        inode.mode = FTYPE_REG | (mode & 0o777)
        if self.current_user is None:
            inode.owner_uid = 0
            inode.group_gid = 0
        else:
            inode.owner_uid = self.current_user.uid
            inode.group_gid = self.current_user.primary_gid
        inode.nlink = 1
        self.disk.write_inode(ino, inode)
        self.disk.write_file(ino, b"")
        mapping[name] = ino
        self._store_name_index(mapping)
        return ino

    def remove(self, path: str):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        if name in (NAME_ROOT, NAME_ROOT_ALIAS):
            raise FsPermissionError("Нельзя удалить корневой каталог")
        if name not in mapping:
            raise FsNotFoundError(path)
        ino = mapping[name]
        inode = self.disk.read_inode(ino)
        self._require_perm(inode, 0o2, "rm")
        if inode.mode & FTYPE_SYSTEM:
            raise FsPermissionError("Нельзя удалить системный файл")
        if inode.nlink > 0:
            inode.nlink -= 1
        self.disk.write_inode(ino, inode)
        del mapping[name]
        self._store_name_index(mapping)
        if inode.nlink <= 0:
            self.disk.free_inode(ino)

    def chmod(self, path: str, new_mode_octal: int):
        ino = self._lookup(path)
        inode = self.disk.read_inode(ino)
        if not (self.current_user and (self.current_user.is_root or self.current_user.uid == inode.owner_uid)):
            raise FsPermissionError("Только владелец или root может менять права доступа")
        ftype = inode.mode & FTYPE_MASK
        inode.mode = ftype | (new_mode_octal & 0o777)
        self.disk.write_inode(ino, inode)

    def chown(self, path: str, new_owner: User):
        ino = self._lookup(path)
        inode = self.disk.read_inode(ino)
        if not (self.current_user and self.current_user.is_root):
            raise FsPermissionError("Только root может менять владельца")
        inode.owner_uid = new_owner.uid
        inode.group_gid = new_owner.primary_gid
        self.disk.write_inode(ino, inode)

    def chgrp(self, path: str, group_name: str):
        self._ensure_root()
        self.reload_users()
        gid = None
        for g_id, g_name in self._group_names.items():
            if g_name == group_name:
                gid = g_id
                break
        if gid is None:
            raise FsNotFoundError(f"Группа не найдена: {group_name}")
        ino = self._lookup(path)
        inode = self.disk.read_inode(ino)
        inode.group_gid = gid
        self.disk.write_inode(ino, inode)

    def touch(self, path: str):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        now = int(time.time())
        if name in mapping:
            ino = mapping[name]
            inode = self.disk.read_inode(ino)
            self._require_perm(inode, 0o2, "touch")
            inode.mtime = now
            self.disk.write_inode(ino, inode)
        else:
            self.create_file(path)

    def read_text(self, path: str):
        ino = self._lookup(path)
        inode = self.disk.read_inode(ino)
        self._require_perm(inode, 0o4, "read")
        raw = self.disk.read_file(ino)
        return raw.decode("utf-8", errors="ignore")

    def write_text(self, path: str, text: str):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        if name in mapping:
            ino = mapping[name]
            inode = self.disk.read_inode(ino)
            self._require_perm(inode, 0o2, "write")
        else:
            ino = self.create_file(path)
        self.disk.write_file(ino, text.encode("utf-8"))

    def append_text(self, path: str, text: str):
        name = self._normalize_path(path)
        mapping = self._load_name_index()
        if name in mapping:
            ino = mapping[name]
            inode = self.disk.read_inode(ino)
            self._require_perm(inode, 0o2, "append")
            old = self.disk.read_file(ino)
            self.disk.write_file(ino, old + text.encode("utf-8"))
        else:
            ino = self.create_file(path)
            self.disk.write_file(ino, text.encode("utf-8"))

    def copy(self, src: str, dst: str):
        src_ino = self._lookup(src)
        src_inode = self.disk.read_inode(src_ino)
        self._require_perm(src_inode, 0o4, "cp")
        data = self.disk.read_file(src_ino)
        dst_name = self._normalize_path(dst)
        mapping = self._load_name_index()
        if dst_name in mapping:
            raise FsExistsError(f"Целевой файл уже существует: {dst}")
        dst_ino = self.disk.alloc_inode()
        dst_inode = Inode.empty()
        dst_inode.mode = src_inode.mode
        if self.current_user:
            dst_inode.owner_uid = self.current_user.uid
            dst_inode.group_gid = self.current_user.primary_gid
        else:
            dst_inode.owner_uid = src_inode.owner_uid
            dst_inode.group_gid = src_inode.group_gid
        dst_inode.nlink = 1
        self.disk.write_inode(dst_ino, dst_inode)
        self.disk.write_file(dst_ino, data)
        mapping[dst_name] = dst_ino
        self._store_name_index(mapping)

    def move(self, src: str, dst: str):
        src_name = self._normalize_path(src)
        dst_name = self._normalize_path(dst)
        mapping = self._load_name_index()
        if src_name in (NAME_ROOT, NAME_ROOT_ALIAS) or dst_name in (NAME_ROOT, NAME_ROOT_ALIAS):
            raise FsPermissionError("Нельзя переименовывать корневой каталог")
        if src_name not in mapping:
            raise FsNotFoundError(src)
        if dst_name in mapping:
            raise FsExistsError(dst)
        ino = mapping[src_name]
        inode = self.disk.read_inode(ino)
        self._require_perm(inode, 0o2, "mv")
        del mapping[src_name]
        mapping[dst_name] = ino
        self._store_name_index(mapping)

    def add_group(self, group_name: str):
        self._ensure_root()
        if not group_name or ":" in group_name:
            raise FsError("Некорректное имя группы")
        raw = self.disk.read_file(self.sb.groups_inode) if self.sb.groups_inode else b""
        lines = []
        max_gid = -1
        if raw:
            text = raw.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    gid_str, name = line.split(":", 1)
                    gid = int(gid_str)
                except ValueError:
                    continue
                if name == group_name:
                    raise FsExistsError("Группа уже существует")
                lines.append((gid, name))
                if gid > max_gid:
                    max_gid = gid
        new_gid = 0 if max_gid < 0 else max_gid + 1
        lines.append((new_gid, group_name))
        lines.sort(key=lambda t: t[0])
        out_lines = [f"{gid}:{name}" for gid, name in lines]
        data = ("\n".join(out_lines) + "\n").encode("utf-8")
        self.disk.write_file(self.sb.groups_inode, data)
        self.reload_users()

    def del_group(self, group_name: str):
        self._ensure_root()
        self.reload_users()
        root_gid = 0
        if root_gid not in self._group_names:
            raise FsError("root group not found")
        raw = self.disk.read_file(self.sb.groups_inode) if self.sb.groups_inode else b""
        if not raw:
            raise FsNotFoundError("Группы не найдены")
        text = raw.decode("utf-8", errors="ignore")
        lines = []
        gid_to_delete = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                gid_str, name = line.split(":", 1)
                gid = int(gid_str)
            except ValueError:
                continue
            if name == group_name:
                gid_to_delete = gid
            else:
                lines.append((gid, name))
        if gid_to_delete is None:
            raise FsNotFoundError("Группа не найдена")
        if gid_to_delete == 0:
            raise FsError("Нельзя удалить системную группу root")
        self._reassign_group_files(gid_to_delete, new_gid=root_gid)
        out_lines = [f"{gid}:{name}" for gid, name in lines]
        data = ("\n".join(out_lines) + ("\n" if out_lines else "")).encode("utf-8")
        self.disk.write_file(self.sb.groups_inode, data)

        raw_ug = self.disk.read_file(self.sb.user_groups_inode) if self.sb.user_groups_inode else b""
        if raw_ug:
            text_ug = raw_ug.decode("utf-8", errors="ignore")
            ug_lines = []
            for line in text_ug.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    uid_str, gid_str = line.split(":", 1)
                    uid = int(uid_str)
                    gid = int(gid_str)
                except ValueError:
                    continue
                if gid == gid_to_delete:
                    continue
                ug_lines.append((uid, gid))
            out_ug = [f"{uid}:{gid}" for uid, gid in ug_lines]
            data_ug = ("\n".join(out_ug) + ("\n" if out_ug else "")).encode("utf-8")
            self.disk.write_file(self.sb.user_groups_inode, data_ug)

        self.reload_users()

    def add_user(self, username: str, password: str):
        self._ensure_root()
        if not username or ":" in username:
            raise FsError("Некорректное имя пользователя")
        raw = self.disk.read_file(self.sb.users_inode) if self.sb.users_inode else b""
        lines = []
        max_uid = -1
        if raw:
            text = raw.decode("utf-8", errors="ignore")
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    uid_str, uname, pwd_hash = line.split(":", 2)
                    uid = int(uid_str)
                except ValueError:
                    continue
                if uname == username:
                    raise FsExistsError("Пользователь уже существует")
                lines.append((uid, uname, pwd_hash))
                if uid > max_uid:
                    max_uid = uid
        new_uid = 0 if max_uid < 0 else max_uid + 1
        pwd_hash_new = hashlib.sha256(password.encode("utf-8")).hexdigest()
        lines.append((new_uid, username, pwd_hash_new))
        lines.sort(key=lambda t: t[0])
        out_lines = [f"{uid}:{uname}:{pwd}" for uid, uname, pwd in lines]
        data = ("\n".join(out_lines) + "\n").encode("utf-8")
        self.disk.write_file(self.sb.users_inode, data)

        raw_groups = self.disk.read_file(self.sb.groups_inode) if self.sb.groups_inode else b""
        root_gid = 0
        if raw_groups:
            text_g = raw_groups.decode("utf-8", errors="ignore")
            has_root = False
            for line in text_g.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    gid_str, gname = line.split(":", 1)
                    gid = int(gid_str)
                except ValueError:
                    continue
                if gid == 0:
                    has_root = True
                    break
            if not has_root:
                root_gid = 0

        raw_ug = self.disk.read_file(self.sb.user_groups_inode) if self.sb.user_groups_inode else b""
        ug_lines = []
        if raw_ug:
            text_ug = raw_ug.decode("utf-8", errors="ignore")
            for line in text_ug.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    uid_str, gid_str = line.split(":", 1)
                    uid = int(uid_str)
                    gid = int(gid_str)
                except ValueError:
                    continue
                ug_lines.append((uid, gid))
        ug_lines.append((new_uid, root_gid))
        out_ug = [f"{uid}:{gid}" for uid, gid in ug_lines]
        data_ug = ("\n".join(out_ug) + "\n").encode("utf-8")
        self.disk.write_file(self.sb.user_groups_inode, data_ug)

        self.reload_users()

    def del_user(self, username: str):
        self._ensure_root()
        self.reload_users()
        root_user = self._user_by_uid.get(0)
        if not root_user:
            raise FsError("Пользователь root не найден")
        raw = self.disk.read_file(self.sb.users_inode) if self.sb.users_inode else b""
        if not raw:
            raise FsNotFoundError("Пользователи не найдены")
        text = raw.decode("utf-8", errors="ignore")
        lines = []
        uid_to_delete = None
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                uid_str, uname, pwd_hash = line.split(":", 2)
                uid = int(uid_str)
            except ValueError:
                continue
            if uname == username:
                uid_to_delete = uid
            else:
                lines.append((uid, uname, pwd_hash))
        if uid_to_delete is None:
            raise FsNotFoundError("Пользователь не найден")
        if uid_to_delete == 0:
            raise FsError("Нельзя удалить пользователя root")

        self._reassign_user_files(uid_to_delete, new_uid=root_user.uid, new_gid=root_user.primary_gid)

        out_lines = [f"{uid}:{uname}:{pwd}" for uid, uname, pwd in lines]
        data = ("\n".join(out_lines) + ("\n" if out_lines else "")).encode("utf-8")
        self.disk.write_file(self.sb.users_inode, data)

        raw_ug = self.disk.read_file(self.sb.user_groups_inode) if self.sb.user_groups_inode else b""
        if raw_ug:
            text_ug = raw_ug.decode("utf-8", errors="ignore")
            ug_lines = []
            for line in text_ug.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    uid_str, gid_str = line.split(":", 1)
                    uid = int(uid_str)
                    gid = int(gid_str)
                except ValueError:
                    continue
                if uid == uid_to_delete:
                    continue
                ug_lines.append((uid, gid))
            out_ug = [f"{uid}:{gid}" for uid, gid in ug_lines]
            data_ug = ("\n".join(out_ug) + ("\n" if out_ug else "")).encode("utf-8")
            self.disk.write_file(self.sb.user_groups_inode, data_ug)

        self.reload_users()

    def add_user_to_group(self, username: str, group_name: str):
        self._ensure_root()
        self.reload_users()
        user = self._user_by_name.get(username)
        if not user:
            raise FsNotFoundError("Пользователь не найден")
        gid = None
        for g_id, g_name in self._group_names.items():
            if g_name == group_name:
                gid = g_id
                break
        if gid is None:
            raise FsNotFoundError("Группа не найдена")
        raw_ug = self.disk.read_file(self.sb.user_groups_inode) if self.sb.user_groups_inode else b""
        ug_lines = []
        exists = False
        if raw_ug:
            text_ug = raw_ug.decode("utf-8", errors="ignore")
            for line in text_ug.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    uid_str, gid_str = line.split(":", 1)
                    uid = int(uid_str)
                    g = int(gid_str)
                except ValueError:
                    continue
                if uid == user.uid and g == gid:
                    exists = True
                ug_lines.append((uid, g))
        if not exists:
            ug_lines.append((user.uid, gid))
        out_ug = [f"{uid}:{g}" for uid, g in ug_lines]
        data_ug = ("\n".join(out_ug) + "\n").encode("utf-8")
        self.disk.write_file(self.sb.user_groups_inode, data_ug)
        self.reload_users()

    def remove_user_from_group(self, username: str, group_name: str):
        self._ensure_root()
        self.reload_users()
        user = self._user_by_name.get(username)
        if not user:
            raise FsNotFoundError("Пользователь не найден")
        gid = None
        for g_id, g_name in self._group_names.items():
            if g_name == group_name:
                gid = g_id
                break
        if gid is None:
            raise FsNotFoundError("Группа не найдена")
        if user.uid == 0 and gid == 0:
            raise FsError("Нельзя удалить пользователя root из группы root")
        raw_ug = self.disk.read_file(self.sb.user_groups_inode) if self.sb.user_groups_inode else b""
        if not raw_ug:
            raise FsNotFoundError("Отношения пользователь-группа не найдены")
        text_ug = raw_ug.decode("utf-8", errors="ignore")
        ug_lines = []
        removed = False
        for line in text_ug.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                uid_str, gid_str = line.split(":", 1)
                uid = int(uid_str)
                g = int(gid_str)
            except ValueError:
                continue
            if uid == user.uid and g == gid:
                removed = True
                continue
            ug_lines.append((uid, g))
        if not removed:
            raise FsNotFoundError("Пользователь не состоит в этой группе")
        out_ug = [f"{uid}:{g}" for uid, g in ug_lines]
        data_ug = ("\n".join(out_ug) + ("\n" if out_ug else "")).encode("utf-8")
        self.disk.write_file(self.sb.user_groups_inode, data_ug)
        self.reload_users()

    def debug_layout(self):
        layouts = []
        blk_size = self.sb.block_size
        for cg in self.disk.cgs:
            base = cg.global_start_block
            entry = {
                "cg_id": cg.cg_id,
                "cg_start_block": base,
                "cg_size_blocks": cg.size_blocks,
                "superblock_block": base + cg.sb_offset,
                "superblock_offset": (base + cg.sb_offset) * blk_size,
                "cg_header_block": base + cg.self_offset,
                "cg_header_offset": (base + cg.self_offset) * blk_size,
                "frag_bitmap_block": None,
                "frag_bitmap_blocks": cg.frag_bitmap_blocks,
                "frag_bitmap_offset": None,
                "inode_bitmap_block": base + cg.inode_bitmap_offset,
                "inode_bitmap_blocks": cg.inode_bitmap_blocks,
                "inode_bitmap_offset": (base + cg.inode_bitmap_offset) * blk_size,
                "inode_table_block": base + cg.inode_table_offset,
                "inode_table_blocks": cg.inode_table_blocks,
                "inode_table_offset": (base + cg.inode_table_offset) * blk_size,
                "data_block_start": base + cg.data_segment_offset,
                "data_block_count": cg.data_blocks,
                "data_offset": (base + cg.data_segment_offset) * blk_size,
            }
            if cg.frag_bitmap_blocks:
                entry["frag_bitmap_block"] = base + cg.frag_bitmap_offset
                entry["frag_bitmap_offset"] = (base + cg.frag_bitmap_offset) * blk_size
            layouts.append(entry)
        return layouts
