from __future__ import annotations

import io
import os
import struct
import time
from dataclasses import dataclass, field
from typing import List

from smol.constants import (
    FS_MAGIC,
    BLOCK_SIZE,
    FRAGMENT_SIZE,
    FRAGS_PER_BLOCK,
    INODE_SIZE,
    SUPERBLOCK_SIZE,
    CG_HEADER_SIZE,
    INODES_PER_CG,
)

SB_STRUCT = struct.Struct("<I H H I H H H I I I I I Q Q H 8s")
INODE_STRUCT = struct.Struct("<H B B I Q Q 11I I I B B B B")
CG_STRUCT = struct.Struct("<H I I H H H H H H I I I")


class DiskError(Exception):
    pass


@dataclass
class Superblock:
    magic: int
    block_size: int
    fragment_size: int
    total_blocks: int
    inode_size: int
    inodes_per_cg: int
    cg_count: int
    cg_blocks: int
    name_inode: int
    users_inode: int
    groups_inode: int
    user_groups_inode: int
    created_at: int
    modified_at: int
    superblock_size: int
    reserved: bytes = field(repr=False)

    @classmethod
    def new(cls, total_blocks: int, cg_blocks: int, cg_count: int):
        now = int(time.time())
        return cls(
            magic=FS_MAGIC,
            block_size=BLOCK_SIZE,
            fragment_size=FRAGMENT_SIZE,
            total_blocks=total_blocks,
            inode_size=INODE_SIZE,
            inodes_per_cg=INODES_PER_CG,
            cg_count=cg_count,
            cg_blocks=cg_blocks,
            name_inode=0,
            users_inode=0,
            groups_inode=0,
            user_groups_inode=0,
            created_at=now,
            modified_at=now,
            superblock_size=SUPERBLOCK_SIZE,
            reserved=b"\x00" * 8,
        )

    def pack(self):
        return SB_STRUCT.pack(
            self.magic,
            self.block_size,
            self.fragment_size,
            self.total_blocks,
            self.inode_size,
            self.inodes_per_cg,
            self.cg_count,
            self.cg_blocks,
            self.name_inode,
            self.users_inode,
            self.groups_inode,
            self.user_groups_inode,
            self.created_at,
            self.modified_at,
            self.superblock_size,
            self.reserved,
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < SUPERBLOCK_SIZE:
            raise DiskError("Суперблок слишком мал")
        fields = SB_STRUCT.unpack(data[:SUPERBLOCK_SIZE])
        sb = cls(
            magic=fields[0],
            block_size=fields[1],
            fragment_size=fields[2],
            total_blocks=fields[3],
            inode_size=fields[4],
            inodes_per_cg=fields[5],
            cg_count=fields[6],
            cg_blocks=fields[7],
            name_inode=fields[8],
            users_inode=fields[9],
            groups_inode=fields[10],
            user_groups_inode=fields[11],
            created_at=fields[12],
            modified_at=fields[13],
            superblock_size=fields[14],
            reserved=fields[15],
        )
        if sb.magic != FS_MAGIC:
            raise DiskError("Это не том SMOLFS (неверная сигнатура)")
        if sb.block_size != BLOCK_SIZE or sb.fragment_size != FRAGMENT_SIZE:
            raise DiskError("Неподдерживаемый размер блока или фрагмента")
        if sb.inode_size != INODE_SIZE:
            raise DiskError("Неподдерживаемый размер инода")
        return sb


@dataclass
class CylinderGroupHeader:
    cg_id: int
    size_blocks: int
    global_start_block: int
    sb_offset: int
    frag_bitmap_offset: int
    self_offset: int
    inode_bitmap_offset: int
    inode_table_offset: int
    data_segment_offset: int
    free_inodes: int
    free_blocks: int
    free_frags: int
    inode_bitmap_bytes: int = 0
    inode_bitmap_blocks: int = 0
    inode_table_blocks: int = 0
    frag_bitmap_bytes: int = 0
    frag_bitmap_blocks: int = 0
    data_blocks: int = 0

    def pack(self):
        return CG_STRUCT.pack(
            self.cg_id,
            self.size_blocks,
            self.global_start_block,
            self.sb_offset,
            self.frag_bitmap_offset,
            self.self_offset,
            self.inode_bitmap_offset,
            self.inode_table_offset,
            self.data_segment_offset,
            self.free_inodes,
            self.free_blocks,
            self.free_frags,
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < CG_HEADER_SIZE:
            raise DiskError("Заголовок группы цилиндров слишком мал")
        fields = CG_STRUCT.unpack(data[:CG_HEADER_SIZE])
        return cls(
            cg_id=fields[0],
            size_blocks=fields[1],
            global_start_block=fields[2],
            sb_offset=fields[3],
            frag_bitmap_offset=fields[4],
            self_offset=fields[5],
            inode_bitmap_offset=fields[6],
            inode_table_offset=fields[7],
            data_segment_offset=fields[8],
            free_inodes=fields[9],
            free_blocks=fields[10],
            free_frags=fields[11],
        )


@dataclass
class Inode:
    mode: int
    owner_uid: int
    group_gid: int
    size_bytes: int
    mtime: int
    ctime: int
    direct_blocks: List[int]
    indirect_block: int
    tail_block: int
    tail_start_frag: int
    tail_frag_count: int
    nlink: int
    reserved: int = 0

    @classmethod
    def empty(cls):
        now = int(time.time())
        return cls(
            mode=0,
            owner_uid=0,
            group_gid=0,
            size_bytes=0,
            mtime=now,
            ctime=now,
            direct_blocks=[0] * 11,
            indirect_block=0,
            tail_block=0,
            tail_start_frag=0,
            tail_frag_count=0,
            nlink=0,
            reserved=0,
        )

    def pack(self):
        if len(self.direct_blocks) != 11:
            raise DiskError("Список прямых блоков инода неверной длины")
        return INODE_STRUCT.pack(
            self.mode,
            self.owner_uid,
            self.group_gid,
            self.size_bytes,
            self.mtime,
            self.ctime,
            *self.direct_blocks,
            self.indirect_block,
            self.tail_block,
            self.tail_start_frag,
            self.tail_frag_count,
            self.nlink,
            self.reserved,
        )

    @classmethod
    def unpack(cls, data: bytes):
        if len(data) < INODE_SIZE:
            raise DiskError("Запись инода слишком мала")
        fields = INODE_STRUCT.unpack(data[:INODE_SIZE])
        mode = fields[0]
        owner_uid = fields[1]
        group_gid = fields[2]
        size_bytes = fields[3]
        mtime = fields[4]
        ctime = fields[5]
        direct_blocks = list(fields[6:17])
        indirect_block = fields[17]
        tail_block = fields[18]
        tail_start_frag = fields[19]
        tail_frag_count = fields[20]
        nlink = fields[21]
        reserved = fields[22]
        return cls(
            mode=mode,
            owner_uid=owner_uid,
            group_gid=group_gid,
            size_bytes=size_bytes,
            mtime=mtime,
            ctime=ctime,
            direct_blocks=direct_blocks,
            indirect_block=indirect_block,
            tail_block=tail_block,
            tail_start_frag=tail_start_frag,
            tail_frag_count=tail_frag_count,
            nlink=nlink,
            reserved=reserved,
        )


def _ceil_div(a: int, b: int):
    return (a + b - 1) // b


def _bit_get(buf: bytes, index: int):
    byte_index = index // 8
    bit_index = index % 8
    return (buf[byte_index] >> bit_index) & 1


def _bit_set(buf: bytearray, index: int, value: int):
    byte_index = index // 8
    bit_index = index % 8
    mask = 1 << bit_index
    if value:
        buf[byte_index] |= mask
    else:
        buf[byte_index] &= ~mask


class Disk:
    def __init__(self, fileobj: io.BufferedRandom, sb: Superblock, cgs: List[CylinderGroupHeader]):
        self.f = fileobj
        self.sb = sb
        self.cgs = cgs

    def _read_at(self, offset: int, size: int):
        self.f.seek(offset)
        data = self.f.read(size)
        if len(data) != size:
            raise DiskError("Не удалось полностью прочитать данные с тома")
        return data

    def _write_at(self, offset: int, data: bytes):
        self.f.seek(offset)
        self.f.write(data)
        self.f.flush()
        os.fsync(self.f.fileno())

    def _read_block(self, block_no: int):
        return self._read_at(block_no * BLOCK_SIZE, BLOCK_SIZE)

    def _write_block(self, block_no: int, data: bytes):
        if len(data) != BLOCK_SIZE:
            if len(data) > BLOCK_SIZE:
                raise DiskError("Запись блока больше размера блока")
            data = data + b"\x00" * (BLOCK_SIZE - len(data))
        self._write_at(block_no * BLOCK_SIZE, data)

    @classmethod
    def create(cls, path: str, size_bytes: int):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        f = open(path, "w+b")
        try:
            f.truncate(size_bytes)
        except OSError:
            f.close()
            raise
        total_blocks = size_bytes // BLOCK_SIZE
        if total_blocks <= 0:
            f.close()
            raise DiskError("Размер тома слишком мал")

        cg_count = 1
        cg_blocks = total_blocks // cg_count

        sb = Superblock.new(total_blocks=total_blocks, cg_blocks=cg_blocks, cg_count=cg_count)

        inode_bitmap_bits = INODES_PER_CG
        inode_bitmap_bytes = _ceil_div(inode_bitmap_bits, 8)
        inode_bitmap_blocks = _ceil_div(inode_bitmap_bytes, BLOCK_SIZE)

        inode_table_bytes = INODES_PER_CG * INODE_SIZE
        inode_table_blocks = _ceil_div(inode_table_bytes, BLOCK_SIZE)

        data_blocks = max(0, cg_blocks - 2 - inode_bitmap_blocks - inode_table_blocks)
        while True:
            frags = data_blocks * FRAGS_PER_BLOCK
            frag_bitmap_bytes = _ceil_div(frags, 8) if frags else 0
            frag_bitmap_blocks = _ceil_div(frag_bitmap_bytes, BLOCK_SIZE) if frag_bitmap_bytes else 0
            new_data_blocks = cg_blocks - 2 - inode_bitmap_blocks - inode_table_blocks - frag_bitmap_blocks
            if new_data_blocks < 0:
                new_data_blocks = 0
            if new_data_blocks == data_blocks:
                break
            data_blocks = new_data_blocks

        frags = data_blocks * FRAGS_PER_BLOCK
        frag_bitmap_bytes = _ceil_div(frags, 8) if frags else 0
        frag_bitmap_blocks = _ceil_div(frag_bitmap_bytes, BLOCK_SIZE) if frag_bitmap_bytes else 0

        sb_offset = 0
        header_offset = 1
        frag_bitmap_offset = header_offset + 1
        inode_bitmap_offset = frag_bitmap_offset + frag_bitmap_blocks
        inode_table_offset = inode_bitmap_offset + inode_bitmap_blocks
        data_segment_offset = inode_table_offset + inode_table_blocks

        if data_segment_offset + data_blocks > cg_blocks:
            raise DiskError("Ошибка расчёта размещения группы цилиндров")

        cg = CylinderGroupHeader(
            cg_id=0,
            size_blocks=cg_blocks,
            global_start_block=0,
            sb_offset=sb_offset,
            frag_bitmap_offset=frag_bitmap_offset,
            self_offset=header_offset,
            inode_bitmap_offset=inode_bitmap_offset,
            inode_table_offset=inode_table_offset,
            data_segment_offset=data_segment_offset,
            free_inodes=INODES_PER_CG,
            free_blocks=data_blocks,
            free_frags=frags,
        )
        cg.inode_bitmap_bytes = inode_bitmap_bytes
        cg.inode_bitmap_blocks = inode_bitmap_blocks
        cg.inode_table_blocks = inode_table_blocks
        cg.frag_bitmap_bytes = frag_bitmap_bytes
        cg.frag_bitmap_blocks = frag_bitmap_blocks
        cg.data_blocks = data_blocks

        vol = cls(fileobj=f, sb=sb, cgs=[cg])
        vol._write_superblock()
        vol._write_cg_header(0)
        vol._init_bitmaps_and_inodes()
        return vol

    @classmethod
    def open(cls, path: str):
        if not os.path.exists(path):
            raise DiskError(f"Том {path} не существует")
        f = open(path, "r+b")
        raw_sb = f.read(SUPERBLOCK_SIZE)
        sb = Superblock.unpack(raw_sb)
        total_blocks = sb.total_blocks
        f.seek(0, os.SEEK_END)
        size = f.tell()
        if size < total_blocks * BLOCK_SIZE:
            raise DiskError("Файл тома меньше заявленного размера")
        cg_blocks = sb.cg_blocks
        cgs: List[CylinderGroupHeader] = []
        for cg_id in range(sb.cg_count):
            cg_start_block = cg_id * cg_blocks
            offset = (cg_start_block + 1) * BLOCK_SIZE
            f.seek(offset)
            raw = f.read(CG_HEADER_SIZE)
            cg = CylinderGroupHeader.unpack(raw)
            cg.global_start_block = cg_start_block

            inode_bitmap_bits = sb.inodes_per_cg
            inode_bitmap_bytes = _ceil_div(inode_bitmap_bits, 8)
            inode_bitmap_blocks = _ceil_div(inode_bitmap_bytes, BLOCK_SIZE)

            inode_table_bytes = sb.inodes_per_cg * INODE_SIZE
            inode_table_blocks = _ceil_div(inode_table_bytes, BLOCK_SIZE)

            data_blocks = cg.size_blocks - cg.data_segment_offset
            frags = data_blocks * FRAGS_PER_BLOCK
            frag_bitmap_bytes = _ceil_div(frags, 8) if frags else 0
            frag_bitmap_blocks = _ceil_div(frag_bitmap_bytes, BLOCK_SIZE) if frag_bitmap_bytes else 0

            cg.inode_bitmap_bytes = inode_bitmap_bytes
            cg.inode_bitmap_blocks = inode_bitmap_blocks
            cg.inode_table_blocks = inode_table_blocks
            cg.frag_bitmap_bytes = frag_bitmap_bytes
            cg.frag_bitmap_blocks = frag_bitmap_blocks
            cg.data_blocks = data_blocks

            cgs.append(cg)

        return cls(fileobj=f, sb=sb, cgs=cgs)

    def close(self):
        try:
            self.f.flush()
            os.fsync(self.f.fileno())
        finally:
            self.f.close()

    def _write_superblock(self):
        raw = self.sb.pack()
        block0 = raw + b"\x00" * (BLOCK_SIZE - len(raw))
        self._write_block(0, block0)
        for cg in self.cgs:
            block_no = cg.global_start_block + cg.sb_offset
            self._write_block(block_no, block0)

    def _write_cg_header(self, cg_index: int):
        cg = self.cgs[cg_index]
        raw = cg.pack()
        block_no = cg.global_start_block + cg.self_offset
        block = self._read_block(block_no)
        block = raw + block[len(raw):]
        self._write_block(block_no, block)

    def _init_bitmaps_and_inodes(self):
        for cg in self.cgs:
            if cg.frag_bitmap_blocks:
                total_bytes = cg.frag_bitmap_blocks * BLOCK_SIZE
                buf = b"\x00" * total_bytes
                self._write_at(
                    (cg.global_start_block + cg.frag_bitmap_offset) * BLOCK_SIZE,
                    buf,
                )
            if cg.inode_bitmap_blocks:
                total_bytes = cg.inode_bitmap_blocks * BLOCK_SIZE
                buf = b"\x00" * total_bytes
                self._write_at(
                    (cg.global_start_block + cg.inode_bitmap_offset) * BLOCK_SIZE,
                    buf,
                )
            if cg.inode_table_blocks:
                total_bytes = cg.inode_table_blocks * BLOCK_SIZE
                buf = b"\x00" * total_bytes
                self._write_at(
                    (cg.global_start_block + cg.inode_table_offset) * BLOCK_SIZE,
                    buf,
                )

    def _read_inode_bitmap(self, cg_index: int):
        cg = self.cgs[cg_index]
        offset = (cg.global_start_block + cg.inode_bitmap_offset) * BLOCK_SIZE
        raw = self._read_at(offset, cg.inode_bitmap_blocks * BLOCK_SIZE)
        return bytearray(raw)

    def _write_inode_bitmap(self, cg_index: int, bitmap: bytearray):
        cg = self.cgs[cg_index]
        if len(bitmap) < cg.inode_bitmap_blocks * BLOCK_SIZE:
            bitmap = bitmap + b"\x00" * (cg.inode_bitmap_blocks * BLOCK_SIZE - len(bitmap))
        self._write_at(
            (cg.global_start_block + cg.inode_bitmap_offset) * BLOCK_SIZE,
            bytes(bitmap),
        )

    def _read_frag_bitmap(self, cg_index: int):
        cg = self.cgs[cg_index]
        if cg.frag_bitmap_blocks == 0:
            return bytearray()
        offset = (cg.global_start_block + cg.frag_bitmap_offset) * BLOCK_SIZE
        raw = self._read_at(offset, cg.frag_bitmap_blocks * BLOCK_SIZE)
        return bytearray(raw)

    def _write_frag_bitmap(self, cg_index: int, bitmap: bytearray):
        cg = self.cgs[cg_index]
        if cg.frag_bitmap_blocks == 0:
            return
        if len(bitmap) < cg.frag_bitmap_blocks * BLOCK_SIZE:
            bitmap = bitmap + b"\x00" * (cg.frag_bitmap_blocks * BLOCK_SIZE - len(bitmap))
        self._write_at(
            (cg.global_start_block + cg.frag_bitmap_offset) * BLOCK_SIZE,
            bytes(bitmap),
        )

    def _inode_location(self, inode_no: int):
        if inode_no < 0:
            raise DiskError("Отрицательный номер инода")
        cg_index = inode_no // self.sb.inodes_per_cg
        local_index = inode_no % self.sb.inodes_per_cg
        if cg_index >= len(self.cgs):
            raise DiskError("Номер инода вне диапазона")
        cg = self.cgs[cg_index]
        inodes_per_block = BLOCK_SIZE // INODE_SIZE
        block_index = local_index // inodes_per_block
        index_in_block = local_index % inodes_per_block
        block_no = cg.global_start_block + cg.inode_table_offset + block_index
        byte_offset = index_in_block * INODE_SIZE
        return cg_index, local_index, block_no, byte_offset

    def read_inode(self, inode_no: int):
        _, _, block_no, byte_offset = self._inode_location(inode_no)
        base = block_no * BLOCK_SIZE + byte_offset
        raw = self._read_at(base, INODE_SIZE)
        return Inode.unpack(raw)

    def write_inode(self, inode_no: int, inode: Inode):
        _, _, block_no, byte_offset = self._inode_location(inode_no)
        base = block_no * BLOCK_SIZE + byte_offset
        raw = inode.pack()
        if len(raw) != INODE_SIZE:
            raise DiskError("Сериализованный инод имеет неверный размер")
        self._write_at(base, raw)

    def alloc_inode(self):
        for cg_index, cg in enumerate(self.cgs):
            if cg.free_inodes <= 0:
                continue
            bitmap = self._read_inode_bitmap(cg_index)
            for local_index in range(self.sb.inodes_per_cg):
                bit = _bit_get(bitmap, local_index)
                if bit == 0:
                    _bit_set(bitmap, local_index, 1)
                    cg.free_inodes -= 1
                    self._write_inode_bitmap(cg_index, bitmap)
                    self._write_cg_header(cg_index)
                    inode_no = cg_index * self.sb.inodes_per_cg + local_index
                    inode = Inode.empty()
                    self.write_inode(inode_no, inode)
                    return inode_no
        raise DiskError("Нет свободных инодов")

    def free_inode(self, inode_no: int):
        cg_index, local_index, _, _ = self._inode_location(inode_no)
        cg = self.cgs[cg_index]
        inode = self.read_inode(inode_no)
        self._free_inode_data(inode)
        self.write_inode(inode_no, Inode.empty())
        bitmap = self._read_inode_bitmap(cg_index)
        if _bit_get(bitmap, local_index) == 1:
            _bit_set(bitmap, local_index, 0)
            cg.free_inodes += 1
            self._write_inode_bitmap(cg_index, bitmap)
            self._write_cg_header(cg_index)

    def _data_block_info(self, block_no: int):
        cg_blocks = self.sb.cg_blocks
        cg_index = block_no // cg_blocks
        if cg_index >= len(self.cgs):
            raise DiskError("Блок вне групп цилиндров")
        cg = self.cgs[cg_index]
        local_block_in_cg = block_no - cg.global_start_block
        local_data_block_index = local_block_in_cg - cg.data_segment_offset
        if not (0 <= local_data_block_index < cg.data_blocks):
            raise DiskError("Блок не относится к области данных")
        return cg_index, local_data_block_index

    def alloc_data_blocks(self, count: int):
        if count <= 0:
            return []
        result: List[int] = []
        for cg_index, cg in enumerate(self.cgs):
            if cg.free_blocks <= 0:
                continue
            bitmap = self._read_frag_bitmap(cg_index)
            for local_block in range(cg.data_blocks):
                if len(result) >= count:
                    break
                all_free = True
                for frag in range(FRAGS_PER_BLOCK):
                    frag_index = local_block * FRAGS_PER_BLOCK + frag
                    if _bit_get(bitmap, frag_index):
                        all_free = False
                        break
                if not all_free:
                    continue
                for frag in range(FRAGS_PER_BLOCK):
                    frag_index = local_block * FRAGS_PER_BLOCK + frag
                    _bit_set(bitmap, frag_index, 1)
                cg.free_blocks -= 1
                cg.free_frags -= FRAGS_PER_BLOCK
                block_no = cg.global_start_block + cg.data_segment_offset + local_block
                result.append(block_no)
            self._write_frag_bitmap(cg_index, bitmap)
            self._write_cg_header(cg_index)
            if len(result) >= count:
                break
        if len(result) < count:
            raise DiskError("Недостаточно свободных блоков")
        return result

    def alloc_tail_fragments(self, frag_count: int):
        if frag_count <= 0:
            raise DiskError("Число фрагментов должно быть > 0")
        if frag_count > FRAGS_PER_BLOCK:
            raise DiskError("Число фрагментов больше числа фрагментов в блоке")
        for cg_index, cg in enumerate(self.cgs):
            bitmap = self._read_frag_bitmap(cg_index)
            for local_block in range(cg.data_blocks):
                base_index = local_block * FRAGS_PER_BLOCK
                run_start = None
                run_len = 0
                for frag in range(FRAGS_PER_BLOCK):
                    bit = _bit_get(bitmap, base_index + frag)
                    if bit == 0:
                        if run_start is None:
                            run_start = frag
                            run_len = 1
                        else:
                            run_len += 1
                        if run_len >= frag_count:
                            for f in range(run_start, run_start + frag_count):
                                idx = base_index + f
                                _bit_set(bitmap, idx, 1)
                                cg.free_frags -= 1
                            full = True
                            for f in range(FRAGS_PER_BLOCK):
                                if _bit_get(bitmap, base_index + f) == 0:
                                    full = False
                                    break
                            if full:
                                cg.free_blocks -= 1
                            self._write_frag_bitmap(cg_index, bitmap)
                            self._write_cg_header(cg_index)
                            block_no = cg.global_start_block + cg.data_segment_offset + local_block
                            return block_no, run_start, frag_count
                    else:
                        run_start = None
                        run_len = 0
        raise DiskError("Недостаточно свободных фрагментов для хвоста файла")

    def free_data_block(self, block_no: int):
        cg_index, local_data_block_index = self._data_block_info(block_no)
        cg = self.cgs[cg_index]
        bitmap = self._read_frag_bitmap(cg_index)
        base_index = local_data_block_index * FRAGS_PER_BLOCK
        used_before = 0
        for f in range(FRAGS_PER_BLOCK):
            if _bit_get(bitmap, base_index + f):
                used_before += 1
        for f in range(FRAGS_PER_BLOCK):
            if _bit_get(bitmap, base_index + f):
                _bit_set(bitmap, base_index + f, 0)
                cg.free_frags += 1
        if used_before == FRAGS_PER_BLOCK:
            cg.free_blocks += 1
        self._write_frag_bitmap(cg_index, bitmap)
        self._write_cg_header(cg_index)

    def free_tail_fragments(self, block_no: int, start_frag: int, frag_count: int):
        cg_index, local_data_block_index = self._data_block_info(block_no)
        cg = self.cgs[cg_index]
        bitmap = self._read_frag_bitmap(cg_index)
        base_index = local_data_block_index * FRAGS_PER_BLOCK
        used_before = sum(1 for f in range(FRAGS_PER_BLOCK) if _bit_get(bitmap, base_index + f))
        for f in range(start_frag, start_frag + frag_count):
            idx = base_index + f
            if _bit_get(bitmap, idx):
                _bit_set(bitmap, idx, 0)
                cg.free_frags += 1
        used_after = sum(1 for f in range(FRAGS_PER_BLOCK) if _bit_get(bitmap, base_index + f))
        if used_before == FRAGS_PER_BLOCK and used_after < FRAGS_PER_BLOCK:
            cg.free_blocks += 1
        self._write_frag_bitmap(cg_index, bitmap)
        self._write_cg_header(cg_index)

    def _free_inode_data(self, inode: Inode):
        size = inode.size_bytes
        if size <= 0:
            return
        full_blocks = size // BLOCK_SIZE
        tail_bytes = size % BLOCK_SIZE

        direct_used = min(full_blocks, len(inode.direct_blocks))
        for i in range(direct_used):
            blk = inode.direct_blocks[i]
            if blk:
                self.free_data_block(blk)
                inode.direct_blocks[i] = 0

        remaining = full_blocks - direct_used
        if remaining > 0 and inode.indirect_block:
            raw = self._read_block(inode.indirect_block)
            ptrs = struct.unpack("<%dI" % (BLOCK_SIZE // 4), raw)
            for j in range(remaining):
                blk = ptrs[j]
                if blk:
                    self.free_data_block(blk)
            self.free_data_block(inode.indirect_block)
            inode.indirect_block = 0

        if tail_bytes and inode.tail_block and inode.tail_frag_count:
            self.free_tail_fragments(
                inode.tail_block,
                inode.tail_start_frag,
                inode.tail_frag_count,
            )
            inode.tail_block = 0
            inode.tail_start_frag = 0
            inode.tail_frag_count = 0

        inode.size_bytes = 0

    def write_file(self, inode_no: int, data: bytes):
        inode = self.read_inode(inode_no)
        self._free_inode_data(inode)

        size = len(data)
        inode.size_bytes = size
        now = int(time.time())
        inode.mtime = now
        inode.ctime = now

        if size == 0:
            self.write_inode(inode_no, inode)
            return

        full_blocks = size // BLOCK_SIZE
        tail_bytes = size % BLOCK_SIZE

        tail_frags = 0
        if tail_bytes:
            tail_frags = _ceil_div(tail_bytes, FRAGMENT_SIZE)
            if tail_frags >= FRAGS_PER_BLOCK:
                full_blocks += 1
                tail_bytes = 0
                tail_frags = 0

        if full_blocks:
            blocks = self.alloc_data_blocks(full_blocks)
        else:
            blocks = []

        direct_count = min(full_blocks, len(inode.direct_blocks))
        for i in range(direct_count):
            inode.direct_blocks[i] = blocks[i]
        for i in range(direct_count, len(inode.direct_blocks)):
            inode.direct_blocks[i] = 0

        extra_blocks = full_blocks - direct_count
        if extra_blocks > 0:
            indirect_block = self.alloc_data_blocks(1)[0]
            inode.indirect_block = indirect_block
            ptrs_per_block = BLOCK_SIZE // 4
            table = [0] * ptrs_per_block
            for i in range(extra_blocks):
                table[i] = blocks[direct_count + i]
            raw_table = struct.pack("<%dI" % ptrs_per_block, *table)
            self._write_block(indirect_block, raw_table)
        else:
            inode.indirect_block = 0

        offset = 0
        for i in range(full_blocks):
            blk = blocks[i]
            chunk = data[offset: offset + BLOCK_SIZE]
            self._write_block(blk, chunk)
            offset += BLOCK_SIZE

        if tail_bytes:
            block_no, start_frag, frag_count = self.alloc_tail_fragments(tail_frags)
            inode.tail_block = block_no
            inode.tail_start_frag = start_frag
            inode.tail_frag_count = frag_count

            tail_data = data[full_blocks * BLOCK_SIZE:]
            tail_total_bytes = frag_count * FRAGMENT_SIZE
            if len(tail_data) < tail_total_bytes:
                tail_data = tail_data + b"\x00" * (tail_total_bytes - len(tail_data))

            blk_data = bytearray(self._read_block(block_no))
            base = start_frag * FRAGMENT_SIZE
            blk_data[base: base + tail_total_bytes] = tail_data[:tail_total_bytes]
            self._write_block(block_no, bytes(blk_data))
        else:
            inode.tail_block = 0
            inode.tail_start_frag = 0
            inode.tail_frag_count = 0

        self.write_inode(inode_no, inode)
        self.sb.modified_at = int(time.time())
        self._write_superblock()

    def read_file(self, inode_no: int):
        inode = self.read_inode(inode_no)
        size = inode.size_bytes
        if size <= 0:
            return b""
        full_blocks = size // BLOCK_SIZE
        tail_bytes = size % BLOCK_SIZE
        parts: List[bytes] = []

        direct_count = min(full_blocks, len(inode.direct_blocks))
        for i in range(direct_count):
            blk = inode.direct_blocks[i]
            if not blk:
                break
            parts.append(self._read_block(blk))

        remaining = full_blocks - direct_count
        if remaining > 0 and inode.indirect_block:
            raw = self._read_block(inode.indirect_block)
            ptrs = struct.unpack("<%dI" % (BLOCK_SIZE // 4), raw)
            for j in range(remaining):
                blk = ptrs[j]
                if not blk:
                    break
                parts.append(self._read_block(blk))

        if tail_bytes and inode.tail_block and inode.tail_frag_count:
            blk_data = self._read_block(inode.tail_block)
            base = inode.tail_start_frag * FRAGMENT_SIZE
            total_tail_bytes = inode.tail_frag_count * FRAGMENT_SIZE
            tail = blk_data[base: base + total_tail_bytes]
            parts.append(tail[:tail_bytes])

        data = b"".join(parts)
        return data[:size]
