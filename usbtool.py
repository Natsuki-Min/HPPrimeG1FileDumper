#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import argparse
from contextlib import contextmanager

# 尝试导入平台特定的库
try:
    import tqdm
except ImportError:
    print("错误: 请安装 'tqdm' 库 (pip install tqdm)")
    sys.exit(1)

if sys.platform == 'win32':
    try:
        import win32file
        import win32api
    except ImportError:
        print("错误: 在Windows上, 请安装 'pywin32' 库 (pip install pywin32)")
        sys.exit(1)

# --- 从逆向分析中得到的协议常量 ---
SECTOR_SIZE = 512
CONTROL_LBA = 170
UNLOCK_READ_SECTORS = 30

# 特殊命令的魔术字和ID
CMD_MAGIC1 = 0xAA5555AA
CMD_MAGIC2 = 0x44435842
CMD_HEADER_SIZE = 512
CMD_FLAG = 0x80000000

CMD_REBOOT = 0xBEC1
CMD_SCAN_BAD_BLOCKS = 0xBEC2 # 建议在烧写前执行，但按要求未作为独立功能
CMD_UPDATE_PROGRESS = 0xBEDC


class S3C2416Downloader:
    """
    S3C2416 Bootloader下载工具，通过原生SCSI磁盘接口通信。
    """

    def __init__(self, device_path):
        """
        初始化下载器。

        :param device_path: 设备的路径 (e.g., '/dev/sdb' on Linux, '\\\\.\\PhysicalDrive1' on Windows)
        """
        self.device_path = device_path
        self.platform = sys.platform
        if not os.path.exists(self.device_path) and self.platform == 'linux':
             raise FileNotFoundError(f"设备 '{self.device_path}' 不存在。请确认设备节点。")


    @contextmanager
    def _get_device_handle(self, read_only=False):
        """
        一个上下文管理器，用于安全地打开和关闭跨平台的设备句柄。
        """
        handle = None
        try:
            if self.platform.startswith('linux'):
                # 在Linux上, 使用 os.open 获取文件描述符
                flags = os.O_RDONLY if read_only else os.O_RDWR
                handle = os.open(self.device_path, flags)
                yield handle
            elif self.platform == 'win32':
                # 在Windows上, 使用 pywin32 的 CreateFile
                access = win32file.GENERIC_READ if read_only else (win32file.GENERIC_READ | win32file.GENERIC_WRITE)
                share_mode = win32file.FILE_SHARE_READ | win32file.FILE_SHARE_WRITE
                
                # CreateFile需要管理员权限才能打开PhysicalDrive
                handle = win32file.CreateFile(
                    self.device_path,
                    access,
                    share_mode,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None
                )
                yield handle
            else:
                raise NotImplementedError(f"不支持的平台: {self.platform}")
        finally:
            if handle is not None:
                if self.platform.startswith('linux'):
                    os.close(handle)
                elif self.platform == 'win32':
                    win32api.CloseHandle(handle)

    def _seek_and_op(self, handle, lba, data=None, num_sectors_to_read=0):
        """
        在指定LBA上执行读或写操作的底层函数。
        """
        offset = lba * SECTOR_SIZE
        
        if self.platform.startswith('linux'):
            os.lseek(handle, offset, os.SEEK_SET)
            if data:
                written = os.write(handle, data)
                if written != len(data):
                    raise IOError(f"写入错误: 期望写入 {len(data)} 字节, 实际写入 {written}")
            else:
                return os.read(handle, num_sectors_to_read * SECTOR_SIZE)
        
        elif self.platform == 'win32':
            win32file.SetFilePointer(handle, offset, win32file.FILE_BEGIN)
            if data:
                _, written = win32file.WriteFile(handle, data)
                if written != len(data):
                    raise IOError(f"写入错误: 期望写入 {len(data)} 字节, 实际写入 {written}")
            else:
                _, data_read = win32file.ReadFile(handle, num_sectors_to_read * SECTOR_SIZE)
                return data_read

    def _send_control_command(self, cmd_id, arg=0):
        """
        构造并发送一个512字节的控制命令到CONTROL_LBA。
        """
        command_packet = struct.pack(
            '<IIIII', # Little-endian, 5x unsigned int
            CMD_MAGIC1,
            CMD_MAGIC2,
            CMD_HEADER_SIZE,
            cmd_id ,
            arg
        )
        # 用0填充到512字节
        command_packet = command_packet.ljust(CMD_HEADER_SIZE, b'\x00')

        with self._get_device_handle() as h:
            self._seek_and_op(h, CONTROL_LBA, data=command_packet)
        print(f"控制命令 0x{cmd_id:X} (参数: {arg}) 已发送。")

    def unlock_device(self):
        """
        [功能1] 解锁设备写入功能。
        通过向LBA 170发送一个长度为30个扇区的读请求来实现。
        """
        print(f"正在向 LBA {CONTROL_LBA} 发送读请求 (长度 {UNLOCK_READ_SECTORS} 扇区) 以解锁设备...")
        with self._get_device_handle(read_only=True) as h:
            self._seek_and_op(h, CONTROL_LBA, num_sectors_to_read=UNLOCK_READ_SECTORS)
        print("设备已解锁，可以进行写入。")

    def update_progress(self, percentage):
        """
        [功能2] 更新设备屏幕上的进度条。
        """
        if not 0 <= percentage <= 100:
            raise ValueError("百分比必须在 0 到 100 之间。")
        self._send_control_command(CMD_UPDATE_PROGRESS, int(percentage))

    def write_to_nand(self, file_path, start_lba=0, block_size_kb=128):
        """
        [功能3] 将本地文件写入NAND。
        以对齐的块大小读取文件，并将最后一块用0xFF填充。
        """
        block_size_bytes = block_size_kb * 1024
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件 '{file_path}' 不存在。")
        
        file_size = os.path.getsize(file_path)
        print(f"准备烧写文件: '{file_path}' ({file_size / 1024:.2f} KB)")
        print(f"目标 LBA: {start_lba}, NAND块大小: {block_size_kb} KB")
        
        with open(file_path, 'rb') as f_in, \
             self._get_device_handle() as h_dev, \
             tqdm.tqdm(total=file_size, unit='B', unit_scale=True, desc="烧写进度") as pbar:
            
            current_lba = start_lba
            while True:
                chunk = f_in.read(block_size_bytes)
                if not chunk:
                    break
                
                # 如果是最后一块且长度不足，用0xFF填充
                if len(chunk) < block_size_bytes:
                    chunk = chunk.ljust(block_size_bytes, b'\xff')
                
                self._seek_and_op(h_dev, current_lba, data=chunk)
                
                current_lba += (block_size_bytes // SECTOR_SIZE)
                pbar.update(len(chunk))
        print("文件烧写完成。")

    def reboot_device(self):
        """
        [功能4] 重启设备。
        """
        self._send_control_command(CMD_REBOOT)
        print("重启命令已发送。设备现在应该会重启。")


def main():
    parser = argparse.ArgumentParser(
        description="S3C2416 Bootloader 原生SCSI下载工具",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "-d", "--device",
        required=True,
        help="目标设备路径。\n"
             "Linux 示例: /dev/sdb\n"
             "Windows 示例: \\\\.\\PhysicalDrive1 (注意需要管理员权限)"
    )
    
    # 创建一个互斥组，因为这些操作不能同时进行
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--unlock", action="store_true", help="执行解锁设备操作。")
    action_group.add_argument("--reboot", action="store_true", help="发送重启命令。")
    action_group.add_argument("--progress", type=int, metavar="<0-100>", help="更新屏幕进度条到指定百分比。")
    action_group.add_argument("--write", type=str, metavar="<文件路径>", help="烧写指定文件到NAND。")
    
    # --write 操作的附加参数
    parser.add_argument("--lba", type=int, default=0, help="烧写起始的LBA地址 (默认为0)。")
    parser.add_argument("--block-size", type=int, default=128, help="NAND的块大小(KB)，用于对齐 (默认为128)。")

    args = parser.parse_args()

    try:
        downloader = S3C2416Downloader(args.device)

        if args.unlock:
            downloader.unlock_device()
        elif args.reboot:
            downloader.reboot_device()
        elif args.progress is not None:
            downloader.update_progress(args.progress)
        elif args.write:
            # 对于烧写，一个完整的流程是：解锁 -> 烧写 -> 重启
            print("--- 开始标准烧写流程 ---")
            downloader.unlock_device()
            downloader.write_to_nand(args.write, args.lba, args.block_size)
            downloader.reboot_device()
            print("--- 烧写流程全部完成 ---")
            
    except (FileNotFoundError, PermissionError, IOError) as e:
        print(f"\n错误: {e}", file=sys.stderr)
        if sys.platform == 'win32' and isinstance(e, PermissionError):
            print("提示: 在Windows上，请确保以管理员身份运行此脚本。", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"\n发生未知错误: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
