#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import struct
import argparse
import ctypes 

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
else:
    import fcntl  
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

SG_IO = 0x2285
SG_DXFER_FROM_DEV = -3
SG_DXFER_TO_DEV = -2

class sg_io_hdr(ctypes.Structure):
    _fields_ = [
        ('interface_id', ctypes.c_int),    # 'S'
        ('dxfer_direction', ctypes.c_int), # SG_DXFER_FROM_DEV
        ('cmd_len', ctypes.c_ubyte),       # Length of SCSI command (10)
        ('mx_sb_len', ctypes.c_ubyte),     # Max sense buffer len
        ('iovec_count', ctypes.c_ushort),  # 0
        ('dxfer_len', ctypes.c_uint),      # Byte count to read
        ('dxferp', ctypes.c_void_p),       # Pointer to data buffer
        ('cmdp', ctypes.c_void_p),         # Pointer to command buffer
        ('sbp', ctypes.c_void_p),          # Pointer to sense buffer
        ('timeout', ctypes.c_uint),        # Milliseconds
        ('flags', ctypes.c_uint),
        ('pack_id', ctypes.c_int),
        ('usr_ptr', ctypes.c_void_p),
        ('status', ctypes.c_ubyte),
        ('masked_status', ctypes.c_ubyte),
        ('msg_status', ctypes.c_ubyte),
        ('sb_len_wr', ctypes.c_ubyte),
        ('host_status', ctypes.c_ushort),
        ('driver_status', ctypes.c_ushort),
        ('resid', ctypes.c_int),
        ('duration', ctypes.c_uint),
        ('info', ctypes.c_uint),
    ]
    
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
                flags = (os.O_RDONLY if read_only else os.O_RDWR) | os.O_DSYNC
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
                os.fsync(handle)
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
        Constructs and sends a 512-byte control command.
        Uses SG_IO on Linux to bypass Read-Modify-Write alignment issues.
        """
        # 1. Construct the data packet (512 bytes)
        command_packet = struct.pack(
            '<IIIII',  # Little-endian, 5x unsigned int
            CMD_MAGIC1,
            CMD_MAGIC2,
            CMD_HEADER_SIZE,
            cmd_id,
            arg
        )
        command_packet = command_packet.ljust(CMD_HEADER_SIZE, b'\x00')

        print(f"Sending Control Command 0x{cmd_id:X} (Arg: {arg})...")

        if self.platform.startswith('linux'):
            # --- Linux: Use SG_IO WRITE_10 ---
            # We must force a write of exactly 1 sector to LBA 170.
            # Standard os.write would trigger a 4KB Read-Modify-Write cycle.
            
            # SCSI WRITE_10 Opcode = 0x2A
            # CDB: [0x2A, 0, LBA_3, LBA_2, LBA_1, LBA_0, 0, LEN_H, LEN_L, Control]
            cdb = struct.pack(
                '>BBIBH B',
                0x2A, 0, CONTROL_LBA, 0, 1, 0  # Length = 1 sector
            )

            # Prepare buffers
            data_buffer = (ctypes.c_ubyte * len(command_packet)).from_buffer_copy(command_packet)
            sense_buffer = (ctypes.c_ubyte * 32)()
            cmd_buffer = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)

            io_hdr = sg_io_hdr()
            io_hdr.interface_id = ord('S')
            io_hdr.dxfer_direction = SG_DXFER_TO_DEV  # -2 (Write to device)
            io_hdr.cmd_len = len(cdb)
            io_hdr.mx_sb_len = len(sense_buffer)
            io_hdr.dxfer_len = len(command_packet)
            io_hdr.dxferp = ctypes.cast(data_buffer, ctypes.c_void_p)
            io_hdr.cmdp = ctypes.cast(cmd_buffer, ctypes.c_void_p)
            io_hdr.sbp = ctypes.cast(sense_buffer, ctypes.c_void_p)
            io_hdr.timeout = 5000

            with self._get_device_handle(read_only=False) as fd:
                try:
                    fcntl.ioctl(fd, SG_IO, io_hdr)
                    print("Linux SG_IO Write command sent successfully.")
                except OSError as e:
                    print(f"Error sending SG_IO Write: {e}")
                    raise

        else:
            # --- Windows: Standard Write ---
            with self._get_device_handle() as h:
                self._seek_and_op(h, CONTROL_LBA, data=command_packet)
                
        print(f"Control command 0x{cmd_id:X} sent.")

    def unlock_device(self):
        """
        [Function 1] Unlock device write function.
        Sends a raw SCSI READ_10 command for exactly 30 sectors to LBA 170.
        """
        print(f"Unlocking: Sending READ request to LBA {CONTROL_LBA} (len {UNLOCK_READ_SECTORS})...")
        
        if self.platform.startswith('linux'):
            # --- Linux Implementation: SCSI Passthrough (SG_IO) ---
            # We must use SG_IO because standard os.read() will be padded 
            # by the kernel block layer (e.g., 30 sectors -> 32 sectors),
            # causing the firmware unlock check to fail.
            
            # Prepare SCSI READ_10 Command (Opcode 0x28)
            # Format: [0x28, 0, LBA_3, LBA_2, LBA_1, LBA_0, 0, LEN_H, LEN_L, Control]
            # SCSI is Big-Endian
            cdb = struct.pack(
                '>BBIBH B', 
                0x28, 0, CONTROL_LBA, 0, UNLOCK_READ_SECTORS, 0
            )
            
            # Create buffers
            data_len = UNLOCK_READ_SECTORS * SECTOR_SIZE
            data_buffer = (ctypes.c_ubyte * data_len)()
            sense_buffer = (ctypes.c_ubyte * 32)()
            cmd_buffer = (ctypes.c_ubyte * len(cdb)).from_buffer_copy(cdb)
            
            # Populate SG_IO Header
            io_hdr = sg_io_hdr()
            io_hdr.interface_id = ord('S')
            io_hdr.dxfer_direction = SG_DXFER_FROM_DEV
            io_hdr.cmd_len = len(cdb)
            io_hdr.mx_sb_len = len(sense_buffer)
            io_hdr.dxfer_len = data_len
            io_hdr.dxferp = ctypes.cast(data_buffer, ctypes.c_void_p)
            io_hdr.cmdp = ctypes.cast(cmd_buffer, ctypes.c_void_p)
            io_hdr.sbp = ctypes.cast(sense_buffer, ctypes.c_void_p)
            io_hdr.timeout = 5000 # 5 seconds
            
            with self._get_device_handle(read_only=True) as fd:
                # On Linux, fd is an integer
                try:
                    fcntl.ioctl(fd, SG_IO, io_hdr)
                    print("Linux SG_IO Unlock command sent successfully.")
                except OSError as e:
                    print(f"Error sending SG_IO command: {e}")
                    raise

        else:
            # --- Windows Implementation ---
            # Windows ReadFile usually respects the exact sector count requested
            with self._get_device_handle(read_only=True) as h:
                self._seek_and_op(h, CONTROL_LBA, num_sectors_to_read=UNLOCK_READ_SECTORS)
                
        print("Device should be unlocked now.")

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
