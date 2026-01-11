# HP Prime G1 File Dumper

A tool to dump the NAND and rescue files from HP Prime G1 calculators.

##  Warning
Use this tool at your own risk. The author is not responsible for any damage to your calculator or data loss.

##  Prerequisites
- Windows computer
- HP Prime G1 calculator
- USB cable

##  Quick Start Guide

### Step 1: Enter Recovery Mode
1. Press the **reset button** on the back of the calculator
2. While booting, hold the **`Symb`** key until the recovery mode screen appears

### Step 2: Patch Bootloader
1. Connect calculator to computer via USB
2. Run `usbtool.exe`
3. Check **"Auto Update"** box
4. Click **"Update"** (this patches the bootloader without affecting your data)

### Step 3: Dump NAND Data
1. After updating, re-enter recovery mode (reset + `Symb`)
2. The computer will now recognize the drive as **528MB** (originally 255MB)
3. NAND content is located at **256MB-512MB**
4. OOB (Out-of-Band) data is at **512MB-520MB**

### Extraction Methods:

#### Method A: Using Git Bash (dd)
```bash
# Dump NAND (256MB-512MB)
dd if=/dev/sdX of=nanddump.bin bs=1M skip=256 count=256

# Dump OOB (512MB-520MB)
dd if=/dev/sdX of=oobdump.bin bs=1M skip=512 count=8
```
*Replace `/dev/sdX` with your actual disk identifier*

#### Method B: Alternative Tools
- Use disk imaging software to extract specific sectors
- Use hex editors with sector extraction capabilities

### Step 4: Extract Files
```bash
extractfile.exe <nanddump.bin> <oobdump.bin>
```
Extracted files will be in:  
`.\extract_files\vfat\vfat000.vdk`

Mount `vfat000.vdk` as a FAT32 image or just open it with 7-zip to access your files.

## File System Structure

The original image uses YAFFS2 layout with the following OOB structure:

```c
#include <stdint.h>
#pragma pack(push, 1)

/**
 * Core Logic:
 * The file system uses OOB offset 22-23 Flags to determine interpretation:
 * - Flags & 0x8000 != 0: Header page (Metadata)
 * - Flags == 0: Data page (File Content)
 */

typedef struct {
    // Block Status
    uint8_t  bad_block_marker;      // 0x00: 0xFF = normal, 0x00 = ignore entire 128KB block
    uint8_t  status_byte;           // 0x01: 0xFE = Used/Good, 0xFF = Free
    
    // Version Control
    uint32_t sequence_number;       // 0x02-0x05: Block sequence number
    // Note: For same file/chunk in same block, use higher sequence number
    
    // Object ID
    uint16_t obj_id_low;            // 0x06-0x07: File ID lower 16 bits
    
    // ECC Regions
    uint8_t  ecc_sector_0[8];       // 0x08-0x0F (for Main Data 0-511)
    uint16_t reserved_padding;      // 0x10-0x11: Usually 0xFFFF
    
    // Reused Area (Critical!)
    union {
        // Header Page (Flags & 0x8000 != 0)
        struct {
            uint16_t obj_type;      // 0x12-0x13: 0x1000=File, 0x3000=Dir, 0x4000=SymLink
            uint16_t parent_id;     // 0x14-0x15: Parent directory Object ID
            uint16_t flags;         // 0x16-0x17: 0x8000 or 0xC000
        } header;
        
        // Data Page (Flags == 0)
        struct {
            uint16_t obj_id_high;   // 0x12-0x13: Usually 0
            uint16_t chunk_id;      // 0x14-0x15: File chunk index (1,2,3...)
            uint16_t flags_unused;  // 0x16-0x17: Usually 0x0000
        } data;
    } tags;
    
    uint8_t  ecc_sector_1[8];       // 0x18-0x1F (for Main Data 512-1023)
    uint16_t reserved_32_33;        // 0x20-0x21: Usually 0xFFFF
    
    // Size Information
    union {
        uint32_t file_size_low;     // Header: Actual file size in bytes
        uint32_t n_bytes;           // Data: Valid bytes in this page (usually 2048)
    } size_info;

    uint16_t reserved_38_39;        // 0x26-0x27 (Offset 38-39): Usually 0xFFFF

    uint8_t  ecc_sector_2[8];       // 0x28-0x2F (Offset 40-47)
    uint8_t  ecc_spare[8];          // 0x30-0x37 (Offset 48-55)
    uint8_t  ecc_sector_3[8];       // 0x38-0x3F (Offset 56-63)

} yaffs_custom_oob_t;

} YAFFS2_OOB;

#pragma pack(pop)
```


## ⚡ Troubleshooting

### Common Issues:
1. **Calculator not detected**: Ensure you're in recovery mode (reset + `Symb`)
2. **Drive size unchanged**: Re-run usbtool.exe update process
3. **Extraction errors**: Verify NAND/OOB dump sizes are correct

### Sequence Number Rules:
- Same file/chunk in same block → use later position
- Same file/chunk with different sequence numbers → error condition
- Higher sequence number indicates newer version

## Notes
- This tool is for educational and data recovery purposes
- Always backup original files before modification
- Report issues with detailed error messages
