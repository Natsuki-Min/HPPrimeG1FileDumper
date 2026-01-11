#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <direct.h>
    #define MKDIR(path) _mkdir(path)
    #define PATH_SEP '\\'
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #define MKDIR(path) mkdir(path, 0777)
    #define PATH_SEP '/'
#endif

// --- 配置参数 ---
#define PAGE_SIZE 2048
#define OOB_SIZE 64
#define BLOCK_PAGES 64
#define OUTPUT_DIR "extract_files"

// --- 内存数据库 ---
typedef struct {
    uint32_t page_addr;
    uint32_t seq_num;
    uint16_t obj_id;
    uint16_t chunk_id; 
    uint8_t  is_header;
    uint8_t  is_valid;
} page_info_t;

typedef struct {
    uint32_t header_page_addr; 
    uint32_t parent_id;
    uint32_t seq_num;
    uint16_t obj_type; // 1=File, 3=Dir
    char     name[256];
    uint8_t  exists;
} object_info_t;

#define MAX_PAGES 131072
#define MAX_OBJECTS 65536

page_info_t *page_db;
object_info_t *obj_db;

// --- 辅助函数 ---
// 恢复使用辅助函数以避免对齐问题，且代码更清晰
uint32_t read_u32_le(const uint8_t *p) {
    return p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24);
}
uint16_t read_u16_le(const uint8_t *p) {
    return p[0] | (p[1] << 8);
}

// 声明
void extract_recursive(FILE *fp_data, uint32_t current_id, const char *current_path);

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <nanddump.bin> <oobdump.bin>\n", argv[0]);
        return 1;
    }

    FILE *fp_data = fopen(argv[1], "rb");
    FILE *fp_oob  = fopen(argv[2], "rb");
    if (!fp_data || !fp_oob) { perror("Open failed"); return 1; }

    page_db = (page_info_t *)calloc(MAX_PAGES, sizeof(page_info_t));
    obj_db  = (object_info_t *)calloc(MAX_OBJECTS, sizeof(object_info_t));
    if (!page_db || !obj_db) { printf("Memory alloc failed\n"); return 1; }

    printf("Phase 1: Scanning NAND (Index building)...\n");

    uint8_t oob_raw[OOB_SIZE];
    uint8_t data_raw[PAGE_SIZE];
    long page_idx = 0;
    int valid_headers = 0;

    while (page_idx < MAX_PAGES) {
        // --- 1. 坏块过滤 ---
        if (page_idx % BLOCK_PAGES == 0) {
            fseek(fp_oob, page_idx * OOB_SIZE, SEEK_SET);
            fread(oob_raw, OOB_SIZE, 1, fp_oob);
            if (oob_raw[0] != 0xFF) {
                // printf("Skipping Bad Block at %ld\n", page_idx);
                page_idx += BLOCK_PAGES;
                continue;
            }
        }

        fseek(fp_oob, page_idx * OOB_SIZE, SEEK_SET);
        if (fread(oob_raw, OOB_SIZE, 1, fp_oob) != 1) break;

        // --- 2. 空页过滤 ---
        // 检查 ECC Spare Area (Offset 50-55)
        int is_empty = 1;
        for (int i = 50; i < 56; i++) {
            if (oob_raw[i] != 0xFF) { is_empty = 0; break; }
        }
        if (is_empty) {
            page_idx++;
            continue;
        }

        // --- 3. 解析 OOB ---
        // 依据之前的分析结果：
        uint32_t seq_num = read_u32_le(oob_raw + 2); // 0x02
        uint16_t obj_id  = read_u16_le(oob_raw + 6); // 0x06
        uint16_t flags   = read_u16_le(oob_raw + 22); // 0x16

        if (obj_id == 0xFFFF || obj_id == 0) { page_idx++; continue; }

        page_db[page_idx].page_addr = page_idx;
        page_db[page_idx].seq_num = seq_num;
        page_db[page_idx].obj_id = obj_id;
        page_db[page_idx].is_valid = 1;

        // --- 4. 判断类型 ---
        if ((flags & 0x8000) != 0) {
            // [HEADER PAGE]
            page_db[page_idx].is_header = 1;
            
            fseek(fp_data, page_idx * PAGE_SIZE, SEEK_SET);
            fread(data_raw, PAGE_SIZE, 1, fp_data);

            uint32_t type = read_u32_le(data_raw + 0);
            
            // 过滤无效 Header
            if (type != 1 && type != 3 && type != 4) {
                page_idx++; continue; 
            }

            int update_needed = 0;
            if (!obj_db[obj_id].exists) {
                update_needed = 1;
            } else {
                if (seq_num >= obj_db[obj_id].seq_num) {
                    // printf("  [Page %ld] Update Obj %d: Seq %d -> %d\n", page_idx, obj_id, obj_db[obj_id].seq_num, seq_num);
                    update_needed = 1;
                }
            }

            if (update_needed) {
                obj_db[obj_id].exists = 1;
                obj_db[obj_id].header_page_addr = page_idx;
                obj_db[obj_id].seq_num = seq_num;
                obj_db[obj_id].obj_type = (uint16_t)type;
                obj_db[obj_id].parent_id = read_u32_le(data_raw + 4);
                strncpy(obj_db[obj_id].name, (char*)(data_raw + 10), 255);
                valid_headers++; // 修复计数
            }

        } else {
            // [DATA PAGE]
            page_db[page_idx].is_header = 0;
            
            // *** 修正重点 ***
            // 你的日志证明 Offset 20 才有数据，18 是 0。
            // 不要改回 18！
            page_db[page_idx].chunk_id = read_u16_le(oob_raw + 20); 
        }
        page_idx++;
    }

    printf("Index built. Found %d valid headers.\n", valid_headers);

    // --- Phase 2: Extraction ---
    MKDIR(OUTPUT_DIR);
    
    if (obj_db[1].exists) {
        extract_recursive(fp_data, 1, OUTPUT_DIR);
    } else {
        printf("Root not found, extracting all orphans...\n");
        // 遍历所有对象
        extract_recursive(fp_data, 1, OUTPUT_DIR); // 尝试找 parent=1 的
    }

    free(page_db);
    free(obj_db);
    fclose(fp_data);
    fclose(fp_oob);
    return 0;
}

// 核心审计提取函数
void extract_file_audit(FILE *fp_data, uint32_t file_id, const char *path) {
    printf("\n=== Extracting File: %s (ObjID %d) ===\n", path, file_id);
    
    FILE *out = fopen(path, "wb");
    if (!out) { printf("  [ERR] Cannot create file.\n"); return; }

    // 1. 找出最大 Chunk ID
    int max_chunk = 0;
    for (long p = 0; p < MAX_PAGES; p++) {
        if (page_db[p].is_valid && !page_db[p].is_header && page_db[p].obj_id == file_id) {
            // 简单防错：Chunk ID 一般不会特别大
            if (page_db[p].chunk_id > max_chunk && page_db[p].chunk_id < 60000) {
                max_chunk = page_db[p].chunk_id;
            }
        }
    }
    printf("  Max Chunk ID found: %d (Approx Size: %d KB)\n", max_chunk, (max_chunk * 2));

    if (max_chunk == 0) {
        printf("  [WARN] No chunks found (Did you use correct Offset 20?)\n");
        fclose(out);
        return;
    }

    uint8_t buf[PAGE_SIZE];
    uint8_t padding[PAGE_SIZE];
    memset(padding, 0xFF, PAGE_SIZE);

    // 2. 逐个 Chunk 提取
    for (int c = 1; c <= max_chunk; c++) {
        long best_page = -1;
        uint32_t best_seq = 0;

        printf("  [Chunk %d] Candidates:\n", c);

        // 遍历寻找该 Chunk 的所有副本
        for (long p = 0; p < MAX_PAGES; p++) {
            if (page_db[p].is_valid && !page_db[p].is_header && 
                page_db[p].obj_id == file_id && page_db[p].chunk_id == c) {
                
                printf("    - Page %ld (Seq %u)", p, page_db[p].seq_num);

                int is_better = 0;
                if (best_page == -1) is_better = 1;
                else if (page_db[p].seq_num > best_seq) is_better = 1; // 选 Seq 更大的
                else if (page_db[p].seq_num == best_seq) {
                    // Seq 相同，选物理地址靠后的
                    is_better = 1;
                    printf(" [Newer Pos]");
                } else {
                    printf(" [Old]");
                }
                
                if (is_better) {
                    best_page = p;
                    best_seq = page_db[p].seq_num;
                    printf(" -> SELECTED\n");
                } else {
                    printf("\n");
                }
            }
        }

        if (best_page != -1) {
            fseek(fp_data, best_page * PAGE_SIZE, SEEK_SET);
            fread(buf, PAGE_SIZE, 1, fp_data);
            fwrite(buf, PAGE_SIZE, 1, out); // 写入 2KB 数据
        } else {
            printf("    [MISSING] Chunk %d lost! Padding 0xFF.\n", c);
            fwrite(padding, PAGE_SIZE, 1, out);
        }
    }

    fclose(out);
}

void extract_recursive(FILE *fp_data, uint32_t current_id, const char *current_path) {
    for (int i = 0; i < MAX_OBJECTS; i++) {
        if (!obj_db[i].exists) continue;
        if (obj_db[i].parent_id == current_id) {
            
            char safe_name[256];
            strncpy(safe_name, obj_db[i].name, 255);
            // 清洗文件名
            for(int k=0; safe_name[k]; k++) {
                if (safe_name[k] == '/' || safe_name[k] == '\\' || safe_name[k] == ':') safe_name[k] = '_';
            }
            if(strlen(safe_name) == 0) sprintf(safe_name, "OBJ_%d", i);

            char new_path[512];
            snprintf(new_path, sizeof(new_path), "%s%c%s", current_path, PATH_SEP, safe_name);

            if (obj_db[i].obj_type == 3) { // Dir
                MKDIR(new_path);
                extract_recursive(fp_data, i, new_path);
            } 
            else if (obj_db[i].obj_type == 1) { // File
                extract_file_audit(fp_data, i, new_path);
            }
        }
    }
}
