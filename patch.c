#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <distorm.h>
#include <mnemonics.h>

#include <inttypes.h>

// #include "Zydis/Zydis.h"


#define align_up(value, alignment) (((value) + (alignment) - 1) / (alignment)) * (alignment)
#define calc_va(nt, sec, offset) (nt)->OptionalHeader.ImageBase + (sec)->VirtualAddress + (offset)

#define calc_available_sections(free_space) (int)((free_space) / sizeof(IMAGE_SECTION_HEADER))

#define bits_to_bytes(nbits) (int)((nbits) / 8)

#define NOP_OPCODE 0x90


typedef unsigned char uint8_t;

typedef struct {
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    
    DWORD file_alignment;
    DWORD section_alignment;
    
    uint8_t *file;
    long file_size;
    
    const char *path;
} PE;

typedef struct {
    uint8_t  dispOffset;
    uint8_t  dispBytes; // in bytes
    uint64_t instOffset; // instruction's offset in a file
} RelocUnit; // relocation unit



/*
example:

A: 0x1000
B: 0x1003
C: 0x1006

insert 3 bytes (addr0=0x1000, delta=3):

X: 0x1000
A: 0x1003
B: 0x1006
C: 0x1009

*/

typedef struct {
    uint64_t addr0;
    uint32_t delta; // in bytes
} RelocShift;

typedef struct {
    RelocUnit  units[100000];
    RelocShift shifts[1000];
    
    uint64_t units_len;
    uint64_t shifts_len;
} Reloc;

typedef struct {
    _DInst di;
    uint64_t instOffset;
} Instruction;



Reloc reloc = {.units_len=0, .shifts_len=0};


/* function prototypes */

IMAGE_SECTION_HEADER *find_section_by_faddr(PE *pe, int64_t faddr);

/* debug functions */

void print_sections(IMAGE_NT_HEADERS64 *nt, IMAGE_SECTION_HEADER *sections)
{
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER *s = &sections[i];
        printf("name=%s, RVA=%d, RAW=%d, size=%d\n", s->Name, s->VirtualAddress, s->PointerToRawData, s->SizeOfRawData);
    }
}

void print_sec(uint8_t *file, IMAGE_SECTION_HEADER *sec)
{
    uint8_t *start = &file[sec->PointerToRawData];
    uint8_t *end   = start + sec->SizeOfRawData;
    
    while (start < end)
    {
        printf("%c", *start);
        start++;
    }
}

void test_disp_hex(uint64_t disp, uint64_t dispSize)
{
    uint8_t dispBytes = bits_to_bytes(dispSize);
    
    
    uint8_t temp[dispBytes];
    memcpy(temp, &disp, dispBytes);
    
    printf(" disp: ");
    for (int i = 0; i < dispBytes; i++)
    {
        printf("%02X ", temp[i]);
    }
    
    printf("\n");
}

/* file api */

long get_file_size(FILE *f)
{
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    return file_size;
}

uint8_t *read_file(FILE *f, long file_size)
{
    uint8_t *file = malloc(file_size);
    
    if (!file) {
        fclose(f);
        return NULL;
    }

    if (fread(file, 1, file_size, f) != (size_t)file_size) {
        free(file);
        fclose(f);
        return NULL;
    }
    fclose(f);
    
    return file;
}

int save_pe(PE *pe, const uint8_t *output)
{
    FILE *f = fopen(output, "wb");
    
    if (!f)
        return -1;
    
    int res = fwrite(pe->file, 1, pe->file_size, f);
    
    if (!res)
    {
        fclose(f);
        return -2;
    }
    
    fclose(f);
    
    return 0;
}

/* pe helpers */

size_t calc_sec_table_space(PE *pe)
{
    WORD section_count = pe->nt->FileHeader.NumberOfSections;
    
    // (sections - file) высчитывает фактически оффсет в файле у начала sections
    // потом берем и добавляем к этому байты всех существующих секций (section_count * sizeof(struct ...))
    // и потом из абсолютного оффсета (PointerToRawData) (он именно в файле ; если бы мы не сделали минус file то там мы работали с адресом в памяти на runtime, что ненужно фактически)
    // вычитаем section_table_end (оффсет конца table)
     
    size_t section_table_end = (size_t)((unsigned char *)pe->sections - pe->file) + section_count * sizeof(IMAGE_SECTION_HEADER);
    size_t first_section_raw = pe->sections[0].PointerToRawData;
    size_t free_space = first_section_raw - section_table_end;

    /*
    printf("section table end: 0x%zx\n", section_table_end);
    printf("first section raw: 0x%zx\n", first_section_raw);
    printf("free space:        0x%zx\n", free_space);
    */

    return free_space;
}

int64_t map_address(int64_t old)
{
    /*
    example:
    
    old=0x1005
    
    shift:
    
    addr0 = 0x1000
    len   = 3
    
    */
    
    int64_t result = old;
    
    for (uint64_t i = 0; i < reloc.shifts_len; ++i)
    {
        RelocShift shift = reloc.shifts[i];
        
        //printf(
        //    "shift.delta=%" PRIu32 "\n", shift.delta
        //);
        
        
        
        if (old >= shift.addr0)
            result += shift.delta;
    }
    
    return result;
}

int insert_bytes(
    unsigned char **buf,
    long int *len,
    size_t pos,
    const uint8_t *data,
    size_t data_len
) {
    if (pos > *len)
        return -1;

    unsigned char *new_buf =
        calloc(1, *len + data_len);

    if (!new_buf)
        return -2;

    // before pos
    
    memcpy(new_buf, *buf, pos);

    // after pos (inserting the string)

    memcpy(new_buf + pos, data, data_len);

    // after data

    memcpy(
        new_buf + pos + data_len,
        *buf + pos,
        *len - pos
    );

    free(*buf);

    *buf = new_buf;
    *len += data_len;

    return 1;
}

int insert_insts(PE *pe, size_t offset, const uint8_t *data, size_t data_len)
{
    IMAGE_SECTION_HEADER *section = find_section_by_faddr(pe, offset);
    
    if (section == NULL)
        return -1;
    
    int res = insert_bytes(&pe->file, &pe->file_size, offset, data, data_len);
    
    if (!res)
        return res;
    
    RelocShift *s = &reloc.shifts[reloc.shifts_len];
    
    s->addr0 = offset;
    s->delta = data_len;
    
    
    /*
    DWORD new_virtual_size = section->Misc.VirtualSize + data_len;
    DWORD new_raw_size     = align_up(section->SizeOfRawData + data_len, file_alignment);
    
    if (new_raw_size != section->SizeOfRawData)
    {
        // calloc(...)
    }
    */

    /*
    printf(
        "insert: len_data=%d, s->addr0=%" PRIu64 ", s->delta=%" PRIu32 "\n",
        data_len,
        s->addr0,
        s->delta
    );
    */

    reloc.shifts_len += 1;
    
    return 0;
}

void append_reloc_unit(uint8_t instSize, uint8_t dispSize, uint64_t instOffset)
{
    RelocUnit *r = &reloc.units[reloc.units_len];
    
    r->dispOffset = instSize - bits_to_bytes(dispSize);
    r->dispBytes  = bits_to_bytes(dispSize);
    r->instOffset = instOffset;
    
    //printf("saved reloc, dispOffset=%d, dispSize=%d, instOffset=%d\n", r->dispOffset, r->dispSize, r->instOffset);
    
    reloc.units_len += 1;
}

/* loaders (init) */

int init_pe(PE *pe, uint8_t *file, long file_size)
{
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file;
    
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return -3;
    
    // nt header
    
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
        return -4;
    
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    
    // initializing structure
    
    pe->dos       = dos;
    pe->nt        = nt;
    pe->sections  = sections;

    pe->file_alignment    = nt->OptionalHeader.FileAlignment;
    pe->section_alignment = nt->OptionalHeader.SectionAlignment;
    
    pe->file      = file;
    pe->file_size = file_size;
    
    return 0;
}

int load_pe(const char *path, PE *pe)
{
    FILE *f        = fopen(path, "rb");
    
    int result;
    
    if (!f)
    {
        result = -1;
        goto cleanup;
    }
    

    long file_size = get_file_size(f);    
    uint8_t *file       = read_file(f, file_size);
    
    if (!file)
    {
        result = -2;
        goto cleanup;
    }
    
    result = init_pe(pe, file, file_size);
    
    if (result != 0)
        goto cleanup;
    
    pe->path      = path;
    
    result = 0;

    fclose(f);
    return 0; // yes it's annoying i know

cleanup:
    free(file);
    fclose(f);
    
    return result;
}

/* main pe api */

IMAGE_SECTION_HEADER *find_section(PE *pe, const char *searched_name)
{
    printf("find_section, ");
    printf("num of sections: %d\n", pe->nt->FileHeader.NumberOfSections);
    
    for (int i = 0; i < pe->nt->FileHeader.NumberOfSections; i++)
    {
        
        IMAGE_SECTION_HEADER *s = &pe->sections[i];
        
        if (strcmp(s->Name, searched_name) == 0)
            return s;
    }
    
    return NULL;
}

IMAGE_SECTION_HEADER *find_section_by_faddr(PE *pe, int64_t faddr)
{
    /* faddr = file address */
    
    for (WORD i = 0; i < pe->nt->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER *s = &pe->sections[i];
        
        if (faddr >= s->PointerToRawData)
        {
            return s;
        }
    }
    
    return NULL;
}


DWORD get_next_raw_offset(PE *pe)
{
    WORD section_count         = pe->nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *last = &pe->sections[section_count - 1];
    
    DWORD new_raw          = align_up(last->PointerToRawData + last->SizeOfRawData, pe->file_alignment);
    
    return new_raw;
}

int add_section(PE *pe, const char *name, const uint8_t *data, size_t data_size) {
    WORD section_count         = pe->nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *last = &pe->sections[section_count - 1];

    size_t free_space = calc_sec_table_space(pe);
    
    if (calc_available_sections(free_space) < 1)
        return -1;

    // aligning file & virtual addresses ; filling the gap with 0x00 in file

    DWORD new_raw          = align_up(last->PointerToRawData + last->SizeOfRawData, pe->file_alignment);
    DWORD new_rva          = align_up(last->VirtualAddress + last->Misc.VirtualSize, pe->section_alignment);
    DWORD new_raw_size     = align_up(data_size, pe->file_alignment);
    DWORD new_virtual_size = (DWORD)data_size;

    // creating new section

    IMAGE_SECTION_HEADER *new_section = &pe->sections[section_count];

    memset(new_section, 0, sizeof(IMAGE_SECTION_HEADER));
    memcpy(new_section->Name, name, strlen(name) > IMAGE_SIZEOF_SHORT_NAME ? IMAGE_SIZEOF_SHORT_NAME : strlen(name));

    new_section->VirtualAddress   = new_rva;
    new_section->Misc.VirtualSize = new_virtual_size;
    new_section->PointerToRawData = new_raw;
    new_section->SizeOfRawData    = new_raw_size;
    new_section->Characteristics  = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

    pe->nt->FileHeader.NumberOfSections++;
    pe->nt->OptionalHeader.SizeOfImage = align_up(new_rva + new_virtual_size, pe->section_alignment);


    size_t new_file_size    = new_raw + new_raw_size;
    unsigned char *new_file = calloc(1, new_file_size);
    if (!new_file)
        return -1;
    
    memcpy(new_file, pe->file, pe->file_size);
    memcpy(new_file + new_raw, data, data_size);

    free(pe->file);
    
    //pe->file = new_file;
    //pe->file_size = new_file_size;
    
    /* reinitializing because the pe->file was changed and that means that the pe->nt and ... pointers point to freed memory */
    
    init_pe(pe, new_file, new_file_size);
    
    return 0;
}

void shift_insts(PE *pe)
{
    for (uint64_t i = 0; i < reloc.units_len; i++)
    {
       
        
        RelocUnit *r = &reloc.units[i];
       
        uint8_t dispBytes = r->dispBytes;
        
        if (dispBytes == 0)
            continue;
       
        // calculating mapped instruction offset
        
        int64_t mappedInstOffset = map_address(r->instOffset);
        
        //printf("r->instOffset: %" PRIi64 " mappedInstOffset: %" PRIi64 " dispbytes=%d" "\n", r->instOffset, mappedInstOffset, dispBytes);
        
        // calculating the pointer to the beginnning of the displacement (rel32, rel8, ...)
        
        uint8_t *disp0 = pe->file + mappedInstOffset + r->dispOffset;
        
        // getting old displacement
        
        int64_t oldDisp;
        //memcpy(&oldDisp, disp0, dispBytes);

        if (dispBytes == 1)
            oldDisp = *(int8_t*)disp0;
        else if (dispBytes == 4)
            oldDisp = *(int32_t*)disp0;
        else if (dispBytes == 8)
            oldDisp = *(int64_t*)disp0;
        
        /*
        for (unsigned int i = 0; i < dispBytes; i++)
        {
            printf("%02X ", disp0[i]);
        }
        */
        



        // getting old target

        int64_t oldInstEnd = r->instOffset + r->dispOffset + dispBytes;
        int64_t oldTarget  = oldInstEnd + oldDisp;
        
        // getting newTarget
        
        int64_t newTarget  = map_address(oldTarget);
        
        // calculating new displacement
        
        int64_t newInstEnd = mappedInstOffset + r->dispOffset + dispBytes;
        int64_t newDisp    = newTarget - newInstEnd;
        
        // apply changes (replace old dipslacement with a new displacement)
        
        memcpy(disp0, &newDisp, dispBytes);
        
        printf("oldTarget=%" PRIi64 ", newTarget=%" PRIi64 ", oldDisp=%" PRIi64 ", newDisp=% " PRIi64 "\n", oldTarget, newTarget, oldDisp, newDisp);
        
    }
    
}

void shift_sections(PE *pe)
{
    WORD section_count = pe->nt->FileHeader.NumberOfSections;
    
    for (WORD i = 0; i < section_count; i++)
    {
        IMAGE_SECTION_HEADER *section = &pe->sections[i];
        
        
        
    }
}

void collect_reloc_info(PE *pe, IMAGE_SECTION_HEADER *sec)
{
    size_t offset = sec->PointerToRawData;
    size_t end    = offset + sec->SizeOfRawData;

    ULONGLONG ImageBase = pe->nt->OptionalHeader.ImageBase;

    _DInst insts[1];
    
    uint32_t count;
    
    _CodeInfo ci = {0};

    while (offset < end)
    {

        ci.codeOffset = ImageBase + offset;
        ci.code       = pe->file + offset;
        ci.codeLen    = (int)(end - offset);
        ci.dt         = Decode64Bits;
        ci.features   = DF_NONE;

        _DecodeResult r = distorm_decompose64(&ci, insts, 1, &count);

        if (count == 0) // err
            break;

        _DInst *di = &insts[0];
        
        if (di->flags & FLAG_RIP_RELATIVE) {
            uint64_t target = INSTRUCTION_GET_RIP_TARGET(di);
            
            // printf("    RIP: opcode=%hu, %llx -> %llx\n", di->opcode, (unsigned long long)di->addr, (unsigned long long)target);
            
            
            /*
            if (di->opcode == I_JMP)
            {
                printf("I_JMP, dispSize=%zu, %llx -> %llx\n", di->dispSize, (uint64_t)di->addr, (uint64_t)target);
            }
            */
            
            
            //printf("offset=%d, di->size: %d ", offset, di->size);
            //test_disp_hex(di->disp, di->dispSize);
            
            
            append_reloc_unit(di->size, di->dispSize, offset);
        }

        for (unsigned int j = 0; j < di->opsNo; j++)
        {
            _Operand *op = &di->ops[j];

            if (op->type == O_PC)
            {
                uint64_t target = INSTRUCTION_GET_TARGET(di);
                // printf("    PC:  %lld -> %lld, di->imm.addr=%lld ; disp=%lld, dispSize=%d\n", (unsigned long long)di->addr, (unsigned long long)target, (unsigned long long)di->imm.addr, di->disp, di->dispSize);
                
                append_reloc_unit(di->size, di->dispSize, offset);
            }
            
            /*
            if (op->type == O_PTR)
            {
                printf("    PTR: segment=%x offset=%x\n", di->imm.ptr.seg, di->imm.ptr.off);
            }
            */
        }

        offset += di->size;
    }
}


/* _InstructionType from mnemonics.h */
RelocUnit *find_riprel_inst(PE *pe, IMAGE_SECTION_HEADER *sec, uint8_t dispSizeBytes, _InstructionType opcode)
{
    size_t offset = sec->PointerToRawData;
    size_t end    = offset + sec->SizeOfRawData;

    ULONGLONG ImageBase = pe->nt->OptionalHeader.ImageBase;

    _DInst insts[1];
    
    uint32_t count;
    
    _CodeInfo ci = {0};
    
    while (offset < end)
    {

        ci.codeOffset = ImageBase + offset;
        ci.code       = pe->file + offset;
        ci.codeLen    = (int)(end - offset);
        ci.dt         = Decode64Bits;
        ci.features   = DF_NONE;
        
        _DecodeResult r = distorm_decompose64(&ci, insts, 1, &count);

        if (count == 0) // err
            break;

        _DInst *di = &insts[0];
        
        
        /* switch bits to bytes (dispSize is either 8 or 32) */
        
        uint8_t dispBytes = bits_to_bytes(di->dispSize);
        
        if (di->flags & FLAG_RIP_RELATIVE && di->opcode == opcode && dispSizeBytes == dispBytes)
        {
            
            
            RelocUnit *r = malloc(sizeof(RelocUnit));
            
            if (r == NULL)
                return NULL;
            
            r->dispOffset = di->size - dispBytes;
            r->dispBytes  = dispBytes;
            r->instOffset = offset;
            
            return r;
        }
        
        offset += di->size;
    }
    
    return NULL;
}

uint32_t calc_code_entrypoint(PE *pe)
{
    IMAGE_SECTION_HEADER *text = find_section(pe, ".text");
    
    if (text == NULL)
        return 0;
    
    uint32_t text_offset = pe->nt->OptionalHeader.AddressOfEntryPoint - text->VirtualAddress;
    
    return text->PointerToRawData + text_offset;
}

uint8_t p2_capture_instructions(
    PE *pe,
    size_t offset,
    size_t patch_inst_size,
    
    Instruction *insts_buffer,
    size_t buffer_size
) {
    IMAGE_SECTION_HEADER *text = find_section(pe, ".text");
    
    if (text == NULL)
        return -1;
    
    size_t end      = offset + text->SizeOfRawData;
    uint32_t count  = 0;
    
    size_t instBytesCount = 0;
    
    uint8_t i = 0;
    
    ULONGLONG ImageBase = pe->nt->OptionalHeader.ImageBase;

    _DInst insts[1];
    _CodeInfo ci = {0};
    
    while (offset < end && instBytesCount < patch_inst_size && i < buffer_size)
    {
        
        
        ci.codeOffset = ImageBase + offset;
        ci.code       = pe->file + offset;
        ci.codeLen    = (int)(end - offset);
        ci.dt         = Decode64Bits;
        ci.features   = DF_NONE;
        
        _DecodeResult r = distorm_decompose64(&ci, insts, 1, &count);

        if (count == 0) // err
            break;

        _DInst *di = &insts[0];

        //printf("cycle, i=%d, di->opcode: %d, size=%d\n", i, di->opcode, di->size);

        Instruction *inst = &insts_buffer[i];

        inst->di = *di;
        inst->instOffset = offset;
        
        /* increment */
        
        offset += di->size;
        instBytesCount += di->size;
        i++;
    }
    
    return i;
}




int patch(PE *pe, const char *new_sec_name, const uint8_t *data, size_t data_size)
{
    uint8_t ret_code = 0;
    
    IMAGE_SECTION_HEADER *text       = find_section(pe, ".text");    
    RelocUnit *p                     = find_riprel_inst(pe, text, 4, I_JMP);
    
    uint8_t *new_data = NULL;
    int ret;
    
    if (text == NULL)
    {
        ret_code = -1;
        goto cleanup;
    }
    
    if (p == NULL)
    {
        ret_code = -2;
        goto cleanup;
    }
    
    /* make copy of the source instruction */
    
    uint8_t inst[16];
    uint8_t instSize = p->dispOffset + p->dispBytes;
    
    memcpy(inst, (pe->file + p->instOffset), instSize);
    
    /* change the relative address in the source instruction so that the instruction refers to the correct address being in a new section */
    
    /* reading as int32_t (4 bytes) */
    
    DWORD section_raw_offset = get_next_raw_offset(pe);
    
    int32_t rel       = *(int32_t*)(pe->file + p->instOffset + p->dispOffset);
    int64_t oldTarget = (p->instOffset + instSize) + rel;
    
    printf("old_target: %d\n", oldTarget);
    
    int32_t newRel    = oldTarget - (section_raw_offset + instSize);
    
    // write the new relative-address to the copied instruction (which is inserted in the data)
    
    memcpy(inst + p->dispOffset, &newRel, sizeof(newRel));

    /* add source instruction to the data (instruction which is patched) */
    
    new_data = malloc(data_size + instSize);
    
    if (new_data == NULL)
    {
        ret_code = -3;
        goto cleanup;
    }
    
    memcpy(new_data, inst, instSize);
    memcpy(new_data + instSize, data, data_size);
    
    size_t new_data_size = data_size + instSize;
    
    /* create new section with this data */
    
    ret = add_section(pe, new_sec_name, new_data, new_data_size);
    // ret = add_section(pe, new_sec_name, data, data_size);
    
    if (ret != 0)
    {
        ret_code = -4;
        goto cleanup;
    }
    
    /* the patch itself */
    
    int32_t patch_riprel = section_raw_offset - (p->instOffset + instSize);
    
    memcpy((pe->file + p->instOffset + p->dispOffset), &patch_riprel, sizeof(patch_riprel));
    
    
    /* test */
    
    /*
    int32_t rell    = *(int32_t*)(pe->file + p->instOffset + p->dispOffset);
    int32_t targett = p->instOffset + p->dispOffset + p->dispBytes + rell;
    
    printf("target: %d\n", targett);
    */
    
    int32_t rell    = *(int32_t*)(inst + p->dispOffset);
    int32_t targett = section_raw_offset + p->dispOffset + p->dispBytes + rell;
    
    printf("rel: %d, section_raw_offset: %d, target: %d\n", rell, section_raw_offset, targett);
    
cleanup:
    
    free(new_data);
    free(p);
    
    return ret_code;
}

int second_patch(PE *pe, const char *new_sec_name, const uint8_t *data, size_t data_size)
{
    Instruction insts_buffer[8];
    uint8_t patch_inst_buffer[5] = {0xE9, 0x00, 0x00, 0x00, 0x00}; // jmp rel32
    
    IMAGE_SECTION_HEADER *text = find_section(pe, ".text");
    
    /* check for errors and calc insts_bytes_size */
    
    uint32_t entrypoint = calc_code_entrypoint(pe);
    
    printf("entrypoint: %u\n", entrypoint);
    
    uint8_t  patch_inst_num = p2_capture_instructions(pe, entrypoint, sizeof(patch_inst_buffer), insts_buffer, sizeof(insts_buffer));
    uint16_t insts_bytes_size = 0;
    
    printf("patch_inst_num: %u\n", patch_inst_num);
    
    for (uint8_t i = 0; i < patch_inst_num; i++)
    {
        Instruction *instruction = &insts_buffer[i];
        _DInst *di = &instruction->di;
        
        //printf("di->opcode: %d, di->dispSize: %d, di->opsNo: %d\n", di->opcode, di->dispSize, di->opsNo);
        
        if (di->flags & FLAG_RIP_RELATIVE)
        {
            fprintf(stderr, "rip-relative instructions at the beginning of the .text section are not supported\n");
            return -1;
        }
        
        
        for (uint8_t j = 0; j < di->opsNo; j++)
        {
            if (di->ops[j].type == O_PC)
            {
                fprintf(stderr, "O_PC instructions at the beginning of the .text section are not supported\n");
                return -2;
            }
        }
        
        
        insts_bytes_size += di->size;
    }
    
    printf("insts_bytes_size: %u\n", insts_bytes_size);
    
    /* copy the source data (inserted then to the new section) */
    
    size_t  new_section_data_size = data_size + insts_bytes_size + sizeof(patch_inst_buffer);
    uint8_t *new_section_data     = malloc(new_section_data_size);
    
    if (new_section_data == NULL)
        return -3;
    
    // copy data
    memcpy(new_section_data, data, data_size);
    
    // copy insts from the source
    memcpy(new_section_data + data_size, pe->file + insts_buffer[0].instOffset, insts_bytes_size);
    
    // copy jmp instruction in order to return to the .text section
    
    uint64_t target = entrypoint + sizeof(patch_inst_buffer); // afterPatchInstAddr
    int32_t  rel    = target - (get_next_raw_offset(pe) + data_size + insts_bytes_size + sizeof(patch_inst_buffer));
    
    printf(".patch to .text: target=%lld, rel=%d\n", target, rel);
    
    // +1 because of the dispOffset (displacement-offset)
    memcpy(patch_inst_buffer + 1, &rel, sizeof(rel));
    
    /*
    printf(".patch to .text patch_buffer: ");
    for (int i = 0; i < sizeof(patch_inst_buffer); i++)
        printf("%02X ", patch_inst_buffer[i]);
    printf("\n");
    printf("backwards: %d\n", *(int32_t*)(patch_inst_buffer + 1));
    */
    
    // copy the instruction itself
    
    memcpy(new_section_data + data_size + insts_bytes_size, patch_inst_buffer, sizeof(patch_inst_buffer));
    
    
    // patch in the .text
    
    // calc rel32 (and create a jmp instruction)
    
    target = get_next_raw_offset(pe);
    rel    = target - (entrypoint + sizeof(patch_inst_buffer));
    
    printf(".text to .patch: target=%lld, rel=%d\n", target, rel);
    
    memcpy(patch_inst_buffer + 1, &rel, sizeof(rel));
    
    /* 
       copy the jmp-instruction
       and if (insts_bytes_size > sizeof(patch_inst_buffer))
       fill this space with nops (0x90 on x86/x64)
    */
    
    
    for (uint16_t i = 0; i < insts_bytes_size; i++)
        pe->file[entrypoint + i] = NOP_OPCODE;
    memcpy(pe->file + entrypoint, patch_inst_buffer, sizeof(patch_inst_buffer));
    
    /*
    printf("\nentrypoint (text): ");
    
    for (int i = 0; i < insts_bytes_size; i++)
    {
        printf("%02X ", pe->file[entrypoint + i]);
    }
    
    printf("\n");
    */
    
    
    
    
    
    printf("dnum of sections: %d\n", pe->nt->FileHeader.NumberOfSections);
    
    add_section(pe, new_sec_name, new_section_data, new_section_data_size);

    /* test .text jmp */
    
    /*
    int32_t rel_test = *(int32_t*)(pe->file + entrypoint + 1);
    uint64_t target_test = entrypoint + sizeof(patch_inst_buffer) + rel_test;
    
    printf("rel_test: %d, target_test: %llu\n", rel_test, target_test);
    printf("target test: ");

    for (int i = 0; i < new_section_data_size; i++)
    {
        printf("%02X ", pe->file[target_test + i]);
    }

    printf("\n");
    */

    /* test .patch jmp */
    
    IMAGE_SECTION_HEADER *sec = find_section(pe, new_sec_name);
    if (sec == NULL)
        printf("sec is null\n");
    
    //printf("sec->name: %s\n", sec->Name);
    
    
    //int32_t rel_test = *(int32_t*)(pe->file + sec->PointerToRawData + new_section_data_size - sizeof(patch_inst_buffer));
    
    //printf("rel_test: %d\n", rel_test);
    
    //int32_t rel_test = *(int32_t*)(pe->file + new_section_data + data_size + insts_bytes_size + 1);
    //uint64_t target_test = () + rel_test;
    
    //printf("rel_test: %d, target_test\n", rel_test, target_test);
    
    
    
    
    



cleanup:

    free(new_section_data);
    return 0;
}


/* clean efi certifiace and sections so that you can add another sections to the pe */

int clean_efi_cert(PE *pe)
{
    IMAGE_DATA_DIRECTORY *cert = &pe->nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
    
    /* docs say: virtual address is file offset here */
    DWORD va = cert->VirtualAddress;
    
    cert->VirtualAddress = 0;
    cert->Size = 0;
    
    pe->file_size = va;
    
    pe->nt->OptionalHeader.SizeOfImage = pe->file_size;
    
    // printf("va: %u\n", va);
}


int main(void) {
    //unsigned char payload[] = {0xEB, 0xFE};
    unsigned char payload[] = {NOP_OPCODE};

    PE p1;
    PE *pe = &p1;
    
    int ret;
    
    
    if ((ret = load_pe("cmd.exe", &p1)) != 0)
    {
        fprintf(stderr, "err: load_pe, err_code=%d\n", ret);
        return 1;
    }
    
    printf("after load_pe\n");
    
    /*
    ret = patch(&p1, ".patch", payload, sizeof(payload));
    printf("patch ret: %d\n", ret);
    */
    
    //printf("faddr entrypoint: %u\n", calc_file_entry_point(pe));
    
    //clean_efi_cert(pe);
    
    printf("num of sections: %d\n", pe->nt->FileHeader.NumberOfSections);
    add_section(pe, ".patch", payload, sizeof(payload));
    printf("num of sections: %d\n", pe->nt->FileHeader.NumberOfSections);
    
    
    //second_patch(pe, ".patch", payload, sizeof(payload));
    
    
    save_pe(pe, "output.exe");

    //IMAGE_SECTION_HEADER *text = find_section(pe, ".text");    
    //collect_reloc_info(pe, text);

    
    /*
    IMAGE_SECTION_HEADER *text = find_section(&p1, ".text");    
    collect_reloc_info(pe, text);
    
    uint8_t data[2] = {0x89, 0xC0}; // nops
    res = insert_insts(pe, text->PointerToRawData, data, sizeof(data));    
    
    //printf("insert_insts res=%d, shifts_len=%d\n", res, reloc.shifts_len);
    
    shift_insts(pe);
    */
   
    //res = save_pe(pe, "output.exe");
    //printf("res: %d\n", res);
    
    //printf("units_len=%llu\n", reloc.units_len);
    // add_section(&p1, "patched.exe", ".patch", payload, sizeof(payload)); 
    

    

    //printf("section added\n");
    return 0;
}


