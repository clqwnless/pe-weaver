#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <distorm.h>

#include <inttypes.h>

// #include "Zydis/Zydis.h"


#define align_up(value, alignment) (((value) + (alignment) - 1) / (alignment)) * (alignment)
#define calc_va(nt, sec, offset) (nt)->OptionalHeader.ImageBase + (sec)->VirtualAddress + (offset)

#define calc_available_sections(free_space) (int)((free_space) / sizeof(IMAGE_SECTION_HEADER))

#define bits_to_bytes(nbits) (int)((nbits) / 8)


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
    uint8_t  dispSize;
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


Reloc reloc = {.units_len=0, .shifts_len=0};


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
    
    printf("here2\n");
    
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
    int res = insert_bytes(&pe->file, &pe->file_size, offset, data, data_len);
    
    if (!res)
        return res;
    
    RelocShift *s = &reloc.shifts[reloc.shifts_len];
    
    s->addr0 = offset;
    s->delta = data_len;

    

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
    r->dispSize   = dispSize;
    r->instOffset = instOffset;
    
    //printf("saved reloc, dispOffset=%d, dispSize=%d, instOffset=%d\n", r->dispOffset, r->dispSize, r->instOffset);
    
    reloc.units_len += 1;
}

/* loaders (init) */

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
    
    // dos (if needed)
    
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)file;
    
    
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        result = -3;
        goto cleanup;
    }
    
    // nt header
    
    IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(file + dos->e_lfanew);
    
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        result = -4;
        goto cleanup;
    }
    
    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    
    // initializing structure
    
    pe->dos       = dos;
    pe->nt        = nt;
    pe->sections  = sections;

    pe->file_alignment    = nt->OptionalHeader.FileAlignment;
    pe->section_alignment = nt->OptionalHeader.SectionAlignment;
    
    pe->file      = file;
    pe->file_size = file_size;
    
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


int add_section(PE *pe, const char *output, const char *name, const uint8_t *data, size_t data_size) {
    
    
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


    size_t new_file_size = new_raw + new_raw_size;
    unsigned char *new_file = calloc(1, new_file_size);
    if (!new_file)
        return 0;

    memcpy(new_file, pe->file, pe->file_size);
    memcpy(new_file + new_raw, data, data_size);

    FILE *out = fopen(output, "wb");
    if (!out) {
        free(new_file);
        return 0;
    }

    fwrite(new_file, 1, new_file_size, out);
    fclose(out);

    free(new_file);
    return 1;
}

void shift_insts(PE *pe)
{
    for (uint64_t i = 0; i < reloc.units_len; i++)
    {
       
        
        RelocUnit *r = &reloc.units[i];
       
        uint8_t dispBytes = bits_to_bytes(r->dispSize);
        
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
            
            //printf("    RIP: %llx -> %llx ; ", (unsigned long long)di->addr, (unsigned long long)target);
            
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
                //printf("    PC:  %llx -> %llx, di->imm.addr=%llx ; disp=%llx\n", (unsigned long long)di->addr, (unsigned long long)target, (unsigned long long)di->imm.addr, di->disp);
                
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



int main(void) {
    unsigned char payload[] = { 0x48, 0x31, 0xC0, 0xC3 };

    PE p1;
    PE *pe = &p1;
    
    int res;
    
    
    if ((res = load_pe("cmd.exe", &p1)) != 0)
    {
        fprintf(stderr, "err: load_pe, err_code=%d\n", res);
        return 1;
    }
    
    IMAGE_SECTION_HEADER *text = find_section(&p1, ".text");
    
    IMAGE_SECTION_HEADER *sec = find_section_by_faddr(pe, text->PointerToRawData);
    
    if (sec)
        printf("sec->Name: %s\n", sec->Name);
    else
        printf("sec not found");
    
    /*
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


