#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define align_up(value, alignment) (((value) + (alignment) - 1) / (alignment)) * (alignment)
#define jmp_calc_rel32(target_addr, current_addr) (target_addr) - ((current_addr) + 5)

#define calc_va(nt, sec, offset) (nt)->OptionalHeader.ImageBase + (sec)->VirtualAddress + (offset)

#define calc_available_sections(free_space) (int)((free_space) / sizeof(IMAGE_SECTION_HEADER))

typedef unsigned char u8;

typedef struct {
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    
    DWORD file_alignment;
    DWORD section_alignment;
    
    u8 *file;
    long file_size;
    
    const char *path;
} PE;


IMAGE_SECTION_HEADER *find_section(IMAGE_SECTION_HEADER *sections, WORD section_count, const char *searched_name)
{
    for (int i = 0; i < section_count; i++)
    {
        IMAGE_SECTION_HEADER *s = &sections[i];
        
        if (strcmp(s->Name, searched_name) == 0)
            return s;
    }
    
    return NULL;
}

void print_sections(IMAGE_NT_HEADERS64 *nt, IMAGE_SECTION_HEADER *sections)
{
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER *s = &sections[i];
        printf("name=%s, RVA=%d, RAW=%d, size=%d\n", s->Name, s->VirtualAddress, s->PointerToRawData, s->SizeOfRawData);
    }
}

void print_sec(u8 *file, IMAGE_SECTION_HEADER *sec)
{
    u8 *start = &file[sec->PointerToRawData];
    u8 *end   = start + sec->SizeOfRawData;
    
    while (start < end)
    {
        printf("%c", *start);
        start++;
    }
}

long get_file_size(FILE *f)
{
    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    return file_size;
}

u8 *read_file(FILE *f, long file_size)
{
    u8 *file = malloc(file_size);
    
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
    u8 *file       = read_file(f, file_size);
    
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

size_t calc_sec_table_space(PE *pe)
{
    printf("here1\n");
    
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


int add_section(PE *pe, const char *output, const char *name, const unsigned char *data, size_t data_size) {
    
    
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



    new_section->VirtualAddress = new_rva;
    new_section->Misc.VirtualSize = new_virtual_size;
    new_section->PointerToRawData = new_raw;
    new_section->SizeOfRawData = new_raw_size;
    new_section->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ;

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

int main(void) {
    unsigned char payload[] = { 0x48, 0x31, 0xC0, 0xC3 };


    PE p1;
    int res;
    
    
    if ((res = load_pe("cmd.exe", &p1)) != 0)
    {
        fprintf(stderr, "err: load_pe, err_code=%d\n", res);
        return 1;
    }
    

    add_section(&p1, "patched.exe", ".patch", payload, sizeof(payload)); 
    

    

    printf("section added\n");
    return 0;
}
