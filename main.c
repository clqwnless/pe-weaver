#include <stdio.h>
#include <stdint.h>
#include "Zydis.h"



// calc relative virtual address (relative to the jmp instruction)
#define jmp_calc_rel32(target_addr, current_addr) (target_addr) - ((current_addr) + 5)

// calc virtual address (basically absolute address)
#define calc_va(nt, sec, offset) (nt)->OptionalHeader.ImageBase + (sec)->VirtualAddress + (offset)

int main(void)
{
    
    
    
    return 0;
    
    
    uint8_t code[] = {
        0x48, 0x83, 0xEC, 0x28,
        0x48, 0x8B, 0x05, 0x95, 0x00, 0x00, 0x00,
        0x48, 0x85, 0xC0,
        0x74, 0x05
    };

    ZydisDecoder   decoder;
    ZydisFormatter formatter;

    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64)))
        return 1;

    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL)))
        return 1;

    size_t offset = 0;
    size_t size   = sizeof(code);

    while (offset < size)
    {
        ZydisDecodedInstruction instruction;

        ZyanStatus status = ZydisDecoderDecodeInstruction(
            &decoder,
            NULL, // context
            code + offset, // buffer (const void *)
            size - offset, // length of the buffer
            &instruction
        );

        if (!ZYAN_SUCCESS(status))
        {
            printf("Decode error at offset 0x%zx\n", offset);
            break;
        }



        
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        status = ZydisDecoderDecodeFull(
            &decoder,
            code + offset, // buffer
            size - offset, // length
            &instruction,
            operands
        );

        if (!ZYAN_SUCCESS(status))
        {
            printf("Operand decode error at offset 0x%zx\n", offset);
            break;
        }
        
        /*
        char text[256];

        status = ZydisFormatterFormatInstruction(
            &formatter,
            &instruction,
            operands,
            instruction.operand_count_visible,
            text,
            sizeof(text),
            (ZyanU64)offset,
            NULL
        );

        if (!ZYAN_SUCCESS(status))
        {
            printf("Format error at offset 0x%zx\n", offset);
            break;
        }

        printf("%04zx  ", offset);

        for (unsigned int i = 0; i < instruction.length; i++)
            printf("%02X ", code[offset + i]);

        for (unsigned int i = instruction.length; i < 12; i++)
            printf("   ");

        printf(" %s\n", text);
        */

        offset += instruction.length;
    }

    return 0;
}