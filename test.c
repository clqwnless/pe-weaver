#include <stdio.h>
#include <stdint.h>
#include <distorm.h>

int main(void)
{
    const uint8_t code[] = {
        0x48, 0x89, 0xD8,       // mov rax, rbx
        0x48, 0x83, 0xC0, 0x01  // add rax, 1
    };

    _DecodeResult result;
    _DecodedInst instructions[16];

    unsigned int count = 16;

    result = distorm_decode64(
        0x1000,
        code,
        sizeof(code),
        Decode64Bits,
        instructions,
        count,
        &count
    );

    if (result == DECRES_INPUTERR)
    {
        printf("Decode error\n");
        return 1;
    }

    for (unsigned int i = 0; i < count; i++)
    {
        printf(
            "0x%llx  size=%u  %s %s\n",
            (unsigned long long)instructions[i].offset,
            instructions[i].size,
            instructions[i].mnemonic.p,
            instructions[i].operands.p
        );
    }

    return 0;
}