//
//  set1challenge5.c
//  cryptopals
//
//  Created by Bloomfield on 10/23/22.
//

#include "set1challenge5.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

uint8_t HexCharToInt(char x) {
    char alphabet[] = "0123456789abcdef";
    int n = 0;
    int y = -1;
    for (n = 0; n < 16; n++) {
        if ( alphabet[n] == x ) { y = n; }
    }
    assert( y >= 0 && y <= 15 );
    return y;
}

void challenge(void) {
    const char key[] = "ICE";
    const int key_len = 3;
    const char input[] = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    const char alphabet[] = "0123456789abcdef";
    char output[256] = "\0";
    
    for(int n = 0; n < strlen(input); n++) {
        uint8_t octet = input[n] ^ key[n % key_len];
        char msb = alphabet[ octet >> 4 ];
        char lsb = alphabet[ octet & 0b1111 ];
        strncat(output, &msb, 1);
        strncat(output, &lsb, 1);

    }
    printf("\n%s\n", output);
}
