//
//  set1challenge1.c
//  cryptopals
//
//  Created by Bloomfield on 10/22/22.
//

#include "set1challenge2.h"
#include <string.h>
#include <assert.h>
#include <stdlib.h>

unsigned int HexCharToInt(char x) {
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
    char str_a[] = "1c0111001f010100061a024b53535009181c";
    char str_b[] = "686974207468652062756c6c277320657965";
    char alphabet[] = "0123456789abcdef";
    char *out = (char*) malloc( sizeof(str_a) /  sizeof(str_a[0] ) );
    int idx;
    
    for( int n = 0; n < strlen(str_a); n++ ) {
        idx = HexCharToInt(str_a[n]) ^ HexCharToInt(str_b[n]);
        out[n] = alphabet[idx];
    }
    
    printf("Result is %s.",  out);
    free(out);
    
}
