//
//  set1challenge3.c
//  cryptopals
//
//  Created by Bloomfield on 10/22/22.
//

#include "set1challenge3.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>

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

float Evaluate(char *s) {
    char x[128] = "";
    char alphabet[] = "etroianscl";
    float frequency[] = {0.124, 0.090, 0.080, 0.079, 0.075, 0.073, 0.066, 0.060, 0.040, 0.038};
    float out[10] = {0};
    assert( strlen(alphabet) == sizeof(frequency)/sizeof(frequency[0]) );
    memcpy(x, s, strlen(s));
    
    for( int n = 0; n < strlen(x); n++) { x[n] = tolower(x[n]); }
    for( int n = 0; n < strlen(alphabet); n++) {
        float count = 0;
        for( int m = 0; m < strlen(x); m++) {
            if( x[m] == alphabet[n] ) count++;
        }
        out[n] = count / (float) strlen(x);
    }
    
    float sum = 0;
    for( int n = 0; n < strlen(alphabet); n++) {
        sum += out[n] * frequency[n];
    }
    return sum;
}

void challenge(void) {
    
    char input[] = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    int cyphertext[34] = {0};
    char plaintext[34] = "";
    
    assert(strlen(input) % 2 == 0);
    
    for(int key = 0; key <= 255; key++) {
        for(int n = 0; n < strlen(input)-1; n+=2) {
            cyphertext[n/2] = HexCharToInt(input[n+1]) + ( HexCharToInt(input[n]) << 4 );
            plaintext[n/2] = key ^ cyphertext[n/2];
        }
        
        printf("Key %d | Score %.3f | %s\n\n", key, Evaluate(plaintext), plaintext);
    }
}

