//
//  set1challenge1.c
//  cryptopals
//
//  Created by Bloomfield on 10/22/22.
//

#include "set1challenge1.h"
#include <string.h>
#include <assert.h>

unsigned int HexCharToInt(char x) {
    char alphabet[16] = "0123456789abcdef";
    int n = 0;
    int y = -1;
    for (n = 0; n < 16; n++) {
        if ( alphabet[n] == x ) { y = n; }
    }
    assert( y >= 0 && y <= 15 );
    return y;
}

unsigned long HexToInt(char* x) {
    unsigned long n = 0;
    unsigned long y = 0;
    unsigned long l = strlen(x)-1;
    for (n = 0; n <= l; n++) {
        y += HexCharToInt(x[l-n]) << (4*n) ;
    }
    
    return y;
}

char* HexToBase64(char* hex) {
    u_long l = strlen(hex)-1;
    int n = 0; // a loop counter, used for breaking input into chunks of 6 hex characters
    char s[6+1] = ""; // holds 6 character substrings
    char out[128+1] = ""; // output variable
    unsigned int window = 0; // holds the int value of s
    char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // alphabet for base64
    char newchar[] = "\0"; // newchar to be appended to output
    
    //process 3 bytes = 6 hex characters at a time
    for(n = 0; n <= l; n += 6) {
        memcpy(s, &hex[n], 6);
        assert(strlen(s) == 6);
        
        window = HexToInt(s);
        assert(window >= 0  && window <= 0xFFFFFF);
        for(int sextet = 0; sextet <= 6*3; sextet += 6) {
            newchar[0] = alphabet[ (window >> 18-sextet) & 0b111111 ];
            strcat(out, newchar);
            out;
        }
        
    }
    return out;
}

int challenge(void) {
    char input[] = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    printf("The output is %s.\n", HexToBase64(input));
    
    return 0;
}
