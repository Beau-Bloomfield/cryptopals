//
//  set1challenge4.c
//  cryptopals
//
//  Created by Bloomfield on 10/23/22.
//

#include "set1challenge4.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#define uint8 unsigned char
#define FILENAME "/Users/bloomfield/Documents/xcode/cryptopals/cryptopals/set1challenge4/data.txt"

struct DecryptionResult {
    char output_string[128];
    uint8 key;
    float score;
};

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

struct DecryptionResult BruteForceXorDecrypt(char *s) {
    struct DecryptionResult result;
    result.score = -1.0;
    result.key = -1;
    assert( s[strlen(s)-1] == '\n');
    s[strlen(s)-1] = '\0';
    assert( strlen(s) == 60 );
    
    for (int key = 0; key < 256; key++) {
        char plaintext[128] = "\0";
        for( int n = 0; n < strlen(s); n+=2) {
            uint8 octet = HexCharToInt(s[n+1]) + ( HexCharToInt(s[n]) << 4 );
            octet ^= key;
            strncat(plaintext, &octet, 1);
        }
        float score = Evaluate(plaintext);
        if( score > result.score) {
            result.score = score;
            result.key = key;
            memcpy(result.output_string, plaintext, strlen(plaintext));
        }
    }
    return result;
}

void challenge(void) {
    // File handling stuff
    FILE * file_pointer;
    char * buffer = NULL;
    size_t buffer_size = 0;
    size_t nchar_read = 1;
    file_pointer = fopen(FILENAME, "r");
    assert(file_pointer != NULL);
    
    float best_score = 0.0;
    int best_line = 0;
    
    int n = 0;
    while( !feof(file_pointer) ) {
        n++;
        nchar_read = getline(&buffer, &buffer_size, file_pointer);
        if(nchar_read <= 1 || feof(file_pointer)) break;
        struct DecryptionResult result = BruteForceXorDecrypt(buffer);
        printf("\nLine: %d | Key: %d | Score: %.3f | Result: %s", n, result.key, result.score, result.output_string);
        if(result.score > best_score) {
            best_score = result.score;
            best_line = n;
        }
    }
    printf("\n--------------------\nBest score: %.3f | Best line: %d", best_score, best_line);
}

