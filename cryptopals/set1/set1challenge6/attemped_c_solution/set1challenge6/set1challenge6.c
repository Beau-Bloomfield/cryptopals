//
//  set1challenge6.c
//  cryptopals
//
//  Created by Bloomfield on 10/23/22.
//

#include "set1challenge6.h"
#include <assert.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#define FILEPATH "/Users/bloomfield/Documents/xcode/cryptopals/cryptopals/set1challenge6/data.txt"

struct Uint8Array {
    uint8_t data[1024]; // array of data, some of which may be spurious
    size_t len; // The length of valid data
};

struct DecryptionResult {
    struct Uint8Array plaintext;
    uint8_t key;
    float score;
};

struct MultikeyDecryptionResult {
    uint8_t *keys;
    uint8_t *plaintext;
    int keysize;
    float average_score;
    
};

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

float Evaluate(uint8_t *s, size_t len) {
    char alphabet[] = "etairnosdlchmupfgbyvwkjxzq";
    float frequency[] = {0.123, 0.087, 0.080, 0.078, 0.077, 0.072, 0.066, 0.063, 0.041, 0.038, 0.036, 0.034, 0.033, 0.032, 0.027, 0.020, 0.018, 0.015, 0.015, 0.014, 0.013, 0.006, 0.006, 0.002, 0.001, 0.001};
    float count[26] = {0};
    assert( strlen(alphabet) == 26 );
    assert( sizeof(frequency) / sizeof(frequency[0]) == 26 );
    for( int n = 0; n < strlen(alphabet); n++) {
        for( int m = 0; m < len; m++) {
            if( tolower(s[m]) == alphabet[n] ) count[n]++;
        }
        count[n] /= (float)(len);
    }
    
    float sum = 0;
    for( int n = 0; n < strlen(alphabet); n++) {
        sum += count[n] * frequency[n];
    }
    return sum;
}

struct DecryptionResult BruteForceXorDecrypt(struct Uint8Array input) {
    struct DecryptionResult result = {.score = -1.0, .key = -1, .plaintext = {.len = 0} };
    result.score = -1.0;
    result.key = -1;
    result.plaintext.data;
    result.plaintext.len = 0;
    
    float score = -1;
    int key = -1;
    uint8_t plaintext[1024];
    
    for (int key = 0; key < 256; key++) {
        for( int n = 0; n < input.len; n++) {
            plaintext[n] = key^input.data[n];
        }
        score = Evaluate(plaintext, input.len);
        if( score > result.score) {
            result.score = score;
            result.key = key;
            for(int n = 0; n < input.len; n++) result.plaintext.data[n] = plaintext[n];
            result.plaintext.len = input.len;
        }
    }
    return result;
}

unsigned int Hamming(uint8_t *a, uint8_t *b, size_t len) {
    unsigned int dist = 0;
    
    for( int n = 0; n < len; n++) {
        uint8_t diff = a[n] ^ b[n];
        while(diff) {
            dist += diff & 0b1;
            diff >>= 1;
        }
    }
    return dist;
}


size_t Base64ToUint8Array(char input[], uint8_t output[]) {
    const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"; // alphabet for base64
    while( input[ strlen(input)-1 ] == '=' ) input[strlen(input)-1] = 'A'; // replace pad charcacters with 0 value
    size_t nbytes = 0; // number of bytes written to output, 0 is a possible value so can't use strlen
    size_t N = strlen(input);
    assert(strlen(input) % 4 == 0);

    int n = 0;
    for(n = 0; n < N; n += 4) {
        uint8_t fourbytes[4] = {0};
        unsigned int twentyfourbits = 0;
        int idx;
        
        // For each set of four b64 charactes match them to the index in the b64 alphabet
        idx = 0;
        while(input[n] != alphabet[idx] && idx < strlen(alphabet)) idx++;
        assert(input[n] == alphabet[idx] && idx < strlen(alphabet));
        fourbytes[0] = idx;
        
        idx = 0;
        while(input[n+1] != alphabet[idx] && idx < strlen(alphabet)) idx++;
        assert(input[n+1] == alphabet[idx] && idx < strlen(alphabet));
        fourbytes[1] = idx;
        
        idx = 0;
        while(input[n+2] != alphabet[idx] && idx < strlen(alphabet)) idx++;
        assert(input[n+2] == alphabet[idx] && idx < strlen(alphabet));
        fourbytes[2] = idx;
        
        idx = 0;
        while(input[n+3] != alphabet[idx] && idx < strlen(alphabet)) idx++;
        assert(input[n+3] == alphabet[idx] && idx < strlen(alphabet));
        fourbytes[3] = idx;
    
        // Combine each set of 6 bit values into a 24 bit number
        twentyfourbits += fourbytes[0] << (6*3);
        twentyfourbits += fourbytes[1] << (6*2);
        twentyfourbits += fourbytes[2] << (6*1);
        twentyfourbits += fourbytes[3] << (6*0);
        
        // break the 24 bit number into three bytes and copy them to the output array
        uint8_t byte = 1;
        
        byte = (twentyfourbits >> 16) & 0b11111111;
        output[nbytes++] = byte;
        
        byte = (twentyfourbits >> 8) & 0b11111111;
        output[nbytes++] = byte;
        
        byte = (twentyfourbits >> 0) & 0b11111111;
        output[nbytes++] = byte;
        
    }
    
    return nbytes;
}

struct MultikeyDecryptionResult SolveForKeysize(struct Uint8Array array, int keysize) {
    int mrows = keysize;
    int ncols = array.len / mrows;

    struct Uint8Array row = {.len = ncols};
    
    // Now try to solve each row individually
    struct MultikeyDecryptionResult multikey_result;
    multikey_result.keysize = keysize;
    multikey_result.average_score = 0.0;
    multikey_result.keys = malloc(sizeof(uint8_t)*keysize);
    
    for(int m = 0; m < mrows; m++) {
        for(int n = 0; n < ncols; n++) row.data[n] = array.data[m + n*keysize];
        struct DecryptionResult result = BruteForceXorDecrypt(row);
        multikey_result.keys[m] = result.key;
        multikey_result.average_score += result.score/keysize;
    }
    return multikey_result;
}

int challenge(void) {
    // First read first N lines from the file and allocate a byte_array large enough to hold its decoded value.
    FILE *filepointer = fopen(FILEPATH, "r");
    char *line = NULL;
    size_t line_len = -1;
    
    // This byte array will hold the base64 decoded data
    struct Uint8Array byte_array = { .len = 0, .data = {0} };
    
    assert(filepointer != NULL);
    int l;
    for(l = 1; l <= 60; l++) {
        ssize_t chars_read = getline(&line, &line_len, filepointer);
        assert( chars_read == strlen(line) ); //serves to make sure there are no NULL chars in the line.
        assert( line[strlen(line)-1] == '\n' ); //ensure the last character is a newline
        for(int n = 0; n < strlen(line)-1; n++) { assert(line[n] != '\n'); } // ensure no other characters are newlines
        line[ strlen(line)-1 ] = '\0'; //delete the newline
        uint8_t decoded[128] = {0};
        size_t nbytes = Base64ToUint8Array(line, decoded); // decode
        
        // Then copy the new bytes to our byte_array
        for(int n = 0; n < nbytes; n++) {
            byte_array.data[byte_array.len++] = decoded[n];
        }
    }
    
    // First find optimal keysize
    float best_score = 1e9, second_best_score = 1e9, third_best_score = 1e9;
    int best_keysize = 0, second_best_keysize = 0, third_best_keysize = 0;
    
    for(int keysize = 2; keysize <= 40; keysize++) {
        assert(byte_array.len > keysize);
        uint8_t a[128] = {0};
        uint8_t b[128] = {0};
        float score = 0.0;
        for(int block = 0; block < byte_array.len/keysize-1; block++) {
            for(int n = 0; n < keysize; n++) a[n] = byte_array.data[block*keysize+n]; // copy the first keysize bytes over
            for(int n = 0; n < keysize; n++) b[n] = byte_array.data[(block+1)*keysize+n]; // copy the next keysize bytes over
            score += (float)Hamming(a, b, keysize) / (float)(keysize); // compute the Hamming distance of a and b
        }
        score /= byte_array.len/keysize-1;
        printf("keysize: %d | score: %.2f\n", keysize, score);
        
        if(score < best_score) {
            third_best_score = second_best_score;
            third_best_keysize = second_best_keysize;
            second_best_score = best_score;
            second_best_keysize = best_keysize;
            best_score = score;
            best_keysize = keysize;
        }
        else if( score < second_best_score) {
            third_best_score = second_best_score;
            third_best_keysize = second_best_keysize;
            second_best_score = score;
            second_best_keysize = keysize;
        }
        else if( score < third_best_score ) {
            third_best_score = score;
            third_best_keysize = keysize;
        }
  
    }
    printf("\nBest | score: %.3f | keysize: %d", best_score, best_keysize);
    printf("\nSecond Best | score: %.3f | keysize: %d", second_best_score, second_best_keysize);
    printf("\nThird Best | score: %.3f | keysize: %d\n", third_best_score, third_best_keysize);
    
    struct MultikeyDecryptionResult final_result = {.average_score = -1};
    struct MultikeyDecryptionResult result;
    
    for( int keysize = 3; keysize <= 40; keysize++) {
        result = SolveForKeysize(byte_array, keysize);
        char plaintext[4096] = "";
        for(int n = 0; n < byte_array.len; n++) plaintext[n] = byte_array.data[n] ^ result.keys[ n % result.keysize ];

        if( result.average_score > final_result.average_score ) final_result = result;
    }


    return 0;
}
