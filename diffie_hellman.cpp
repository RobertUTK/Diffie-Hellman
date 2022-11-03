#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <iostream>
#include <string>
#include <cstring>
#include <iomanip>

using std::cout;
using std::cin;
using std::endl;
using std::string;
using std::hex;
using std::stoi;
using std::setfill;
using std::setw;
using std::cerr;

void fastModExp(BIGNUM * ,BIGNUM *, BIGNUM *, BIGNUM *);
bool isPrime(BIGNUM *, int);

int main(int argc, char **argv){
    BIGNUM *p = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *p2 = BN_new();
    BIGNUM *g = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *gOfA = BN_new();
    BIGNUM *gOfB = BN_new();
    BIGNUM *key = BN_new();
    BIGNUM *bnIV = BN_new();
    BIGNUM *cText = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int len = 0;
    unsigned char *str;
    unsigned char md[SHA256_DIGEST_LENGTH+1];
    unsigned char IV[32], ciphertext[1024], out[2048];
    string gOfBstr;
    string tempStr;
    EVP_CIPHER_CTX *evpCTX = EVP_CIPHER_CTX_new();
    const EVP_CIPHER *cipher = EVP_aes_128_cbc();
    bool fast = false;

    if(argc < 3){
        cerr << "usage: " << argv[0] << " g -fast|rand\n";
        exit(1);
    }
    if(strcmp(argv[2]+1, "fast") == 0) fast = true;

    BN_dec2bn(&g, argv[1]);

    BN_one(one);
    BN_add(two, one, one);
    if(fast) BN_generate_prime_ex(p, 1024, true, NULL, NULL, NULL);
    else     BN_rand(p, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    
    cout << "Searching for prime\n\n";
    while(1){
        if(isPrime(p, 10)){
            BN_sub(p2, p, one);
            BN_div(p2, NULL, p2, two, ctx);
            if(isPrime(p2, 10)) break;
        }
        if(fast) BN_generate_prime_ex(p, 1024, true, NULL, NULL, NULL);
        else     BN_rand(p, 1024, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ODD);
    }

    str = (unsigned char *)BN_bn2dec(p);
    cout << "Prime: " << str << endl << endl;
    OPENSSL_free(str);

    BN_rand(a, 128, true, false);
    BN_copy(e, a);
    fastModExp(gOfA, g, e, p);
    str = (unsigned char *)BN_bn2dec(gOfA);
    cout << "g^a: " << str << endl << endl;
    OPENSSL_free(str);

    cout << "Enter g^b: ";
    cin >> gOfBstr;
    cout << endl;

    BN_dec2bn(&gOfB, gOfBstr.c_str());
    fastModExp(key, gOfB, a, p);
    str = (unsigned char *)BN_bn2dec(key);
    cout << "Key: " << str << endl << endl;
    OPENSSL_free(str);

    str = new unsigned char[BN_num_bytes(key)];
    BN_bn2bin(key, str);
    SHA256(str, BN_num_bytes(key), md);

    cout << "Key hex: ";
    for(int i = 0; i < BN_num_bytes(key); i++) cout << hex << setw(2) << setfill('0') << (int) str[i];
    cout << endl << endl;
    delete [] str;

    cout << "Key hash: ";
    for(int i = 0; i < 32; i++) {
        cout << hex << setw(2) << setfill('0') << (int) md[i];
    }
    cout << endl << endl;

    cout << "Enter IV: ";
    cin >> tempStr;
    BN_hex2bn(&bnIV, tempStr.c_str());
    BN_bn2bin(bnIV, IV);
    cout << endl;

    cout << "Enter ciphertext: ";
    cin >> tempStr;
    BN_hex2bn(&cText, tempStr.c_str());
    BN_bn2bin(cText, ciphertext);
    cout << endl;

    len = BN_num_bytes(cText);

    EVP_DecryptInit(evpCTX, cipher, md, IV);
    EVP_Cipher(evpCTX, out, ciphertext, len);
    cout << out << endl;

    BN_free(p);
    BN_free(one);
    BN_free(two);
    BN_free(p2);
    BN_free(g);
    BN_free(a);
    BN_free(e);
    BN_free(gOfA);
    BN_free(gOfB);
    BN_free(key);
    BN_free(bnIV);
    BN_free(cText);
    BN_CTX_free(ctx);
    EVP_CIPHER_CTX_free(evpCTX);
}

void fastModExp(BIGNUM *product, BIGNUM *b, BIGNUM *e, BIGNUM *n){
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *mod = BN_new();
    BN_one(product);
    while(!BN_is_zero(e)){
        if(BN_is_odd(e)) {
            BN_mul(product, product, b, ctx);
            BN_mod(mod, product, n, ctx);
            BN_copy(product, mod);
        }
        BN_sqr(b, b, ctx);
        BN_mod(mod, b, n, ctx);
        BN_copy(b, mod);
        BN_rshift1(e, e);
    }
    BN_CTX_free(ctx);
    BN_free(mod);
}

bool isPrime(BIGNUM *n, int k){
    BIGNUM *d = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *two = BN_new();
    BIGNUM *a = BN_new();
    BIGNUM *nMinusTwo = BN_new();
    BIGNUM *nMinusOne = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *x2 = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    int s = 0;

    BN_one(one);
    BN_add(two, one, one);
    
    BN_sub(nMinusOne, n, one);
    BN_sub(nMinusTwo, n, two);

    BN_sub(d, n, one);

    while(!BN_is_odd(d)){ BN_div(d, NULL, d, two, ctx); s++;}
    
    
    for(int i = 0; i < k; i++){
        BN_rand_range(a, nMinusTwo);
        BN_add(a, a, one);
        fastModExp(x, a, d, n);
        if(BN_cmp(x, one) == 0|| BN_cmp(x, nMinusOne) == 0) continue;
        for(int j = 0; j < s; j++){
            BN_sqr(x, x, ctx);
            BN_mod(x, x, n, ctx);
            if(BN_cmp(x, nMinusOne) == 0) break;
        }
        if(BN_cmp(x, nMinusOne) == 0) continue;
        BN_free(d);
        BN_free(one);
        BN_free(two);
        BN_free(a);
        BN_free(nMinusTwo);
        BN_free(nMinusOne);
        BN_free(x);
        BN_free(x2);
        BN_CTX_free(ctx);
        return false;
    }
    BN_free(d);
    BN_free(one);
    BN_free(two);
    BN_free(a);
    BN_free(nMinusTwo);
    BN_free(nMinusOne);
    BN_free(x);
    BN_free(x2);
    BN_CTX_free(ctx);

    return true;
}