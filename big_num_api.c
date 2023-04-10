/* bn_sample.c */
#include <stdio.h>
#include <string.h>
#include <openssl/bn.h>

#define NBITS 256

void printBN(char *msg, BIGNUM * a)
{
    /* Use BN_bn2hex(a) for hex string
    * Use BN_bn2dec(a) for decimal string */
    char * number_str = BN_bn2hex(a);
    printf("%s %s\n", msg, number_str);
    OPENSSL_free(number_str);
}
int main ()
{
    BN_CTX *ctx = BN_CTX_new();

    // BIGNUM *a = BN_new();
    // BIGNUM *b = BN_new();
    // BIGNUM *n = BN_new();
    // BIGNUM *res = BN_new();
    
    // // Initialize a, b, n
    // BN_generate_prime_ex(a, NBITS, 1, NULL, NULL, NULL);
    
    // BN_dec2bn(&b, "273489463796838501848592769467194369268");
    
    // BN_rand(n, NBITS, 0, 0);
    
    // // res = a*b
    // BN_mul(res, a, b, ctx);
    // printBN("a * b = ", res);
    
    // // res = aˆb mod n
    // BN_mod_exp(res, a, b, n, ctx);
    // printBN("aˆc mod n = ", res);

    /***************************************************/
    // Task One
    /***************************************************/
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *d = BN_new();

    // Assign hex numbers to p, q and e
    BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
    BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
    BN_hex2bn(&e, "0D88C3");

    // Calculate n
    BN_mul(n, p, q, ctx);

    // Find private key d
    
    BN_mod_inverse(d, e, n, ctx);

    printf("\nTASK ONE:\n");
    printBN("\np = ", p);
    printBN("\nq = ", q);
    printBN("\nn = ", n);
    printBN("\ne = ", e);
    printBN("\nd = ", d);

    /***************************************************/
    // Task Two
    /***************************************************/
    // 4120746f702073656372657421 => hex message
    BIGNUM *m = BN_new();
    BN_hex2bn(&m, "4120746f702073656372657421");
    BIGNUM *c = BN_new();
    BN_hex2bn(&n, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
    BN_hex2bn(&e, "010001");
    BN_hex2bn(&d, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

    // Calculate ciphertext
    BN_mod_exp(c, m, e, n, ctx);

    printf("\nTASK TWO:\n");
    printBN("\nm = ", m);
    printBN("\ne = ", e);
    printBN("\nn = ", n);
    printBN("\nCIPHERTEXT = ", c);

    // Calculate Plaintext
    BN_mod_exp(m, c, d, n, ctx);

    printBN("\nd = ", d);
    printBN("\nPLAINTEXT = ", m);

    /***************************************************/
    // Task Three
    /***************************************************/
    BN_hex2bn(&c, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");

    // Calculate Plaintext
    BN_mod_exp(m, c, d, n, ctx);

    printf("\nTASK THREE:\n");
    printBN("\nd = ", d);
    printBN("\nPLAINTEXT = ", m);

    /***************************************************/
    // Task Four
    /***************************************************/
    char *message1 = "I owe you $2000.";
    // 49206f776520796f752024323030302e => hex value

    char *message2 = "I owe you $3000.";
    // 49206f776520796f752024333030302e => hex value
    
    BN_hex2bn(&m, "49206f776520796f752024323030302e");

    // signature = m ^ d mod n
    BIGNUM *sig1 = BN_new();
    BIGNUM *sig2 = BN_new();

    // Sign message1
    BN_mod_mul(sig1, m, d, n, ctx);

    BN_hex2bn(&m, "49206f776520796f752024333030302e");

    // Sign message2
    BN_mod_mul(sig2, m, d, n, ctx);

    printf("\nTASK FOUR:\n");
    printf("Message 1: %s\n", message1);
    printBN("Signature 1 = ", sig1);

    printf("Message 2: %s\n", message2);
    printBN("Signature 2 = ", sig2);

    
    /***************************************************/
    // Task Five
    /***************************************************/
    // Message is "Launch a missle."
    // 4c61756e63682061206d697373696c652e => message hex value
    
    char* message = "4c61756e63682061206d697373696c652e";

    // Set up Alice's signature
    BN_hex2bn(&sig1, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");

    // Set up e
    BN_hex2bn(&e, "010001");

    // Set up n
    BN_hex2bn(&n, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");

    // Verify Signature
    BN_mod_exp(m, sig1, e, n, ctx);

    printf("\nTASK FIVE:\n");
    printBN("\nSignature = ", sig1);
    printBN("\ne = ", e);
    printBN("\nn = ", n);
    printf("\nMessage = %s\n", message);
    printBN("\nresult = ", m);
    if(strcasecmp(BN_bn2hex(m), message) == 0) {
        printf("\nAlice is the Sender\n");
    } else {
        printf("\nAlice is not the sender.\n");
    }
    return 0;
}