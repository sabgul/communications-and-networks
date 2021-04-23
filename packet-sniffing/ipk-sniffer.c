#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define SUCCESS 0
#define ARG_ERROR 11

int processArguments(int argc, char **argv, bool *iSpec, char **interface, bool *numSpec, int *numOfPackets, bool *portSpec, int *port) {
    // *numOfPackets = 6;
    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            // prekopirujem hodnotu z i+1 do interface, i inkrementujem, skontrolujem ci nie je vacsie ako argc
            i++;
            if(i >= argc) { return ARG_ERROR; }
            // strcpy 
        } else if (strcmp(argv[i], "-p") == 0) {
            i++;
            if(i >= argc) { return ARG_ERROR; }
            *port = atoi(argv[i]);
        } else if (strcmp(argv[i], "-n") == 0) {
            i++;
            if(i >= argc) { return ARG_ERROR; }
            *numOfPackets = atoi(argv[i]);
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0 ||
                   strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0 ||
                   strcmp(argv[i], "--arp") == 0 ||
                   strcmp(argv[i], "--icmp") == 0) {
                   continue;
        } else {
            return ARG_ERROR;
        }
    }

    // skontrolovat ci mam len povolene argumenty, skontrolovat ci mam spravne cislo portu

    return SUCCESS;
}


int main(int argc, char **argv) {
    /* Flags specify whether given argument was entered / specified, or not */
    bool interfaceSpec = false;
    bool portSpec = false;
    bool tcpSpec = false;
    bool udpSpec = false;
    bool arpSpec = false;
    bool icmpSpec = false;
    bool numSpec = false; 
    int numOfPackets = -1;
    int port = -1;
    char *interface = NULL;

    /* Processing arguments which specify the desired behaviour of the program */
    // if(processArguments(argc, argv, &interfaceSpec, &interface, &numSpec, &numOfPackets, &portSpec, &port) == ARG_ERROR) {
    //     fprintf(stderr, "error: invalid arguments were entered\n");
    //     return ARG_ERROR;
    // }

    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            interfaceSpec = true; 
            i++;
            if(i >= argc) { fprintf(stderr, "error: invalid arguments were entered\n"); return ARG_ERROR; }
            // TODO strcpy 
            strcpy(interface, argv[i]);
        } else if (strcmp(argv[i], "-p") == 0) {
            portSpec = true;
            i++;
            if(i >= argc) { fprintf(stderr, "error: invalid arguments were entered\n"); return ARG_ERROR; }
            port = atoi(argv[i]);
            // TODO check ci ide o valid port
        } else if (strcmp(argv[i], "-n") == 0) {
            numSpec = true;
            i++;
            if(i >= argc) { fprintf(stderr, "error: invalid arguments were entered\n"); return ARG_ERROR; }
            numOfPackets = atoi(argv[i]);
        } else if (strcmp(argv[i], "-t") == 0 || strcmp(argv[i], "--tcp") == 0) {
            tcpSpec = true;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            udpSpec = true;
        } else if (strcmp(argv[i], "--arp") == 0) {
            arpSpec = true;
        } else if (strcmp(argv[i], "--icmp") == 0) {
            icmpSpec = true;
        } else {
            fprintf(stderr, "error: invalid arguments were entered\n");
            return ARG_ERROR;
        }
    }

    /* sets flags to true if user specified so */
    return SUCCESS;
}
