#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define SUCCESS 0
#define ARG_ERROR 11
#define INTERNAL_ERR 99

// program by sa mal dat kedykolvek ukoncit pomocou ctrl+c

int main(int argc, char **argv) {
    /* Flags specify whether given argument was entered / specified, or not */
    bool interfaceSet = false; /* defines, whether -i option was used */
    bool interfaceSpec = false; /* defines, whether interface was specified */
    bool portSpec = false; /* defines, whether -p option was used an parameter specified */
    bool tcpSpec = false;
    bool udpSpec = false;
    bool arpSpec = false;
    bool icmpSpec = false;
    bool numSpec = false; 
    int numOfPackets = -1;
    int port = -1;
    char *interface = NULL;

    /*------------------------------ PROCESSING OF ARGUMENTS ------------------------------*/
    /* Checking if only allowed arguments and their combinations were entered, respective flags are set */
    for(int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0) {
            interfaceSet = true; 
            i++;
            if(i < argc) {
                if (!(strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "-n") == 0 ||
                    strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0 ||
                    strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0 ||
                    strcmp(argv[i], "--arp") == 0 || strcmp(argv[i], "--icmp") == 0)) {
                    interfaceSpec = true; 
                    interface = malloc(strlen(argv[1]) + 1);

                    if(interface == NULL) {
                        fprintf(stderr, "error: allocation failed.");
                        return INTERNAL_ERR;
                    }

                    strcpy(interface, argv[i]);
                } 
            }
        } else if (strcmp(argv[i], "-p") == 0) {
            portSpec = true;
            i++;
            if((i >= argc) || strcmp(argv[i], "-n") == 0 || 
                    strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0 ||
                    strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0 ||
                    strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0 ||
                    strcmp(argv[i], "--arp") == 0 || strcmp(argv[i], "--icmp") == 0) { 
                fprintf(stderr, "error: -p option was used but not specified\n"); return ARG_ERROR; 
            }
            port = atoi(argv[i]);
        } else if (strcmp(argv[i], "-n") == 0) {
            numSpec = true;
            i++;
            if(i >= argc || strcmp(argv[i], "-p") == 0 || 
                    strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interface") == 0 ||
                    strcmp(argv[i], "--tcp") == 0 || strcmp(argv[i], "-t") == 0 ||
                    strcmp(argv[i], "--udp") == 0 || strcmp(argv[i], "-u") == 0 ||
                    strcmp(argv[i], "--arp") == 0 || strcmp(argv[i], "--icmp") == 0) { 
                fprintf(stderr, "error: -n option was used but not specified\n"); return ARG_ERROR; 
            }
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
    /*-------------------------------------------------------------------------------------*/
    
    return SUCCESS;
}
