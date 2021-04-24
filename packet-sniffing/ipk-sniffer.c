#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#define SUCCESS 0
#define ARG_ERROR 11
#define FINDALLDEVS_ERR 2
#define INTERNAL_ERR 99

// program by sa mal dat kedykolvek ukoncit pomocou ctrl+c
// TODO mozno povolit kombinovanie filtrov, to dorobim ak ostane cas, inak dovolujem len jeden
int listInterfaces() {
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaceList;
    pcap_if_t *iElement;
    
    int findInterfacesCheck = pcap_findalldevs(&interfaceList, errorBuffer);
    if (findInterfacesCheck != 0) {
        fprintf(stderr, "error: findalldevs failed\n");
        return FINDALLDEVS_ERR;
    } 

    if (interfaceList == NULL) {
        fprintf(stdout, "There are no active interfaces.\n");
        return SUCCESS;
    }

    iElement = interfaceList;
    while(iElement != NULL) {
        fprintf(stdout, "%s\n", iElement->name);
        iElement = iElement->next;
    }

    return SUCCESS;
}


int main(int argc, char **argv) {
    /* Flags specify whether given argument was entered / specified, or not */
    bool interfaceSet = false; /* defines, whether -i option was used */
    bool interfaceSpec = false; /* defines, whether interface was specified */
    bool portSpec = false; /* defines, whether -p option was used an parameter specified */
    bool tcpSpec = false; /* lists only tcp packets */
    bool udpSpec = false; /* lists only udp packets */
    bool arpSpec = false; /* lists only arp frames */
    bool icmpSpec = false; /* lists only ICMPv4 and ICMPv6 packets */
    bool numSpec = false; 
    int numOfPackets = 1;
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
                        fprintf(stderr, "error: allocation failed.\n");
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

            if (port < 0 || port > 65635) {
                fprintf(stderr, "error: invalid port\n");
                return ARG_ERROR;
            }

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
            if (udpSpec || arpSpec || icmpSpec) {
                fprintf(stderr, "error: two filters for packets were used, choose only one\n");
                return ARG_ERROR;
            }
            tcpSpec = true;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            if (tcpSpec || arpSpec || icmpSpec) {
                fprintf(stderr, "error: two filters for packets were used, choose only one\n");
                return ARG_ERROR;
            }
            udpSpec = true;
        } else if (strcmp(argv[i], "--arp") == 0) {
            if (tcpSpec || udpSpec || icmpSpec) {
                fprintf(stderr, "error: two filters for packets were used, choose only one\n");
                return ARG_ERROR;
            }
            arpSpec = true;
        } else if (strcmp(argv[i], "--icmp") == 0) {
            if (tcpSpec || udpSpec || arpSpec) {
                fprintf(stderr, "error: two filters for packets were used, choose only one\n");
                return ARG_ERROR;
            }
            icmpSpec = true;
        } else {
            fprintf(stderr, "error: invalid arguments were entered\n");
            return ARG_ERROR;
        }
    }
    /*-------------------------------------------------------------------------------------*/
    
    // get available devices
    if (interfaceSet == false || interfaceSpec == false) {
        return listInterfaces();
    } else {
        // tuto budeme snifovac
    }
    // TODO skontrolovat ci je zadany interface v liste vstekych rozhrani
    // set up sniffing 


    /*--------------------------------------CLEANUP-----------------------------------------*/

    if (interfaceSpec) {
        free(interface);
    }

    return SUCCESS;
}
    /*-------------------------------------END OF CODE--------------------------------------*/
