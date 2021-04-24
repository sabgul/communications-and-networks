#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>

#define SUCCESS 0
#define ARG_ERROR 1
#define FINDALLDEVS_ERR 2
#define LOOKUP_ERR 3
#define PCAPOPEN_ERR 4
#define FILTER_ERR 5
#define INTERNAL_ERR 99

// program by sa mal dat kedykolvek ukoncit pomocou ctrl+c
// TODO ked mi teda niekto nezada -n, mam vypisat 1 packet, ci vsetky kym nepride ctrl+c?
// TODO mozno povolit kombinovanie filtrov, to dorobim ak ostane cas, inak dovolujem len jeden

/* 
    Function lists all available interfaces if -i option was used with no 
    specific value, or if it wasn't used at all, and terminates the script
    with respective error code. 
*/
int listInterfaces() {
    /* TODO ocitovat*/
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


/* Creation of the capture filter is based on the documentation of Wireshark:
    https://www.wireshark.org/docs/wsug_html_chunked/ChCapCaptureFilterSection.html
    which described the valid syntax of capture filter. Wireshark - like this sniffer -
    is based on the libcap library, therefore the syntax is equivalent */ // TODO toto to dokumentacie skor ako tu
char* getCaptureFilter(bool portFlag, int port, bool tcpFlag, bool udpFlag, bool arpSpec, bool icmpSpec) {
    return NULL;
}


void packetProcessing() {}


/*
    The core function of this program. Behaves according to the specified flags and set values.
    It processes obtained data. //TODO ked budem vediet co vlastne robim 
*/
int packetSniffing(char *interface, bool portSpec, int port, bool tcpSpec, bool udpSpec, bool arpSpec, bool icmpSpec, int numOfPackets) {
    /* Goes through the list of interfaces and checks whether available interface is to be sniffed */
    char errorBuffer[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaceList;
    
    int findInterfacesCheck = pcap_findalldevs(&interfaceList, errorBuffer);
    if (findInterfacesCheck != 0) {
        fprintf(stderr, "error: findalldevs failed\n");
        return FINDALLDEVS_ERR;
    }

    pcap_if_t *iElement = interfaceList;
    bool validInterface = false;
    while(iElement != NULL) {
        if(strcmp(iElement->name, interface) == 0) { validInterface = true; break;}
        iElement = iElement->next;
    } 

    if(!validInterface) {
        fprintf(stderr, "error: invalid / inactive interface was specified\n");
        return ARG_ERROR;
    }
    /* ------ */

    /*  
        Following snippet of code is based on the article // TODO
        @see: https://www.binarytides.com/packet-sniffer-code-c-libpcap-linux-sockets/
        For the applying of filter:
        @see: https://www.tcpdump.org/pcap.html
    */

    struct bpf_program fp;		/* will contain the compiled filter expression */
    bpf_u_int32 interfaceIp;
    bpf_u_int32 interfaceMask;

    if (pcap_lookupnet(interface, &interfaceIp, &interfaceMask, errorBuffer) == -1) {
        fprintf(stderr, "error: could not get netmask for interface %s\n", interface);
        return LOOKUP_ERR;
    }

    /* selecting an interface for sniffing data
            1 - interface is to be put into promiscuous mode
            10000 - packet buffer timeout in miliseconds */
    pcap_t *packetCaptureHandle = pcap_open_live(interface, BUFSIZ, 1, 10000, errorBuffer);
    if(packetCaptureHandle == NULL) {
        fprintf(stderr, "error: cannot open the interface %s\n", interface);
        return PCAPOPEN_ERR;
    }

    /*  Creates and applies capture filter according to the specified flags.
        Therefore only packets compliant with the specified parameters 
        will be captured and later displayed  */

    char *captureFilter = getCaptureFilter(portSpec, port, tcpSpec, udpSpec, arpSpec, icmpSpec);
    if (pcap_compile(packetCaptureHandle, &fp, captureFilter, 0, interfaceIp) == -1) {
        fprintf(stderr, "error: compilation of filter failed\n");
        return FILTER_ERR;
    }

    /* Application of the capture filter */
    if (pcap_setfilter(packetCaptureHandle, &fp) == -1) {
        fprintf(stderr, "error: application of filter failed\n");
        return FILTER_ERR;
    }

    /* starting the sniffing of interface and processing the sniffed packets */
    pcap_loop(packetCaptureHandle, numOfPackets, packetProcessing, NULL);
    pcap_close(packetCaptureHandle);
    /* ------ */

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
        return packetSniffing(interface, portSpec, port, tcpSpec, udpSpec, arpSpec, icmpSpec, numOfPackets);
    }

    /*--------------------------------------CLEANUP-----------------------------------------*/

    if (interfaceSpec) {
        free(interface);
    }

    return SUCCESS;
}
    /*-------------------------------------END OF CODE--------------------------------------*/
