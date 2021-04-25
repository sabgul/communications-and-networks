#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <ctype.h>
#define SUCCESS 0
#define ARG_ERROR 1
#define FINDALLDEVS_ERR 2
#define LOOKUP_ERR 3
#define PCAPOPEN_ERR 4
#define FILTER_ERR 5
#define INTERNAL_ERR 99

#define TCP_PROTOCOL 6
#define UDP_PROTOCOL 17
#define ICMP_PROTOCOL 1
// arp: The EtherType for ARP is 0x0806. 
// This appears in the Ethernet frame header when the payload is an ARP packet and is not to be confused with PTYPE, 
// which appears within this encapsulated ARP packet.

// TODO DOKU mozno povolit kombinovanie filtrov, to dorobim ak ostane cas, inak dovolujem len jeden
/*
    Function displays brief description of this application.
    It is executed when -h or --help command line argument was used.
*/
void displayHelp() {
    fprintf(stdout, "\n---------------------- GUIDE - PACKET SNIFFER ----------------------\n"
                    "DESCRIPTION: \n"
                    "   Application ipk-sniffer serves as a packet sniffer which \n"
                    "   is a tool used to monitor the network traffic. \n"
                    "   This application is capable of capturing and filtering of packets\n"
                    "   according to the behaviour specified by command line arguments.\n\n"
                    "ACCEPTED PARAMETERS: \n"
                    "   -h | --help      - displays this guide\n"
                    "   -i | --interface - specifies the interface for sniffing\n"
                    "   -p               - only capturing packets on specified port\n"
                    "   -t | --tcp       - only displaying TCP packets \n" 
                    "   -u | --udp       - only displaying UDP packets \n"
                    "   -n               - number of packets to be sniffed\n\n"
                    "ERROR CODES: \n"
                    "   1                - invalid arguments\n"
                    "   2                - error listing all active interfaces\n"
                    "   3                - error in lookup \n"
                    "   4                - pcap error opening the interface \n"
                    "   5                - error compiling or applying filter\n"
                    "   99               - internal error - allocation failed etc.\n"
                    "--------------------------------------------------------------------\n\n");
}

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
char* getCaptureFilter(bool portFlag, int port, bool tcpFlag, bool udpFlag, bool arpFlag, bool icmpFlag) {
    static char captureFilter[50] = "\0";
    char portS[6];
    sprintf(portS, "%d", port);

    if (tcpFlag && udpFlag) {
        strcat(captureFilter, "tcp or udp");
    } else if (tcpFlag && arpFlag) {
        strcat(captureFilter, "tcp or arp");
    } else if (tcpFlag && icmpFlag) {
        strcat(captureFilter, "tcp or icmp");
    } else if (udpFlag && arpFlag) {
        strcat(captureFilter, "udp or arp");
    } else if (udpFlag && icmpFlag) {
        strcat(captureFilter, "udp or icmp");
    } else if (arpFlag && icmpFlag) {
        strcat(captureFilter, "arp or icmp");
    } else if (tcpFlag && udpFlag && arpFlag) {
        strcat(captureFilter, "tcp or udp or arp");
    } else if (tcpFlag && arpFlag && icmpFlag) {
        strcat(captureFilter, "tcp or arp or icmp");
    } else if (tcpFlag && udpFlag && icmpFlag) {
        strcat(captureFilter, "tcp or udp or icmp");
    } else if (udpFlag && arpFlag && icmpFlag) {
        strcat(captureFilter, "udp or arp or icmp");
    } else if (tcpFlag && udpFlag && arpFlag && icmpFlag) {
        strcat(captureFilter, "tcp or udp or arp or icmp");
    } else if (tcpFlag) {
        strcat(captureFilter, "tcp");
    } else if (udpFlag) {
        strcat(captureFilter, "udp");
    } else if (arpFlag) {
        strcat(captureFilter, "arp");   
    } else if (icmpFlag) {
        strcat(captureFilter, "icmp");
    }

    if (portFlag && !(tcpFlag || udpFlag || arpFlag || icmpFlag)) {
        strcat(captureFilter, "port ");
        strcat(captureFilter, portS);
    } else if(portFlag && (arpFlag || icmpFlag)) {
        strcat(captureFilter, " or port ");
        strcat(captureFilter, portS);
    } else if (portFlag) {
        strcat(captureFilter, " and port ");
        strcat(captureFilter, portS);
    } 
    return captureFilter;
}


/*  
    The arguments of this function are defined by the required structure of the callback 
    function in the pcap_loop.
    Function processes each captured packet and decides about the captured data's postprocessing
    into the desired output form.
*/
void packetProcessing(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    /*  As defined in pcap.h
        struct pcap_pkthdr {
            struct timeval ts; -- time stamp
            bpf_u_int32 caplen; -- length of portion present 
            bpf_u_int32 len; -- length this packet (off wire) 
        };      
    */
    //struct sniffedTime{} = packet.ts;
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    /* The total packet length, including all headers
       and the data payload is stored in
       header->len and header->caplen. Caplen is
       the amount actually available, and len is the
       total packet length even if it is larger
       than what we currently have captured. If the snapshot
       length set with pcap_open_live() is too small, you may
       not have the whole packet. */
    // printf("Total packet available: %d bytes\n", header->caplen);
    // printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    /* The second-half of the first byte in ip_header
       contains the IP header length (IHL). */
    ip_header_length = ((*ip_header) & 0x0F);
    /* The IHL is number of 32-bit segments. Multiply
       by four to get a byte count for pointer arithmetic */
    ip_header_length = ip_header_length * 4;
    // printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    /* Now that we know where the IP header is, we can 
       inspect the IP header for a protocol number to 
       make sure it is TCP before going any further. 
       Protocol is always the 10th byte of the IP header */
    u_char protocol = *(ip_header + 9);

    if (protocol == IPPROTO_ICMP) {
        // sniff icmp 
        printf(" >> ICMP CAU \n");
    } 

    if (protocol == IPPROTO_ICMPV6) {
        printf(" >> ICMPv6 CAU \n");
    } 

    if (protocol == IPPROTO_UDP) {
        printf(" >> UDP CAU \n");
    } 

    if (protocol == IPPROTO_TCP) {
        printf(" >> TCP CAU \n");
        tcp_header = packet + ethernet_header_length + ip_header_length;
        tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
        tcp_header_length = tcp_header_length * 4;
        int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
        payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
        payload = packet + total_headers_size;
        if (payload_length > 0) {
            const u_char *temp_pointer = payload;
            int byte_count = 0;
            char asciiDisplay[17] = "\0";
            int enoguhHex = 0;
            int disp = 0;
            printf("0x%04x: ", disp);
            while (byte_count++ < payload_length) {
                char hexData [3];
                sprintf(hexData,"%02x", *temp_pointer);
                enoguhHex++;
                char cosi = *temp_pointer;
                if(isprint(cosi)) {
                    // fprintf(stdout,"\nTu som.\n");
                    strncat(asciiDisplay, &cosi,1);
                    // if (enoguhHex == 6){
                    //     strcat(asciiDisplay, " ");
                    // }
                } else {
                    // fprintf(stdout,"\nTu som..\n");
                    strncat(asciiDisplay, ".",1);
                }
                
                if ((enoguhHex >= 1 && enoguhHex < 8) || (enoguhHex > 8 && enoguhHex < 16)) {
                    fprintf(stdout, "%s ", hexData);
                } else if (enoguhHex == 8) {
                    fprintf(stdout, "%s  ", hexData);
                } else if (enoguhHex == 16) {
                    disp += 16;
                    fprintf(stdout, "%s  ", hexData);
                    fprintf(stdout, "%s\n0x%04x: ", asciiDisplay, disp);
                    strcpy(asciiDisplay, "");
                } else {
                    enoguhHex = 0;
                }



                temp_pointer++;
            }
            printf("\n");
        }
    }

    // /* Add the ethernet and ip header length to the start of the packet
    //    to find the beginning of the TCP header */
    // tcp_header = packet + ethernet_header_length + ip_header_length;
    // /* TCP header length is stored in the first half 
    //    of the 12th byte in the TCP header. Because we only want
    //    the value of the top half of the byte, we have to shift it
    //    down to the bottom half otherwise it is using the most 
    //    significant bits instead of the least significant bits */
    // tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    // /* The TCP header length stored in those 4 bits represents
    //    how many 32-bit words there are in the header, just like
    //    the IP header length. We multiply by four again to get a
    //    byte count. */
    // tcp_header_length = tcp_header_length * 4;
    // printf("TCP header length in bytes: %d\n", tcp_header_length);

    // /* Add up all the header sizes to find the payload offset */
    // int total_headers_size = ethernet_header_length+ip_header_length+tcp_header_length;
    // printf("Size of all headers combined: %d bytes\n", total_headers_size);
    // payload_length = header->caplen -
    //     (ethernet_header_length + ip_header_length + tcp_header_length);
    // printf("Payload size: %d bytes\n", payload_length);
    // payload = packet + total_headers_size;
    // printf("Memory address where payload begins: %s\n\n", payload);

    // /* Print payload in ASCII */
      
    // if (payload_length > 0) {
    //     const u_char *temp_pointer = payload;
    //     int byte_count = 0;
    //     while (byte_count++ < payload_length) {
    //         if(isprint(*temp_pointer)) {
    //             printf("%c", *temp_pointer);
    //         } else {
    //             printf(".");
    //         }
            
    //         temp_pointer++;
    //     }
    //     printf("\n");
    // }
    

}


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
        fprintf(stderr, "error: findalldevs failed: %s\n", errorBuffer);
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

    /* selecting an interface for sniffing data
            1 - interface is to be put into promiscuous mode
            1000 - packet buffer timeout in miliseconds */
    pcap_t *packetCaptureHandle = pcap_open_live(interface, BUFSIZ, 1, 1000, errorBuffer);
    if(packetCaptureHandle == NULL) {
        fprintf(stderr, "error: cannot open the interface %s: %s\n", interface, errorBuffer);
        return PCAPOPEN_ERR;
    }

    if (pcap_lookupnet(interface, &interfaceIp, &interfaceMask, errorBuffer) == -1) {
        fprintf(stderr, "error: could not get netmask for interface %s\n", interface);
        return LOOKUP_ERR;
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
            if(strcmp(argv[i], "0") != 0 && port == 0) {
                fprintf(stderr, "error: invalid port\n");
                return ARG_ERROR;
            }

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
            tcpSpec = true;
        } else if (strcmp(argv[i], "-u") == 0 || strcmp(argv[i], "--udp") == 0) {
            udpSpec = true;
        } else if (strcmp(argv[i], "--arp") == 0) {
            arpSpec = true;
        } else if (strcmp(argv[i], "--icmp") == 0) {
            icmpSpec = true;
        } else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            displayHelp();
            return SUCCESS;
        } else {
            fprintf(stderr, "error: invalid arguments were entered\n");
            return ARG_ERROR;
        }
    }
    /*-------------------------------------------------------------------------------------*/
    
    if (interfaceSet == false || interfaceSpec == false) {
        return listInterfaces();
    } else {
        return packetSniffing(interface, portSpec, port, tcpSpec, udpSpec, arpSpec, icmpSpec, numOfPackets);
    }

    /*--------------------------------------CLEANUP-----------------------------------------*/

    if (interfaceSpec) {
        free(interface);
    }

    return SUCCESS;
}
    /*-------------------------------------END OF CODE--------------------------------------*/
