/***********************************************
 * 
 * NAME : ANIKET RAY
 * E-Mail: aniketiq@gmail.com
 * Resume: http://bit.ly/2QTa5jQ
 * OS : MacOS 
 * Compiler: clang
 * NO SUPPORT FOR IPv6
 ***********************************************/

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <errno.h>

int toggle = 1; //1 --> Run | 0 --> Stop
void INThandler(int A) { toggle = 0; }

int TTL_value = 64;
int setTimeout = 1;
float pingInterval = 1.0; //(Time in Secs)

#define PING_PCKT 64 // (IP header + Transport header + Application Data)
#define TTL TTL_value

struct Packet
{
    icmp header; //BSD - 28 Bytes
    char message[PING_PCKT - sizeof(icmp)];
};

char *dns_lookup(char *, sockaddr_in *);
void ping(int, sockaddr_in *, char *, char *);
unsigned short checksum(void *, int);
void getUsageDetails(void);

unsigned short checksum(void *b, int len)
{
    unsigned short *buf = (unsigned short *)b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

char *dns_lookup(char *hostAddress,
                 sockaddr_in *connectionAddress)
{
    printf("\nResolving DNS...\n\n");
    char *ip = (char *)malloc(NI_MAXHOST * sizeof(char));
    hostent *hostEntity;

    hostEntity = gethostbyname(hostAddress);

    if (hostEntity == NULL)
    {
        free(ip);
        return NULL;
    }

    strcpy(ip, inet_ntoa(*(in_addr *)hostEntity->h_addr));
    (*connectionAddress).sin_family = hostEntity->h_addrtype;
    (*connectionAddress).sin_port = htons(0); //automatic port selection
    (*connectionAddress).sin_addr.s_addr = *(long *)hostEntity->h_addr;

    return ip;
}

void ping(int socketFileDescriptor,
          sockaddr_in *connectionAddress,
          char *IP_address,
          char *host)
{
    Packet packet;
    sockaddr_in receivedAddress;

    int isSent,
        msgCount = 0,
        receiveCount = 0;

    if (setsockopt(socketFileDescriptor, IPPROTO_IP, IP_TTL, &TTL_value, sizeof(TTL_value)))
    {
        printf("\nStatus: Something went Wrong\n\n");
        exit(EXIT_FAILURE);
    }

    printf("\nStatus: Connection Successful\n\n");

    timeval timeout;
    timeout.tv_sec = setTimeout; //
    timeout.tv_usec = 0;         //Corresponds to 1 secs : 0 microseconds

    timespec timeStart, timeEnd;

    setsockopt(socketFileDescriptor,
               SOL_SOCKET,
               SO_RCVTIMEO,
               (const char *)&timeout,
               sizeof(timeout));

    printf("PING %s (%s): %lu data bytes\n", host, IP_address, (PING_PCKT - sizeof(icmp)));
    while (toggle)
    {
        isSent = 1;
        memset(&packet, 0, sizeof(packet)); //Packet Message
        packet.header.icmp_type = ICMP_ECHO;
        packet.header.icmp_hun.ih_idseq.icd_id = getpid();

        for (size_t i = 0; i < sizeof(packet.message); i++)
        {
            packet.message[i] = i + 'A';
        }

        packet.header.icmp_hun.ih_idseq.icd_seq = msgCount++;
        packet.header.icmp_cksum = checksum(&packet, sizeof(packet));

        sleep(pingInterval);

        //Send ICMP ECHO Request
        clock_gettime(CLOCK_MONOTONIC, &timeStart);
        int isSuccess = sendto(socketFileDescriptor,
                               &packet,
                               sizeof(packet),
                               0,
                               (sockaddr *)connectionAddress,
                               sizeof(sockaddr_in));

        if (isSuccess <= 0)
        {
            printf("\nSending Failed!\n");
            fprintf(stderr, "Error %d: %s\n", (*__error()), strerror((int)(*__error())));
            isSent = 0;
        }

        //Receive ICMP
        socklen_t addressLength = sizeof(receivedAddress);

        isSuccess = recvfrom(socketFileDescriptor,
                             &packet,
                             sizeof(packet),
                             0,
                             (sockaddr *)&receivedAddress,
                             &(addressLength));

        if (isSuccess <= 0 && msgCount > 1)
            printf("Request Timeout for icmp_seq %d\n", msgCount - 1);
        else
        {
            clock_gettime(CLOCK_MONOTONIC, &timeEnd);

            if (isSent)
            {
                if (packet.header.icmp_type == 69 && packet.header.icmp_type == 0)
                {
                    fprintf(stderr, "Error!\n");
                }
                else
                {
                    double roundTripTime = (timeEnd.tv_nsec - timeStart.tv_nsec) / 1e6f;
                    roundTripTime = (timeEnd.tv_sec - timeStart.tv_sec) * (1000.0) + roundTripTime;

                    printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%0.3f ms \n",
                           PING_PCKT, IP_address, msgCount - 1, TTL_value, roundTripTime);
                    receiveCount++;
                }
            }
        }
    }

    float lossPercent = ((msgCount - receiveCount) / (float)msgCount) * 100;
    printf("\n--- %s ping statistics ---\n\n", host);
    printf("- Packets Sent = %d\n", msgCount);
    printf("- Packets Received = %d\n", receiveCount);
    printf("- Packet Loss = %.2f%c \n", lossPercent, '%');
}

void getUsageDetails(void)
{
    fprintf(stderr, "Usage: Filename -h [Host Name OR IP Address] (optional) -t [TTL Value] -i [Ping Interval (ms)] (default : 1000 ms)\n");
}

int main(int argc, char *argv[])
{
    if (argc < 3)
    {
        getUsageDetails();
        exit(EXIT_FAILURE);
    }

    char *hostInp;

    int option;
    while ((option = getopt(argc, argv, "h:i::t::")) != -1)
    {
        switch (option)
        {
        case 'h':
            hostInp = optarg;
            break;
        case 't':
            TTL_value = atoi(optarg);
            break;
        case 'i':
            pingInterval = atof(optarg) / 1000;
            break;
        default:
            getUsageDetails();
            exit(EXIT_FAILURE);
        }
    }

    int socketFileDescriptor;
    sockaddr_in connectionAddress;
    int addressLen = sizeof(connectionAddress);
    char hostName[NI_MAXHOST];
    char *IP_address;

    IP_address = dns_lookup(hostInp, &connectionAddress);

    if (IP_address == NULL)
    {
        fprintf(stderr, "DNS couldn't be Resolved\n");
        exit(EXIT_FAILURE);
    }

    //Building the socket
    socketFileDescriptor = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP); //Must be run in sudo

    if (socketFileDescriptor < 0)
    {
        fprintf(stderr, "Desciptor not received\n");
        exit(EXIT_FAILURE);
    }

    signal(SIGINT, INThandler);
    printf("IP : %s\n", IP_address);
    ping(socketFileDescriptor, &connectionAddress, IP_address, hostInp);

    return 0;
}

/**********************************************************************
 * References : 
 * 1. https://blog.benjojo.co.uk/post/linux-icmp-type-69
 * 2. https://scanftree.com/programs/c/implementation-of-checksum/
 * 3. https://www.csee.usf.edu/~kchriste/tools/checksum.c
 **********************************************************************/