#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

#include <string>
#include <vector>

using namespace std;

#define DNS_PORT  "53"
#define URL       "www.taobao.com"
#define DNS_IP    "8.8.8.8"
#define RET_SIZE  551

//   +---------------------+
//   |        Header       |
//   +---------------------+t
//   |       Question      | the question for the name server
//   +---------------------+
//   |        Answer       | RRs answering the question
//   +---------------------+
//   |      Authority      | RRs pointing toward an authority
//   +---------------------+
//   |      Additional     | RRs holding additional information
//   +---------------------+


// Header  6bytes (48bits)
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


// Question 
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                     QNAME                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QTYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     QCLASS                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

typedef struct DNSHeader {
    // id
    uint16_t id;
    unsigned char option1;
    unsigned char option2;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} DNSHeader;

typedef struct DNSQuestion {
    vector<string> labels;  // qname
    uint16_t qtype;
    uint16_t qclass;
} DNSQuestion;

const char *QTYPE[] = {
    "",
    "A",        "NS",       "MD",   "MF",
    "CNAME",    "SOA",      "MB",   "MG",
    "MR",       "NULL",     "WKS",  "PTR",
    "HINFO",    "MINFO",    "MX",   "TXT",
    /* ignore other types*/
};

const char *QCLASS[] = {
    "",
    "IN",   "CS",   "CH",   "HS",
};

int __splitLabel(const string &domain, vector<string> &labels) {
    string::size_type pos = 0, start = 0;
    string label;
    while ((pos = domain.find('.', pos)) != string::npos) {
        label = domain.substr(start, pos-start);
        // too long
        if (label.length() > 255)
            return -1;
        labels.push_back(label);
        start = ++pos;
    }
    // the last label
    if (start < domain.size()) {
        label = domain.substr(start);
        if (label.length() > 255)
            return -1;
        labels.push_back(label);
    }
    return 0;
}

int __getReservedSpace(vector<string> &labels) {
    int len = sizeof(DNSHeader);
    for (int i = 0; i<labels.size(); ++i) {
        // 1 for label length (1 byte)
        len += (1 + labels[i].length());
    }
    // 1 for '\0'
    // 4 for qtype and qclass;
    len += 5;
    return len;
}

// return 0 for end, other for already parsed bytes
int __parseNameEndWithZero(char *ret, char *start, int recur) {
    uint16_t arg16;
    unsigned char arg8;
    // parsed length
    int len = 0;
parseBegin:
    arg8 = start[0];
    // check whether is compression
    if (((arg8 >> 6) & 3) == 3) {
        arg16 = (start[0] << 8) | start[1];
        arg16 = arg16 & 0x3fff;
        len += 2;
        // recursively parsed uncounted
        if (__parseNameEndWithZero(ret, ret+arg16, 1) != 0)
            goto parseBegin;
    } else {
        ++start;
        ++len;
        // arg8 is label length now
        while (arg8 > 0) {
            printf("%c", start[0]);
            ++start;
            ++len;
            --arg8;
        }
        arg8 = start[0];
        if (arg8 != 0) {
            printf(".");
            goto parseBegin;
        } else {
            ++len;
        }
    }
    return recur == 0 ? len : 0;
}

int __parseIPV4(char *start) {
    unsigned char ch;
    for (int i = 0; i<4; ++i) {
        ch = start[i];
        printf("%u", ch);
        if (i < 3) {
            printf(".");
        }
    }
    return 4;
}

int __parseIPV6(char *start) {
    unsigned char ch1, ch2;
    for (int i = 0; i<8; ++i) {
        ch1 = start[i];
        ch2 = start[i+1];
        printf("%x%x", ch1, ch2);
        if (i < 7) {
            printf(":");
        }
    }
    return 16;
}

int __parseAnswer(char *ret, char *start) {
    uint16_t qtype, qclass, rdlength;
    uint32_t ttl;
    unsigned char arg8;
    int len, tlen;
    // parse name
    len = __parseNameEndWithZero(ret, start, 0);
    if (len == 0) {
        // error
        return 0;
    }
    printf(": ");
    // skip to type
    arg8 = start[0];
    if (((arg8 >> 6) & 3) == 3) {
        start += 2;
    } else {
        // skip to zero
        while (arg8 != 0) {
            ++start;
            ++len;
            arg8 = start[0];
        }
        ++start;
    }
    // parse type
    qtype = start[0] | start[1];
    if (qtype > 16) {
        printf("unknown qtype(%u), ", qtype);
    } else {
        printf("type %s, ", QTYPE[qtype]);
    }
    start += 2;
    len += 2;

    // parse class
    qclass = start[0] | start[1];
    if (qclass > 4) {
        printf("unknown qclass(%u), ", qclass);
    } else {
        printf("class %s, ", QCLASS[qclass]);
    }
    start += 2;
    len += 2;

    // parse ttl
    ttl = start[0] | start[1] | start[2] | start[3];
    printf("ttl %u seconds, to ", ttl);
    start += 4;
    len += 4;

    // parse rdlength
    rdlength = start[0] | start[1];
    start += 2;
    len += 2;

    // read qdata
    switch (qtype) {
        case 1:
            // host address
            if (rdlength == 4) {
                // ipv4
                len += __parseIPV4(start);
            } else if (rdlength == 16) {
                // ipv6
                len += __parseIPV6(start);
            } else {
                printf("unknown ip type(len %u)", rdlength);
            }
            break;
        case 5:
            // cname
            tlen = __parseNameEndWithZero(ret, start, 0);
            if (tlen == 0) {
                printf("dest parse error");
            }
            len += tlen;
            break;
        default:
            printf("not supported qtype %u", qtype);
            len = 0;    // error
            break;
    }
    printf("\n");
    return len;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        printf("usage: ./a.out dnserver[8.8.8.8] domain[www.taobao.com]\n");
        return 1;
    }

    DNSHeader dnsheader;
    DNSQuestion dnsquestion;
    int sockfd, state, len, tmp = 0;
    struct addrinfo hint, *infos = NULL, *p = NULL;
    char *buffer = NULL, *tret;
    char ret[RET_SIZE];
    string dnserver(argv[1]);
    string domain(argv[2]);

    tret = ret;

    // id
    dnsheader.id = htons(9527);
    // |QR|   Opcode  |AA|TC|RD|
    // |0 |  0 0 0 0  |0 |0 |1 |
    dnsheader.option1 = 1;
    // |RA|   Z    |   RCODE   |
    // |0 | 0 0 0  |  0 0 0 0  |
    dnsheader.option2 = 0;
    dnsheader.qdcount = htons(1);
    dnsheader.ancount = htons(0);
    dnsheader.nscount = htons(0);
    dnsheader.arcount = htons(0);


    // split
    if (__splitLabel(domain, dnsquestion.labels) < 0) {
        printf("domail format error\n");
        goto err;
    }
    // query type A records
    dnsquestion.qtype = htons(1);
    // query class IN records
    dnsquestion.qclass = htons(1);


    // network
    memset(&hint, 0, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_DGRAM;

    state = getaddrinfo(dnserver.c_str(), DNS_PORT, &hint, &infos);
    if (state != 0)  {
        fprintf(stderr,"getaddrinfo: %s\n", gai_strerror(state));\
        return 0;
    }
    for (p = infos; p != NULL; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("once failed");
            continue;
        }
        
        break;
    }

    if (p == NULL) {
        perror("create socket failed");
        return 0;
    }

    // fill content
    len = __getReservedSpace(dnsquestion.labels);
    if (len > 550) {
        printf("TCP is not supported yet\n");
        goto err;
    }
    buffer = (char*)malloc(len);
    memcpy(buffer, &dnsheader, sizeof(dnsheader));
    for (int i = 0; i<dnsquestion.labels.size(); ++i) {
        unsigned char l = (dnsquestion.labels)[i].length();
        memcpy(buffer+sizeof(dnsheader)+tmp, &l, 1);
        ++tmp;
        memcpy(buffer+sizeof(dnsheader)+tmp, (dnsquestion.labels)[i].c_str(), l);
        tmp += l;
    }
    buffer[sizeof(dnsheader)+tmp] = '\0';
    ++tmp;
    memcpy(buffer+sizeof(dnsheader)+tmp, &(dnsquestion.qtype), 2);
    memcpy(buffer+sizeof(dnsheader)+tmp+2, &(dnsquestion.qclass), 2);

    state = sendto(sockfd, buffer, len, 0, p->ai_addr, p->ai_addrlen);
    printf("buffer len is %d, and send %d bytes success\n", len, state);
    // receive data
    printf("wait for answer......\n\n");
    state = recvfrom(sockfd, ret, RET_SIZE, 0, NULL, 0);
    if (state == -1) {
        printf("recv error\n");
        goto err;
    }

    ret[state] = '\0';
    // parse ret
    // parse header
    memcpy(&dnsheader, ret, sizeof(dnsheader));
    dnsheader.id = ntohs(dnsheader.id);
    dnsheader.qdcount = ntohs(dnsheader.qdcount);
    dnsheader.nscount = ntohs(dnsheader.nscount);
    dnsheader.arcount = ntohs(dnsheader.arcount);
    // get answer count
    dnsheader.ancount = ntohs(dnsheader.ancount);
    printf("there are %u results: \n", dnsheader.ancount);
    // parse answer
    tmp = len;
    for (int i = 0; i<dnsheader.ancount; ++i) {
        len = __parseAnswer(tret, ret+tmp);
        if (len == 0) {
            break;
        }
        tmp += len;
    }

err:
    close(sockfd);
    if (infos != NULL) {
        freeaddrinfo(infos);
    }
    if (buffer != NULL) {
        free(buffer);
    }
    return 0;
}