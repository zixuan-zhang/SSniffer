#ifndef SNIFFERTHREAD_H
#define SNIFFERTHREAD_H

#include <QThread>
#include<QStringList>
#include<QMap>
#include<QMutex>

/*
 * pcap related inclusion
 */
#include<pcap.h>
#include<netinet/in.h>

#include<string>

using namespace std;

#define DUMPFILE "capture.tmp"
typedef u_int32_t int_addr_t;


class SnifferThread : public QThread
{
    Q_OBJECT
public:
    explicit SnifferThread(QObject *parent = 0);
    void changeFilterString(QString filterString);
    void closeSniffer();
    void analyze_packet(int selectNumber);
    //QStringList analyze_ip(const u_char *packet);
    //QStringList analyze_arp(const u_char *packet);
    QStringList static analyze_tcp(const u_char* packet);
    QStringList static analyze_udp(const u_char* packet);
    QStringList static analyze_icmp(const u_char *packet);
    QStringList static analyze_payload(const u_char* payload, int len);
    QString static print_hex_ascii_line(const u_char *payload, int len, int offset);

signals:
    void PackageExtracted(QString);
    void PackageAnalyzed(QStringList);

public slots:
    void run();

private:
    /*
     * pcap related operation
     */

    static int packetNumber ;
    QMutex mutex;

    void sniffer_engine();
    void static ether_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    QStringList static ip_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);
    QStringList static arp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet);

    /*
     * pcap related definition
     */

    struct PacketInfo{
        const struct pcap_pkthdr *pkthdr;
        const u_char *packet;
    };

    QMap<int,struct PacketInfo*> *packetMap;

    QStringList packetList[10000];

    static string str_key;
    char *select_dev;
    char *filter_str;
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program filter;
    bpf_u_int32 net_mask;
    bpf_u_int32 net_ip;

    //IP Header Definition
    struct ip_header
    {
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      u_int8_t ip_hdr_len:4, ip_version:4;
    #elif __BYTE_ORDER == __BIG_ENDIAN
      u_int8_t ip_version:4, ip_hdr_len:4;
    #else
    #error	"Please fix <bits/endian.h>"
    #endif
      u_int8_t tos;
      u_int16_t tot_len;
      u_int16_t id;
      u_int16_t frag_off;
      u_int8_t ttl;
      u_int8_t protocol;
      u_int16_t checksum;
      struct in_addr src_addr;
      struct in_addr dst_addr;
    };

    // UDP Header Definition
    struct udp_header
    {
      u_int16_t src_port;
      u_int16_t dst_port;
      u_int16_t len;
      u_int16_t checksum;
    };

    //TCP Header Definition
    struct tcp_header
    {
      u_int16_t src_port;		/* source port */
      u_int16_t dst_port;		/* destination port */
      u_int32_t tcp_seq;		/* sequence number */
      u_int32_t tcp_ack;		/* acknowledgement number */
    #if __BYTE_ORDER == __LITTLE_ENDIAN
      u_int8_t tcp_reserved:4,	/* (unused) */
        tcp_off:4;			/* data offset */
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
      u_int8_t tcp_off:4, tcp_reserved:4;
    #endif
      u_int8_t th_flags;
    #define TH_FIN	0x01
    #define TH_SYN	0x02
    #define TH_RST	0x04
    #define TH_PSH	0x08
    #define TH_ACK	0x10
    #define TH_URG	0x20
      u_int16_t th_win;		/* window */
      u_int16_t th_sum;		/* checksum */
      u_int16_t th_urp;		/* urgent pointer */
    };

    //ICMP Header Definition
    struct icmp_header
    {
      u_int8_t icmp_type;
      u_int8_t icmp_code;
      u_int16_t icmp_chksum;
      u_int16_t icmp_id;
      u_int16_t icmp_seq;
    };

    //ARP Header Definition
    struct arp_header
    {
      u_int16_t htype;
      u_int16_t ptype;
      u_int8_t hlen;
      u_int8_t plen;
      u_int16_t oper;
      u_int8_t sha[6];
      u_int8_t spa[4];
      u_int8_t tha[6];
      u_int8_t tpa[4];
    };

};





#endif // SNIFFERTHREAD_H


