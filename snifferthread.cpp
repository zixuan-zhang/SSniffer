#include "snifferthread.h"

/*
 * pcap related inclusion
 */
#include <netinet/ether.h>
#include <arpa/inet.h>
#include<string>
#include<fstream>
#include<QDebug>
using namespace std;

/* Program Use Variable Definition
 */
int SnifferThread::packetNumber=0;
string SnifferThread::str_key = "name";

SnifferThread::SnifferThread(QObject *parent) :
    QThread(parent)
{
    packetMap = new QMap<int,PacketInfo*>;
    isOn = false;
}

void SnifferThread::run()
{
    if(!isOn){
        isOn = true;
        packetNumber = 0;
        qDebug()<<"sniffer start";
        sniffer_engine();
    }
}

void SnifferThread::changeFilterString(QString filterRule)
{
    QByteArray ba = filterRule.toLatin1();
    char *filter_temp;
    filter_temp  = ba.data();
    filter_str = new char[strlen(filter_temp) + 1];
    strcpy(filter_str, filter_temp);
}

void SnifferThread::closeSniffer()
{
    if(isOn){
        pcap_close(handle);
        delete filter_str;
        isOn = false;
    }
}

void SnifferThread::analyze_packet(int selectNumber)
{
    QStringList dataList = packetList[selectNumber];
    emit PackageAnalyzed(dataList);
}

QStringList SnifferThread::analyze_tcp(const u_char *packet){
    QStringList dataList;
    QStringList data;
    struct tcp_header *hdr;
    hdr = (struct tcp_header*)(packet + 14 + 20);
    int size_tcp = hdr->tcp_off * 4;
    if(size_tcp < 20){
        data += "Invalid TCP header length";
        dataList.append(data);
        return dataList;
    }

    data += "SrcPort: " + QString::number(ntohs(hdr->src_port)) +
            "DstPort: " + QString::number(ntohs(hdr->dst_port)) + "\n";
    data += "SequenceNumber: " + QString::number(ntohs(hdr->tcp_seq)) + "\n";
    data += "Acknowlegement: " + QString::number(ntohs(hdr->tcp_ack)) + "\n";
    data += "CheckSum: " + QString::number(ntohs(hdr->th_sum)) + "\n";

    dataList.append(data);

    u_char *payload = (u_char*)(packet + 14 + 20 + size_tcp);
    ip_header *ip_hdr;
    ip_hdr = (ip_header*)(packet + 14);
    int size_payload = ntohs(ip_hdr->tot_len) - 20;
    QStringList remainData;
    if(size_payload > 0){
        dataList.append(QString("\nPayload Length: ") + QString::number(size_payload) + QString(" bytes: \n"));
        remainData = analyze_payload(payload, size_payload);
    }

    dataList += remainData;
    return dataList;
}

QStringList SnifferThread::analyze_udp(const u_char *packet)
{
    QStringList dataList;
    struct udp_header *hdr;
        u_short src_port;
        u_short dst_port;
        u_short len;

        hdr = (struct udp_header *)(packet + 14 + 20);

        src_port = ntohs(hdr->src_port);
        dst_port = ntohs(hdr->dst_port);
        len = ntohs(hdr->len);

        dataList.append(QString("Srouce Port = ") + QString::number(src_port) + "\n");
        dataList.append(QString("Des  Port      = ") + QString::number(dst_port) + "\n");
        dataList.append(QString("Udp Length   = ") + QString::number(len) + "\n");
        dataList.append(QString("Check Sum     = ") + QString::number(hdr->checksum) + "\n");

        u_char *payload = (u_char*)(packet + 14 + 20 + 8);// refers to ether, ip, udp header size
        int size_payload = ntohs(hdr->len) - 8;

        qDebug()<<"udp payload size is "<<size_payload;

        QStringList remainData;
        if(size_payload > 0){
            dataList.append(QString("\nPayload Length: ") + QString::number(size_payload) + QString("Bytes: \n"));
            remainData = analyze_payload(payload, size_payload);
        }
        dataList += remainData;
        return dataList;
}

QStringList SnifferThread::analyze_icmp(const u_char *packet)
{
    QStringList dataList;
    struct icmp_header *hdr;
    hdr = (struct icmp_header*)(packet + 14 + 20);

    QString data;
    data += "Type           = ";

    switch (hdr->icmp_type){
        case 8:
            data += "ICMP ECHO Request\n";
            break;
        case 0:
            data += "ICMP Echo Reply\n";
            break;
        case 3:
            data += "ICMP Uncreachable\n";
            break;
        case 4:
            data += "ICMP Queunch\n";
            break;
        case 5:
            data += "ICMP Redirect\n";
            break;
        case 9:
            data += "ICMP Adertisement\n";
            break;
        case 10:
            data += "Router Solicitation\n";
            break;
        case 11:
            data += "Time Exceeded\n";
            break;
        case 13:
            data += "ICMP Timestamp Request\n";
            break;
        default:
            break;
    }
    dataList.append(data);
    dataList.append(QString("Code           =  ") + QString::number(hdr->icmp_code) + "\n");
    dataList.append(QString("Checksum   =  ") + QString::number(hdr->icmp_chksum) + "\n");
    dataList.append(QString("ID               =  ") + QString::number(hdr->icmp_id) + "\n");
    dataList.append(QString("Sequence   =  ") + QString::number(hdr->icmp_seq) + "\n");

    return dataList;
}

QStringList SnifferThread::analyze_payload(const u_char *payload, int len){
    QStringList dataList;
        int len_rem = len;
        int line_width = 16;			/* number of bytes per line */
        int line_len;
        int offset = 0;					/* zero-based offset counter */
        const u_char *ch = payload;

        if (len <= 0)
        return dataList;

        QString data;
        if (len <= line_width) {
            qDebug()<<"only one line";
            data = print_hex_ascii_line(ch, len, offset);
            dataList.append(data);
            return dataList;
        }
        /* data spans multiple lines */
        for ( ;; ) {
            /* compute current line length */
            line_len = line_width % len_rem;
            /* print line */
            data = print_hex_ascii_line(ch, line_len, offset);
            dataList.append(data);
            /* compute total remaining */
            len_rem = len_rem - line_len;
            /* shift pointer to remaining bytes to print */
            ch = ch + line_len;
            /* add offset */
            offset = offset + line_width;
            /* check if we have line width chars or less */
            if (len_rem <= line_width) {
                /* print last line and get out */
                data = print_hex_ascii_line(ch, len_rem, offset);
                dataList.append(data);
                break;
            }
        }
        return dataList;
}

QString SnifferThread::print_hex_ascii_line(const u_char *payload, int len, int offset)
{
    QString data;
        int i;
        int gap;
        const u_char *ch;
        data += QString("%1").arg(offset, 5, 10, QChar('0')) + " ";

        /* hex */
        ch = payload;
        for(i = 0; i < len; i++) {
            //printf("%02x ", *ch);
                data += QString("%1").arg(*ch, 2, 16, QChar('0'));
                data += " ";
                ch++;
            /* print extra space after 8th byte for visual aid */
            if (i == 7)
            {
                    //printf(" ");
                data += " ";
            }
        }
        /* print space to handle line less than 8 bytes */
        if (len < 8)
        {
            //printf(" ");
            data += " ";
        }

        /* fill hex gap with spaces if not full line */
        if (len < 16) {
            gap = 16 - len;
            for (i = 0; i < gap; i++) {
                    //printf("   ");
                    data += "   ";
            }
        }
        data += "   ";
        /* ascii (if printable) */
        ch = payload;
        for(i = 0; i < len; i++)
        {
            if (isprint(*ch))
            {
                    data += *ch;
                    int k=0;
                    u_char* p=(u_char*)ch;
                    //TODO: figure out what happened here
                    while( p  && k<(int)str_key.length() && (*p)==str_key.at(k) )
                    {
                        p++;
                        k++;
                    }//while
                    if( k==(int)str_key.length() )
                    {
                        string f_str;
                        while( p && (*p)>32 && (*p)<123 )
                        {
                            f_str+=(*p);
                            p++;
                        }
                    }
            }
            else
                {
                    data += ".";
                }
            ch++;
        }
        data += "\n";
        return data;
}

void SnifferThread::sniffer_engine()
{
    select_dev = pcap_lookupdev(errbuf);
    pcap_lookupnet(select_dev, &net_ip, &net_mask, errbuf);

    handle = pcap_open_live(select_dev, BUFSIZ, 1, 0, errbuf);
    pcap_compile(handle, &filter, filter_str, 0, net_ip);
    pcap_setfilter(handle, &filter);
    pcap_dump_open(handle, DUMPFILE);
    pcap_loop(handle, -1, ether_callback, (u_char*)this);
}

void SnifferThread::ether_callback(u_char *arg, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    qDebug()<<"Ether Callback";
    QString data;
    QString SrcMac, DstMac;
    SnifferThread *thisThread = (SnifferThread*)arg;

    //thisThread->mutex.lock();
    qDebug()<<"ether in lock";
    data += QString::number(++packetNumber) + ",";

    struct ether_header *e_header;
    e_header = (struct ether_header*)packet;

    ether_addr addr;
    u_int8_t *p1 = addr.ether_addr_octet;
    u_int8_t *p2 = e_header->ether_shost;
    for(int i=0;i<ETH_ALEN;i++,p1++,p2++)
    {
        *p1=*p2;
    }
    SrcMac = QString(ether_ntoa(&addr));

    p1=addr.ether_addr_octet;
    p2=e_header->ether_dhost;
    for(int i=0;i<ETH_ALEN;i++,p1++,p2++)
    {
        *p1=*p2;
    }
    DstMac = QString(ether_ntoa(&addr));

    u_int16_t ether_type = ntohs(e_header->ether_type);

     QStringList remainList;
    if(ether_type==0x0800||ether_type==0x0806){
        switch(ether_type){
            case 0x0800:
            remainList = ip_callback(arg, pkthdr, packet);
                break;
            case 0x0806:
            remainList = arp_callback(arg, pkthdr, packet);
                break;
        }
    }
    else{
        return;
    }

    data += SrcMac + ",";
    data += DstMac + ",";
    data += remainList[0];
    //qDebug()<<"extract data is "<<data;
    remainList[0] = data;
    thisThread->packetList[packetNumber] = remainList;
    //thisThread->mutex.unlock();
    //qDebug()<<packetNumber<<" list number is"<<remainList.count();
    emit thisThread->PackageExtracted(data);
}

QStringList SnifferThread::ip_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
        const u_char *packet){
    /*
     * Return QStringList object including: src_ip, dst_ip, protocal, length
     */
    //SnifferThread *thisThread = (SnifferThread*)arg; TODO: useless or not?

    QStringList dataList;
    QString data;

    struct ip_header *hdr;
    hdr = (struct ip_header *)(packet + 14);
    //int size_ip = hdr->ip_hdr_len * 4; TODO: useless or not?
    data += QString(inet_ntoa(hdr->src_addr)) + ",";
    data += QString(inet_ntoa(hdr->dst_addr)) + ",";

    QStringList remainData;
    switch(hdr->protocol){
        case 6:
            data.append("TCP,");
            remainData = analyze_tcp(packet);
            break;
        case 17:
            data.append("UDP,");
            remainData = analyze_udp(packet);
            break;
        case 1:
            data.append("ICMP,");
            remainData = analyze_icmp(packet);
            break;
    }
    data += QString::number(ntohs(hdr->tot_len));
    dataList.append(data);
    dataList += remainData;
    return dataList;
}

QStringList SnifferThread::arp_callback(u_char *arg, const struct pcap_pkthdr *pkthdr,
                                        const u_char *packet)
{
    /*
     * Return QStringList object, including src_ip, dst_ip, protocol, and length
     */
    QStringList dataList;
    QString data;
        QString src_ip, dst_ip;
        struct arp_header *hdr;
        hdr = (struct arp_header *)(packet + 14);
        int i;
        for (i = 0; i < 4; i++)
        {
            if(3==i)
            {
                src_ip += QString::number(int(hdr->spa[i]));
            }
            else
            {
                src_ip += QString::number(int(hdr->spa[i]));
                src_ip += ".";
            }
        }
        data += (src_ip + ",");

        for (i = 0; i < 4; i++)
        {
            if(3==i)
            {
                dst_ip += QString::number(int(hdr->tpa[i]));
            }
            else
            {
                dst_ip += QString::number(int(hdr->tpa[i]));
                dst_ip += ".";
            }
        }
        data += (dst_ip + ",");
        data += ("ARP,");
        data += QString::number(42);
        dataList.append(data);

        data = "Format of hardware address = ";
        u_int16_t htype = ntohs(hdr->htype);
        if( htype == 1){
            data += "(100Mb Ethernet)\n";
        }
        dataList.append(data);
        dataList.append(QString("Hardware address length  = ") +
                        QString::number(hdr->hlen) + "\n");
        dataList.append(QString("Protocol address length  = ") +
                        QString::number(hdr->plen) + "\n");
        data = "ARP opcode (comandl)    = ";
        switch(ntohs(hdr->oper)){
        case 1:
            data += "(ARP request) \n";
            break;
        case 2:
            data += "(ARP reply) \n";
            break;
        case 3:
            data += "(RARP request) \n";
            break;
        case 4:
            data += "(RARP reply) \n";
            break;
        }
        return dataList;
}
