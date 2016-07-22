#include <iostream>
#include <libnet.h>
#include <unistd.h>
#include <pcap.h>
#include <wait.h>

using namespace std;


class arp_info{
private:
   static u_int32_t ip_addr_gateway;
   static u_int32_t ip_addr_atacker;
   static u_int32_t ip_addr_victim;
    u_int8_t *mac_addr_victim;
    u_int8_t *mac_addr_attacker;
    libnet_t *handle;
    u_int8_t *broad;

    char *gate(char* buf);
    const u_char *packet;
    pcap_t *p_handle;
    struct pcap_pkthdr *header;
public:

    void change_stringtohex(char *)
    {

    }


    void get_gateway()
    {
        FILE *pFile = NULL;
        char strTemp[255];
           pFile = fopen( "/proc/net/arp", "r" );
           if( pFile != NULL )
           {
    //arp_table second colrom is gateway
               fgets( strTemp, sizeof(strTemp), pFile );
               fgets( strTemp, sizeof(strTemp), pFile );
               fclose( pFile );
           }
           else
            printf("Can't open arp table\n");
           char *list;
           list=strtok(strTemp," ");
           ip_addr_gateway=inet_addr(list);
    }

    void arp_init()
    {
        //u_int32_t ip_addr_victim;
        //libnet_t *handle;
        char errbuf[LIBNET_ERRBUF_SIZE];

        if((handle=libnet_init(LIBNET_LINK_ADV,NULL,errbuf))==NULL)
            return ;

        //get attacker ip
        char ip_addr_str[16];
        //ip_addr_str=(char*)malloc(16);
        printf("Input target ip:\n");
        fgets(ip_addr_str,16,stdin);
        //puts(ip_addr_str);
        ip_addr_victim=inet_addr(ip_addr_str);
        //free(ip_addr_str);
        //get attacker mac
        mac_addr_attacker=libnet_get_hwaddr(handle)->ether_addr_octet;
        ip_addr_atacker=libnet_get_ipaddr4(handle);
        get_gateway();
        printf("target:%s\n",ip_addr_str);
        //get_victim_mac2(ip_addr_str);
        get_victim_mac();
        printf("finish victim\n");
    }

    void arp_spoofing()
    {
        //    if(arp(ARPOP_REPLY,handle,ip_addr_gateway,ip_addr_victim,mac_addr_attacker,mac_addr_victim)==2)
        //        printf("\nFail\n");

    }
/*
    void get_victim_mac2(char * target_ip)
    {
        FILE *pFile = NULL;
        char strTemp[255];
        char *list;
        target_ip[strlen(target_ip) - 1] = '\0';
        pFile = fopen( "/proc/net/arp", "r" );
        int i=0;
        while( pFile != NULL )
        {
            i++;
            if(i==5)
                break;
            fgets( strTemp, sizeof(strTemp), pFile );
           // cout<<i<<"::"<<strTemp<<endl;
            list=strtok(strTemp," ");
            //printf("SS:%d   %d\n",sizeof(list),sizeof(target_ip));
            if((strcmp(list,target_ip)==0))
            {
                list=strtok(NULL," ");//there is a mac in arp 4th
                list=strtok(NULL," ");
                list=strtok(NULL," ");
                printf("MAC:%s\n",list);
                break;
            }

        }
        fclose( pFile );
       // cout<<list<<endl;

        string tmp;
        list=strtok(list,":");
        tmp.append(list);
       // mac_addr_victim=(u_int8_t*)list;
       // cout<<mac_addr_victim<<endl;

        list=strtok(NULL,":");
        tmp.append(list);
       // mac_addr_victim=(unsigned char*)list;
       // cout<<mac_addr_victim<<endl;

        list=strtok(NULL,":");
        tmp.append(list);
        //mac_addr_victim=(unsigned char*)list;
        //cout<<mac_addr_victim<<endl;

        list=strtok(NULL,":");
        tmp.append(list);
        //mac_addr_victim=(unsigned char*)list;
        //cout<<mac_addr_victim<<endl;

        list=strtok(NULL,":");
        tmp.append(list);
        //mac_addr_victim=(unsigned char*)list;
        //cout<<mac_addr_victim<<endl;

        list=strtok(NULL,":");
        tmp.append(list);
        //mac_addr_victim=(unsigned char*)list;
        //cout<<mac_addr_victim<<endl;
        //cout<<tmp<<endl;

        mac_addr_victim=(u_int8_t *)tmp.data();

        const char *hex=tmp.data();

     //   cout<<"test:"<<t_tmp<<endl;
        for(int k=0;k<6;k++)
        {
            int t_tmp=atoi(hex);
        }

        cout<<mac_addr_victim<<endl;

        //mac_addr_victim=inet_aton(list);
         printf("MAC2:%2X:%2X:%2X:%2X:%2X:%2X ",mac_addr_victim[0],mac_addr_victim[1],mac_addr_victim[2],mac_addr_victim[3],mac_addr_victim[4],mac_addr_victim[5]);
    }
*/
    void arp_request();
    int arp(u_int8_t option,libnet_t *handle,u_int32_t ip_addr_s,u_int32_t ip_addr_d,u_int8_t *mac_addr_s, u_int8_t *mac_addr_d)
    {
        libnet_ptag_t arp;
       // printf("Write packet\n");

        //build ARP and ethernet
        arp=libnet_autobuild_arp(option,mac_addr_s,(u_int8_t*)&ip_addr_s,mac_addr_d,(u_int8_t*)&ip_addr_d,handle);
        //printf("Write packet\n");
        if(arp==-1)
        {
            printf("ARP_Error\n");
            return 2;
        }
        arp=libnet_autobuild_ethernet(mac_addr_d,ETHERTYPE_ARP,handle);
        if(arp==-1)
        {
            printf("Ether_Error\n");
            return 2;
        }
        libnet_write(handle);
        //printf("Write packet\n");
        libnet_destroy(handle);

        return 0;
    }



    void get_victim_mac()//send broad cast and receive the packet about victim
    {
      //  printf("finish victimzzzz\n");
         unsigned char cast[]={0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
        if(arp(ARPOP_REQUEST,handle,libnet_get_ipaddr4(handle),ip_addr_victim,libnet_get_hwaddr(handle)->ether_addr_octet,cast)==2)
               printf("\n Fail to get victim_mac\n");
       // printf("This ()\n");
        printf("send request\n");

        char *dev,error_buf[PCAP_ERRBUF_SIZE];
        dev=pcap_lookupdev(error_buf);//search device
        if(dev==NULL)
        {
            fprintf(stderr,"No such device:%s\n",error_buf);
            return ;
        }

        //p_handle=pcap_open_live(dev,1000,0,10000,error_buf); //dev open
        struct libnet_ethernet_hdr *e_hdr;
        struct libnet_arp_hdr *arp_hdr;
        struct libnet_ipv4_hdr *ipv4_hdr;

        u_int32_t ip_addr_tmp;
      //  u_int8_t *mac_addr_tmp;


        while(true)
        {
            printf("checking mac....\n");
            p_handle=pcap_open_live(dev,1000,0,1000,error_buf); //dev open
            pcap_next_ex(p_handle,&header,&packet);
            e_hdr=(struct libnet_ethernet_hdr *)packet;
           // arp_hdr=(struct libnet_arp_hdr*)(packet+sizeof(struct libnet_ethernet_hdr ));
           // ipv4_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr )+sizeof(struct libnet_arp_hdr));
            printf("start\n\n");
            if(e_hdr->ether_type==ETHERTYPE_ARP)
            {
                printf("in_e_hdr\n");
                    if(0x0200==arp_hdr->ar_op)
                    {
                        arp_hdr=(struct libnet_arp_hdr*)(packet+sizeof(struct libnet_ethernet_hdr ));
                        printf("arp_v\n");
                        if(ip_addr_tmp==ntohs(ipv4_hdr->ip_src.s_addr))
                        {
                            ipv4_hdr=(struct libnet_ipv4_hdr*)(packet+sizeof(struct libnet_ethernet_hdr )+sizeof(struct libnet_arp_hdr));
                            printf("%02X %02X\n",e_hdr->ether_type,e_hdr->ether_type);
                            //  mac_addr_victim=e_hdr->ether_shost;
                            break;
                        }
                     }

            }

        pcap_close(p_handle);
      //  printf("%02X:%02X:%02X:%02X:%02X:%02X ",mac_addr_victim[0],mac_addr_victim[1],mac_addr_victim[2],mac_addr_victim[3],mac_addr_victim[4],mac_addr_victim[5]);
        }
    }

    static void get_packet(u_char *user, const struct pcap_pkthdr *h,const u_char *bytes)
    {
        struct libnet_ethernet_hdr *e_hdr;
        struct libnet_arp_hdr *arp_hdr;
        struct libnet_ipv4_hdr *ipv4_hdr;
        u_int32_t ip_addr_tmp;
        u_int8_t *mac_addr_victim;

            e_hdr=(struct libnet_ethernet_hdr *)bytes;
            arp_hdr=(struct libnet_arp_hdr*)(bytes+sizeof(struct libnet_ethernet_hdr ));

            ipv4_hdr=(struct libnet_ipv4_hdr*)(bytes+sizeof(struct libnet_ethernet_hdr )+sizeof(struct libnet_arp_hdr));
            //ip_addr_tmp=(u_int32_t)(packet+sizeof(struct libnet_ethernet_hdr )+sizeof(struct libnet_arp_hdr)+sizeof(u_int8_t));
            if((e_hdr->ether_type==ETHERTYPE_ARP)&&(ARPOP_REPLY==arp_hdr->ar_op)&&(ip_addr_tmp==ipv4_hdr->ip_src.s_addr));
            {
                mac_addr_victim=e_hdr->ether_shost;
                printf("%02X:%02X:%02X:%02X:%02X:%02X ",mac_addr_victim[0],mac_addr_victim[1],mac_addr_victim[2],mac_addr_victim[3],mac_addr_victim[4],mac_addr_victim[5]);

            }
    }
};

u_int32_t arp_info::ip_addr_gateway=0;
u_int32_t arp_info::ip_addr_atacker=0;
u_int32_t arp_info::ip_addr_victim=0;

int main(void)
{
    arp_info test;
 //   test.get_gateway();
    test.arp_init();
    //test.get_victim_mac();

    return 0;
}


