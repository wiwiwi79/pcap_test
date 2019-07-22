#include <pcap.h>
int main(){
	struct pcap_pkthdr header;
	const u_char *packet;
	char *device;
	pcap_t *pcap_handle;
	int i;
	int Dport;
	int Sport;
	char filter_rule[0x10]="tcp";
	struct bpf_program fcode;
	device = pcap_lookupdev(errbuf);

	printf("start device: %s sniffing\n",device);

	pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
	pcap_compile(pcap_handle,&fcode,filter_rule,0,0);
	pcap_setfilter(pcap_handle, &fcode);  

	for(i=0;; i++){
		packet = pcap_next(pcap_handle, &header);    
		printf("Dmac :  %02x.%02x.%02x.%02x.%02x.%02x\n", packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]);
		printf("Smac :  %02x.%02x.%02x.%02x.%02x.%02x\n",packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);
		printf("Sip :  %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]);
		printf("Dip : %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);
		Sport=packet[34]*0x100+packet[35];
		Dport=packet[36]*0x100+packet[37];		
		printf("Dport : %d\n",Dport);
		printf("Sport : %d\n",Sport);
		printf("len : %d\n",header.len);
		int header_len=packet[0x2e];	
		header_len=(32*header_len/16/8);	
		printf("header len : %d\n",header_len);
		printf("Data : ");
		for(int x=0;x<=10;x++){
			if(packet[0x35+x]){
				printf("%c",packet[0x35+x]);
		}
		}
		printf("\n\n");
	}
	pcap_close(pcap_handle);
	return 0;
}

