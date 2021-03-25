#include <iostream>
#include <cstdio>
#include <string.h>
#include <stdlib.h>                                            
#include <unistd.h>                                           
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <string>

using namespace std;

#define hh_thresh 10
#define h_pscan_thresh 20
#define v_pscan_thresh 20

/*--- ./testattack ip_addr port  ---*/

char* remove_dot(int len, char *ip_addr){
	char *result = new char[len];
	for(int i = 0; i < len; i++){
		if (ip_addr[i] != '.')
			result[i] = ip_addr[i];
		else
			result[i] = ' ';
	}
	//cout << result << endl;
	return result;
}


int main(int argc, char **argv) {
	if (argc < 2){
		fprintf(stderr, "Usage: %s <dst_ip> <dst_port>\n", argv[0]);
		exit(1);
	}

	cout << "-----------Start of Heavy Hitter------------" << endl;
	int sd_HH;

	if ((sd_HH = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
		perror("socket() error");
		exit(1);	
	}

	struct sockaddr_in server_addr;

	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[2]));
	server_addr.sin_addr.s_addr = inet_addr(argv[1]);

	int SIZE = 1024 * 10;
	int repeat = ((hh_thresh+10) * 1024 * 1024) / SIZE;
	char buffer[SIZE];

	for (int i = 0; i < repeat; i++){
		memset(buffer, 'a', sizeof(buffer));
		
		
		if (sendto(sd_HH, buffer, strlen(buffer), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
			cout << "Heavy Hitters Error." << endl;
		}
	}
	close(sd_HH);
	cout << "-----------End of Heavy Hitter------------" << endl;

	usleep(3000000);	

	cout << "-----------Start of H_Portscan------------" << endl;

	int sd_H;	
	int ip_len = strlen(argv[1]);
	
	char ip_addr[ip_len];
	strcpy(ip_addr, remove_dot(ip_len, argv[1]));
	int separate_ip[4];
	sscanf(ip_addr, "%d %d %d %d", &separate_ip[0], &separate_ip[1], &separate_ip[2], &separate_ip[3]);

	memset(buffer, 0, sizeof(buffer));
	//memcpy(buffer, "This is H_PortScan.\n", sizeof(buffer));
	strcpy(buffer, "This is H_PortScan.\n");

	for (int i = 0; i < h_pscan_thresh; i++){
		char des_ip[15];
		sprintf(des_ip, "%d.%d.%d.%d", separate_ip[0], separate_ip[1], separate_ip[2], i+10);
		
		if ((sd_H = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
			perror("socket() error");
			exit(1);	
		}
	
		memset(&server_addr,0,sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(atoi(argv[2]));
		server_addr.sin_addr.s_addr = inet_addr(des_ip);
		
		if (sendto(sd_H, buffer, strlen(buffer), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
			cout << "Horizontal Portscan Error." << endl;
		}

		close(sd_H);
		
	}


	cout << "-----------End of H_Portscan------------" << endl;

	usleep(3000000);

	cout << "-----------Start of V_Portscan------------" << endl;

	int sd_V;	
	memset(buffer, 0, sizeof(buffer));
	//memcpy(buffer, "This is V_PortScan.\n", sizeof(buffer));
	strcpy(buffer, "This is V_PortScan.\n");
	
	for (int i = 0; i < v_pscan_thresh; i++){
		if ((sd_V = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0){
			perror("socket() error");
			exit(1);	
		}
	
		memset(&server_addr,0,sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(atoi(argv[2])+i);
		server_addr.sin_addr.s_addr = inet_addr(argv[1]);
		
		if (sendto(sd_V, buffer, strlen(buffer), 0, (const struct sockaddr *)&server_addr, sizeof(server_addr)) < 0){
			cout << "Vertical Portscan Error." << endl;
		}

		close(sd_V);
	}


	cout << "-----------End of V_Portscan------------" << endl;

	return 0;

}
