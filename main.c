/*	DEV ENVIRONMENT
	OS		: LINUX MINT
	TEXT EDITOR	: VIM
	GCC VER		: 5.4.0
*/

#include <stdio.h>
#include <pcap.h>

int 	main	(int argc, char** argv){
	char 		*device;					/*	Name of your device	*/
	char		error_buffer[PCAP_ERRBUF_SIZE];			/*	Defined 256		*/

	device 	=	 pcap_lookupdev(error_buffer);
	if	(device == NULL){
		printf("Error finding device : %s\n", error_buffer);
		return	1;
	}
	
	printf("Network device found : %s\n",device);
	return 0;
}
