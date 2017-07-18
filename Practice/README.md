  # BoB Security Consulting Track Geon Yong Kim
  # With GilGil Mento .
  https://gitlab.com/gilgil/network/wikis/ethernet-packet-dissection/pcap-programming
  
  ## Libpcap Reference
  https://fossies.org/dox/libpcap-1.8.1/index.html
  
  ### bpf_program struct reference
  http://www.rajivchakravorty.com/source-code/.tmp/snort-html/structbpf__program.html
  
  ### bpf_insn struct reference
  http://www.rajivchakravorty.com/source-code/.tmp/snort-html/structbpf__insn.html

  ### How to print MAC ADDRESS || IP ADDRESS?
  http://gatolu.tistory.com/entry/PCAP-MAC-IP-%EC%A3%BC%EC%86%8C

  ### Line By Line Comment!
  001 - 005	: My Dev Environment
  007 - 017	: Header Include
  020 - 036	: ether_header struct {
			u_int8_t ether_dhost[ETH_ALEN]
			u_int8_t ether_shost[ETH_ALEN]
			u_int16_t ether_type;}
		  packet divided into ether_header. 
		  using format string to print MAC Address(6 bytes)
  038 - 042	: re-define ethernet header
  045 - 048	: re-define ip_vhl, ip_p, ip_src, ip_dst (ip_addr)
  051 - 056	: re-define src port, dest port, data offset
  058 - 060	: function prototype
  062 - 101	: print one-line data (memory / hex / data)
  103 - 130	: main printer. using offset to print
  		  get packet length and get line length with modular calc.
		  const u_char *ch : string array -> we can use offset!
		  print_hex_ascii_line is print format for every line.
		  in this function, we just setting an option to print.
  131 - 202	: 
