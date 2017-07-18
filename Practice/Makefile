main : main.o
	gcc -o main main.o -lpcap

main.o : main.c
	gcc -c -o main.o main.c -lpcap

clean : rm *.o main
