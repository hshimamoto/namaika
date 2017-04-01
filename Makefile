ika: ika.c
	gcc -g -O2 -Wall -o $@ $<

clean:
	rm -f ika
