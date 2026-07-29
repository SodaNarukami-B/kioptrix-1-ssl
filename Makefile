all:
	gcc ./master.c ./src/*/*.c -o ./bin/main
	./bin/main
