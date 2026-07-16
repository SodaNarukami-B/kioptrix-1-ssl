all:
	gcc ./master.c ./src/*/module.c -o ./bin/main
	./bin/main
