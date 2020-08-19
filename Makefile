
all: test
	
test:
	clang -g test_merkle_tree.c -I./deps && ./a.out
