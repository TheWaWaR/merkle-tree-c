
all: test
	
test:
	clang -g test_merkle_tree.c -I. && ./a.out
