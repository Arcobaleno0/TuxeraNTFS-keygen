patcher = TuxeraNTFS-patcher
keygen = TuxeraNTFS-keygen

openssl_include_path = /usr/local/opt/openssl/include
openssl_lib_path = /usr/local/opt/openssl/lib

keygen: TuxeraNTFS-keygen.c helper.c
	gcc -std=c11 -I$(openssl_include_path) -L$(openssl_lib_path) -lcrypto -largon2 TuxeraNTFS-keygen.c helper.c -o $(keygen)

patcher: TuxeraNTFS-patcher.c helper.c
	gcc -std=c11 -I$(openssl_include_path) -L$(openssl_lib_path) -lcrypto TuxeraNTFS-patcher.c helper.c -o $(patcher)

clean:
ifeq ($(wildcard $(patcher)), $(patcher))
	rm $(patcher)
endif

ifeq ($(wildcard $(keygen)), $(keygen))
	rm $(keygen)
endif

