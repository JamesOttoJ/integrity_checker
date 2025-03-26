integrity_check_fast: integrity_check
	upx -ointegrity_check_fast integrity_check

integrity_check: integrity_check.c
	gcc integrity_check.c -lcrypto -lcurl -o integrity_check
	