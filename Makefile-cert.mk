cert-req: req.pem
cert cert-req: QMAIL/control/clientcert.pem
	@:

QMAIL/control/clientcert.pem: QMAIL/control/servercert.pem
	ln -s $< $@

QMAIL/control/servercert.pem:
	PATH=$$PATH:/usr/local/ssl/bin \
		openssl req -new -newkey rsa:4096 -x509 -nodes -days 366 -out $@ -keyout $@
	chmod 640 $@
	chown `head -9 conf-users | tail -1`:`head -3 conf-groups | tail -1` $@

req.pem:
	PATH=$$PATH:/usr/local/ssl/bin openssl req \
		-new -newkey rsa:4096 -nodes -out $@ -keyout QMAIL/control/servercert.pem
	chmod 640 QMAIL/control/servercert.pem
	chown `head -9 conf-users | tail -1`:`head -3 conf-groups | tail -1` QMAIL/control/servercert.pem
	@echo
	@echo "Send req.pem to your CA to obtain signed_req.pem, and do:"
	@echo "cat signed_req.pem >> QMAIL/control/servercert.pem"
