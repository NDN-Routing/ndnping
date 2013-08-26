ACLOCAL_AMFLAGS = -I build-aux -I m4

bin_PROGRAMS = ndnping ndnpingserver

ndnping_SOURCES = ndnping.c
ndnping_CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes -fPIC -pie @NDN_INCLUDES@ @OPENSSL_INCLUDES@
ndnping_LDFLAGS = @NDN_LDFLAGS@ @OPENSSL_LDFLAGS@ @NDN_LIBS@ @OPENSSL_LIBS@

ndnpingserver_SOURCES = ndnpingserver.c
ndnpingserver_CFLAGS = -g -Wall -Wpointer-arith -Wreturn-type -Wstrict-prototypes -fPIC -pie @NDN_INCLUDES@ @OPENSSL_INCLUDES@
ndnpingserver_LDFLAGS = @NDN_LDFLAGS@ @OPENSSL_LDFLAGS@ @NDN_LIBS@ @OPENSSL_LIBS@
