all: tunslip6 webrtc

tunslip6: tunslip6.c util.c
	$(CC) -o $@ $(CFLAGS) $(LIBS) tunslip6.c util.c

webrtc: webrtc.go
	go build -o $@ webrtc.go

clean:
	rm -f tunslip6 webrtc
