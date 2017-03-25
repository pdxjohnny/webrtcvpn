all: tunslip6 webrtc

tunslip6: tunslip6.c
	$(CC) -o $@ $(CFLAGS) $(LIBS) tunslip6.c

webrtc: webrtc.go
	go build -o $@ webrtc.go

clean:
	rm -f tunslip6 webrtc
