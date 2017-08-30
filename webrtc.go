/*
 * Webrtc chat demo.
 * Send chat messages via webrtc, over go.
 * Can interop with the JS client. (Open chat.html in a browser)
 *
 * To use: `go run chat.go`
 */
package main

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"os/user"
	"path"
	"strings"

	"github.com/keroserene/go-webrtc"
)

const (
	PKG_NAME = "webrtcvpn"
)

var pc *webrtc.PeerConnection
var dc *webrtc.DataChannel
var mode Mode
var err error
var username = "Alice"

// Janky state machine.
type Mode int

const (
	ModeInit Mode = iota
	ModeConnect
	ModeChat
)

//
// Preparing SDP messages for signaling.
// generateOffer and generateAnswer are expected to be called within goroutines.
// It is possible to send the serialized offers or answers immediately upon
// creation, followed by subsequent individual ICE candidates.
//
// However, to ease the user's copy & paste experience, in this case we forgo
// the trickle ICE and wait for OnIceComplete to fire, which will contain
// a full SDP mesasge with all ICE candidates, so the user only has to copy
// one message.
//

func generateOffer() {
	log.Println("Generating offer...")
	offer, err := pc.CreateOffer() // blocking
	if err != nil {
		log.Println(err)
		return
	}
	pc.SetLocalDescription(offer)
}

func generateAnswer() {
	log.Println("Generating answer...")
	answer, err := pc.CreateAnswer() // blocking
	if err != nil {
		log.Println(err)
		return
	}
	pc.SetLocalDescription(answer)
}

func receiveDescription(sdp *webrtc.SessionDescription) {
	err = pc.SetRemoteDescription(sdp)
	if nil != err {
		log.Println("ERROR", err)
		return
	}
	log.Println("SDP " + sdp.Type + " successfully received.")
	if "offer" == sdp.Type {
		go generateAnswer()
	}
}

// Manual "copy-paste" signaling channel.
func signalSend(msg string) {
	log.Println("\n ---- Please copy the below to peer ---- \n")
	log.Println(msg + "\n")

	u, err := user.Current()
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(
		path.Join(u.HomeDir, "."+PKG_NAME+"-send-to-peer"),
		[]byte(msg),
		0400,
	)
	if err != nil {
		log.Fatal(err)
	}
}

func signalReceive(msg string) {
	var parsed map[string]interface{}
	err = json.Unmarshal([]byte(msg), &parsed)
	if nil != err {
		// log.Println(err, ", try again.")
		return
	}

	// If this is a valid signal and no PeerConnection has been instantiated,
	// start as the "answerer."
	if nil == pc {
		start(false)
	}

	if nil != parsed["sdp"] {
		sdp := webrtc.DeserializeSessionDescription(msg)
		if nil == sdp {
			log.Println("Invalid SDP.")
			return
		}
		receiveDescription(sdp)
	}

	// Allow individual ICE candidate messages, but this won't be necessary if
	// the remote peer also doesn't use trickle ICE.
	if nil != parsed["candidate"] {
		ice := webrtc.DeserializeIceCandidate(msg)
		if nil == ice {
			log.Println("Invalid ICE candidate.")
			return
		}
		pc.AddIceCandidate(*ice)
		log.Println("ICE candidate successfully received.")
	}
}

// Attach callbacks to a newly created data channel.
// In this demo, only one data channel is expected, and is only used for chat.
// But it is possible to send any sort of bytes over a data channel, for many
// more interesting purposes.
func prepareDataChannel(channel *webrtc.DataChannel) {
	channel.OnOpen = func() {
		log.Println("Data Channel Opened!")
		startChat()
	}
	channel.OnClose = func() {
		log.Println("Data Channel closed.")
		endChat()
	}
	channel.OnMessage = func(msg []byte) {
		receiveChat(string(msg))
	}
}

func startChat() {
	mode = ModeChat
	log.Println("------- chat enabled! -------")
}

func endChat() {
	mode = ModeInit
	log.Println("------- chat disabled -------")
}

func sendChat(msg string) {
	line := username + ": " + msg
	log.Println("[sent]")
	dc.Send([]byte(line))
}

func receiveChat(msg string) {
	log.Println("\n" + string(msg))
}

// Janky /command inputs.
func parseCommands(input string) bool {
	if !strings.HasPrefix(input, "/") {
		return false
	}
	cmd := strings.TrimSpace(strings.TrimLeft(input, "/"))
	switch cmd {
	case "quit":
		log.Println("Disconnecting chat session...")
		dc.Close()
	case "status":
		log.Println("WebRTC PeerConnection Configuration:\n", pc.GetConfiguration())
		log.Println("Signaling State: ", pc.SignalingState())
		log.Println("Connection State: ", pc.ConnectionState())
	case "help":
		showCommands()
	default:
		log.Println("Unknown command:", cmd)
		showCommands()
	}
	return true
}

func showCommands() {
	log.Println("Possible commands: help status quit")
}

// Create a PeerConnection.
// If |instigator| is true, create local data channel which causes a
// negotiation-needed, leading to preparing an SDP offer to be sent to the
// remote peer. Otherwise, await an SDP offer from the remote peer, and send an
// answer back.
func start(instigator bool) {
	mode = ModeConnect
	log.Println("Starting up PeerConnection...")
	// TODO: Try with TURN servers.
	config := webrtc.NewConfiguration(
		webrtc.OptionIceServer("stun:stun.l.google.com:19302"))

	pc, err = webrtc.NewPeerConnection(config)
	if nil != err {
		log.Println("Failed to create PeerConnection.")
		return
	}

	// OnNegotiationNeeded is triggered when something important has occurred in
	// the state of PeerConnection (such as creating a new data channel), in which
	// case a new SDP offer must be prepared and sent to the remote peer.
	pc.OnNegotiationNeeded = func() {
		go generateOffer()
	}
	// Once all ICE candidates are prepared, they need to be sent to the remote
	// peer which will attempt reaching the local peer through NATs.
	pc.OnIceComplete = func() {
		log.Println("Finished gathering ICE candidates.")
		sdp := pc.LocalDescription().Serialize()
		signalSend(sdp)
	}
	/*
		pc.OnIceGatheringStateChange = func(state webrtc.IceGatheringState) {
			log.Println("Ice Gathering State:", state)
			if webrtc.IceGatheringStateComplete == state {
				// send local description.
			}
		}
	*/
	// A DataChannel is generated through this callback only when the remote peer
	// has initiated the creation of the data channel.
	pc.OnDataChannel = func(channel *webrtc.DataChannel) {
		log.Println("Datachannel established by remote... ", channel.Label())
		dc = channel
		prepareDataChannel(channel)
	}

	if instigator {
		// Attempting to create the first datachannel triggers ICE.
		log.Println("Initializing datachannel....")
		dc, err = pc.CreateDataChannel("test", webrtc.Init{})
		if nil != err {
			log.Println("Unexpected failure creating Channel.")
			return
		}
		prepareDataChannel(dc)
	}
}

func main() {
	webrtc.SetLoggingVerbosity(1)
	mode = ModeInit
	reader := bufio.NewReader(os.Stdin)

	f, err := os.OpenFile("go-webrtc-logfile", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("error opening file: %v", err)
	}
	defer f.Close()

	log.SetOutput(f)

	wait := make(chan int, 1)
	log.Println("=== go-webrtc chat demo ===")
	log.Println("What is your username?")
	username, _ = reader.ReadString('\n')
	username = strings.TrimSpace(username)

	log.Println("Welcome, " + username + "!")
	log.Println("To initiate a WebRTC PeerConnection, type \"start\".")
	log.Println("(Alternatively, immediately input SDP messages from the peer.)")

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		log.Println("Demo interrupted. Disconnecting...")
		if nil != dc {
			dc.Close()
		}
		if nil != pc {
			pc.Close()
		}
		os.Exit(1)
	}()

	// Input loop.
	for {
		text, _ := reader.ReadString('\n')
		switch mode {
		case ModeInit:
			if strings.HasPrefix(text, "start") {
				start(true)
			} else {
				signalReceive(text)
			}
		case ModeConnect:
			signalReceive(text)
		case ModeChat:
			// TODO: make chat interface nicer.
			if !parseCommands(text) {
				sendChat(text)
			}
			// log.Print(username + ": ")
			break
		}
	}
	<-wait
	log.Println("done")
}
