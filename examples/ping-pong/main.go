package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/pion/ice/v2"
	"github.com/pion/randutil"
)

//nolint
var (
	isControlling bool
	isServer      bool

	iceAgent              *ice.Agent
	remoteAuthChannel     chan string
	localCandidateChannel chan string

	remoteHTTPHost string
	remoteHTTPPort int
)

type CandidateInfo struct {
	Ufrag     string `json:"ufrag,omitempty"`
	Pwd       string `json:"pwd"`
	Candidate string `json:"candidate"`
}

// HTTP Listener to get ICE Credentials from remote Peer
func remoteAuth(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	remoteAuthChannel <- r.PostForm["ufrag"][0]
	remoteAuthChannel <- r.PostForm["pwd"][0]
	log.Printf("receive remote auth")

	// Get the local auth details and send to remote peer
	localUfrag, localPwd, err := iceAgent.GetLocalUserCredentials()
	if err != nil {
		panic(err)
	}

	c := &CandidateInfo{Ufrag: localUfrag, Pwd: localPwd}
	json.NewEncoder(w).Encode(c)
}

// HTTP Listener to get ICE Candidate from remote Peer
func remoteCandidate(w http.ResponseWriter, r *http.Request) {
	log.Printf("receive remote candidate")

	if err := r.ParseForm(); err != nil {
		panic(err)
	}

	c, err := ice.UnmarshalCandidate(r.PostForm["candidate"][0])
	if err != nil {
		panic(err)
	}

	if err := iceAgent.AddRemoteCandidate(c); err != nil {
		panic(err)
	}
	select {
	case localCandidate := <-localCandidateChannel:
		data := &CandidateInfo{Candidate: localCandidate}
		json.NewEncoder(w).Encode(data)
	case <-time.After(1 * time.Second):
		localCandidate := ""
		data := &CandidateInfo{Candidate: localCandidate}
		json.NewEncoder(w).Encode(data)
		log.Printf("no local candidate")
	}
}

// go run main.go -server
//  go run main.go -controlling
// export PION_LOG_TRACE=all
func main() { //nolint
	remoteAuthChannel = make(chan string, 3)

	flag.BoolVar(&isControlling, "controlling", false, "is ICE Agent controlling")

	flag.BoolVar(&isServer, "server", false, "is server")

	flag.Parse()
	remoteAuthChannel = make(chan string, 3)
	localCandidateChannel = make(chan string)

	remoteHTTPHost = "1.15.130.58:9001"
	//remoteHTTPHost = "localhost:9001"
	remoteHTTPPort = 9001

	if isServer {
		server()
	} else {
		client()
	}
}

func client() { //nolint
	var (
		err  error
		conn *ice.Conn
	)
	http.DefaultClient.Timeout = 3 * time.Second

	if isControlling {
		fmt.Println("Local Agent is controlling")
	} else {
		fmt.Println("Local Agent is controlled")
	}
	fmt.Print("Press 'Enter' when both processes have started")
	if _, err = bufio.NewReader(os.Stdin).ReadBytes('\n'); err != nil {
		panic(err)
	}

	iceAgent, err = ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
	})
	if err != nil {
		panic(err)
	}

	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		log.Printf("local candidate is : %s\n", c)

		resp, err := http.PostForm(fmt.Sprintf("http://%s/remoteCandidate", remoteHTTPHost), //nolint
			url.Values{
				"candidate": {c.Marshal()},
			})
		if err != nil {
			panic(err)
		}

		bytes, err := parseResp(resp)
		if err != nil {
			panic(err)
		}
		candidate := &CandidateInfo{}
		err = json.Unmarshal(bytes, candidate)
		if err != nil {
			panic(err)
		}

		if candidate.Candidate != "" {
			remoteCandidate, err := ice.UnmarshalCandidate(candidate.Candidate)
			if err != nil {
				panic(err)
			}
			if err := iceAgent.AddRemoteCandidate(remoteCandidate); err != nil {
				panic(err)
			}
			log.Printf("local candidate is : %s, remote candidate is %s\n", c, remoteCandidate)
		} else {
			log.Printf("local candidate is : %s, remote candidate is empty\n", c)
		}
	}); err != nil {
		panic(err)
	}

	// When ICE Connection state has change print to stdout
	if err = iceAgent.OnConnectionStateChange(func(c ice.ConnectionState) {
		fmt.Printf("ICE Connection State has changed: %s\n", c.String())
	}); err != nil {
		panic(err)
	}

	// Get the local auth details and send to remote peer
	localUfrag, localPwd, err := iceAgent.GetLocalUserCredentials()
	if err != nil {
		panic(err)
	}

	resp, err := http.PostForm(fmt.Sprintf("http://%s/remoteAuth", remoteHTTPHost), //nolint
		url.Values{
			"ufrag": {localUfrag},
			"pwd":   {localPwd},
		})
	if err != nil {
		panic(err)
	}
	bytes, err := parseResp(resp)
	if err != nil {
		panic(err)
	}
	candidate := &CandidateInfo{}
	err = json.Unmarshal(bytes, candidate)
	if err != nil {
		panic(err)
	}

	remoteUfrag := candidate.Ufrag
	remotePwd := candidate.Pwd
	log.Printf("remote ufrag pwd is : %s,%s\n", remoteUfrag, remotePwd)

	// todo 收集自身的candidate，然后将自身candidate，发送给对方
	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}

	// Start the ICE Agent. One side must be controlled, and the other must be controlling
	if isControlling {
		conn, err = iceAgent.Dial(context.TODO(), remoteUfrag, remotePwd)
	} else {
		conn, err = iceAgent.Accept(context.TODO(), remoteUfrag, remotePwd)
	}
	if err != nil {
		panic(err)
	}

	// Send messages in a loop to the remote peer
	go func() {
		for {
			time.Sleep(time.Second * 3)

			val, err := randutil.GenerateCryptoRandomString(15, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err != nil {
				panic(err)
			}
			if _, err = conn.Write([]byte(val)); err != nil {
				panic(err)
			}

			fmt.Printf("Sent: '%s'\n", val)
		}
	}()

	// Receive messages in a loop from the remote peer
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Received: '%s'\n", string(buf[:n]))
	}
}

func server() { //nolint
	var (
		err  error
		conn *ice.Conn
	)

	http.HandleFunc("/remoteAuth", remoteAuth)
	http.HandleFunc("/remoteCandidate", remoteCandidate)
	go func() {
		if err = http.ListenAndServe(fmt.Sprintf(":%d", remoteHTTPPort), nil); err != nil {
			panic(err)
		}
	}()

	if isControlling {
		fmt.Println("Local Agent is controlling")
	} else {
		fmt.Println("Local Agent is controlled")
	}
	fmt.Print("Press 'Enter' when both processes have started")
	if _, err = bufio.NewReader(os.Stdin).ReadBytes('\n'); err != nil {
		panic(err)
	}

	iceAgent, err = ice.NewAgent(&ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4},
		NAT1To1IPs:[]string{"1.15.130.58"},
	})
	if err != nil {
		panic(err)
	}

	// When we have gathered a new ICE Candidate send it to the remote peer
	if err = iceAgent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}

		log.Printf("local candidate is : %s\n", c)
		localCandidateChannel <- c.Marshal()
	}); err != nil {
		panic(err)
	}

	// When ICE Connection state has change print to stdout
	if err = iceAgent.OnConnectionStateChange(func(c ice.ConnectionState) {
		fmt.Printf("ICE Connection State has changed: %s\n", c.String())
	}); err != nil {
		panic(err)
	}

	remoteUfrag := <-remoteAuthChannel
	remotePwd := <-remoteAuthChannel

	// todo 收集自身的candidate，然后将自身candidate，发送给对方
	if err = iceAgent.GatherCandidates(); err != nil {
		panic(err)
	}

	// Start the ICE Agent. One side must be controlled, and the other must be controlling
	if isControlling {
		conn, err = iceAgent.Dial(context.TODO(), remoteUfrag, remotePwd)
	} else {
		conn, err = iceAgent.Accept(context.TODO(), remoteUfrag, remotePwd)
	}
	if err != nil {
		panic(err)
	}

	// Send messages in a loop to the remote peer
	go func() {
		for {
			time.Sleep(time.Second * 3)

			val, err := randutil.GenerateCryptoRandomString(15, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
			if err != nil {
				panic(err)
			}
			if _, err = conn.Write([]byte(val)); err != nil {
				panic(err)
			}

			fmt.Printf("Sent: '%s'\n", val)
		}
	}()

	// Receive messages in a loop from the remote peer
	buf := make([]byte, 1500)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Received: '%s'\n", string(buf[:n]))
	}
}

func parseResp(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()

	// check response
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode > 399 { // error
		return nil, err
	}

	return body, err
}
