# NDPeekr
A Golang agent for monitoring NDP traffic events to sus out v6 addresses on the network.

TODO:
Reduce messaging to a running tally of addresses, messages and, intervals seen for inventory building. 


## Run it
```
go mod tidy
sudo go run . -log-level=info
```
This will require to run as `sudo` for low level access needed in the listener.

### To restrict to a single interface
```
sudo go run . -iface=eth0
```

### Adjustments
The script has been adjusted to keep a running tally and refresh the windo every 2 seconds. It also has a default window of 15 minutes to keep results so things time out over time. To run with these news flags: 
```aiignore
sudo go run . -- window 2m --refresh 1s
# or
sudo ./NDPeekr --window 2m --refresh 1s
```