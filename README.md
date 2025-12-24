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
