* sslstrip by default works on port 10000
* Analyzes only packets which pass through port 10000
* We need to redirect any packet which comes to my cp to port 10000
* In order to do so we use iptables command

```shell
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000
```
