# etherping
A ping client and server for layer 2, implemented in C, using its own protocol ("Hardware Ethernet Location Protocol"). You can (and probably should) use it to test layer 2 routes in your network.

For protocoll reference, please refer to the included text file in the repository.

# Install

client: `gcc client.c -o client -O1 -pthread`

server: `gcc server.c -o server -O1`
