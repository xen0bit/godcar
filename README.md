# godcar
Golang Implementation of DCAR (Packet Editing)

# Install Dependencies & Build
apt install libnetfilter-queue-dev

go build -o godcar godrcar.go

# Start listener on nfqueue 0
sudo ./godcar

# Route Packets into the Queue for processing
sudo iptables -A OUTPUT -p tcp --dport 9999 -j NFQUEUE --queue-num 0

Any instance of "magic string" destined for tcp port 9999 will be replaced with "modifiedvalue" with the correct checksums applied.
