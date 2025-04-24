#!/bin/bash
set -e

if [[ -z "$1" ]]; then
  echo "❌ Usage: $0 YOUR_PUBLIC_IP"
  exit 1
fi

PUBLIC_IP="$1"
CLIENT_NAME="client1"
EASYRSA_DIR=~/openvpn-ca
OUTPUT_DIR=~/client-configs

echo "🧹 Cleaning up existing OpenVPN/Easy-RSA setup..."
sudo systemctl stop openvpn@server || true
sudo systemctl stop openvpn || true
sudo systemctl disable openvpn@server || true
sudo systemctl disable openvpn || true
sudo killall openvpn || true
sudo apt purge -y openvpn easy-rsa
sudo rm -rf /etc/openvpn/ /var/log/openvpn/ /etc/easy-rsa/
sudo apt autoremove -y
sudo apt update

echo "📦 Installing OpenVPN and Easy-RSA..."
sudo apt install -y openvpn easy-rsa iptables-persistent

echo "🔧 Setting up Easy-RSA..."
mkdir -p "$EASYRSA_DIR"
cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
cd "$EASYRSA_DIR"

cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "CA"
set_var EASYRSA_REQ_PROVINCE   "NS"
set_var EASYRSA_REQ_CITY       "Halifax"
set_var EASYRSA_REQ_ORG        "SomaDetect"
set_var EASYRSA_REQ_EMAIL      "lucas@somadetect.com"
set_var EASYRSA_REQ_OU         "AI"
EOF

./easyrsa init-pki
./easyrsa build-ca nopass <<EOF
yes
EOF

./easyrsa gen-req server nopass
./easyrsa sign-req server server <<EOF
yes
EOF

./easyrsa gen-dh
./easyrsa gen-crl
openvpn --genkey --secret ta.key

./easyrsa gen-req "$CLIENT_NAME" nopass
./easyrsa sign-req client "$CLIENT_NAME" <<EOF
yes
EOF

echo "📁 Copying files to /etc/openvpn/..."
sudo mkdir -p /etc/openvpn/
sudo cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key /etc/openvpn/
sudo cp pki/crl.pem /etc/openvpn/
sudo chown nobody:nogroup /etc/openvpn/crl.pem

echo "📝 Creating OpenVPN server config..."
sudo tee /etc/openvpn/server.conf > /dev/null <<EOF
port 1194
proto udp
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA256
tls-auth ta.key 0
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
keepalive 10 120
cipher AES-256-CBC
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 3
crl-verify crl.pem
EOF

echo "🌐 Enabling IP forwarding..."
sudo sed -i '/net.ipv4.ip_forward=1/ d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

NIC=$(ip -o -4 route show default | awk '{print $5}')
if [[ -z "$NIC" ]]; then
    echo "❌ Error: Could not detect network interface. Please set NIC manually."
    exit 1
fi
echo "🛡 Configuring iptables (interface: $NIC)..."
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
sudo netfilter-persistent save

echo "🧱 Setting up UFW..."
sudo ufw allow 1194/udp
sudo ufw allow OpenSSH
sudo ufw reload

echo "🚀 Starting and enabling OpenVPN service..."
sudo systemctl start openvpn@server
sudo systemctl enable openvpn@server
sleep 2
sudo journalctl -u openvpn@server --no-pager -n 15

echo "🛠 Creating client config..."
mkdir -p "$OUTPUT_DIR"

cat > "$OUTPUT_DIR/$CLIENT_NAME.ovpn" <<EOF
client
dev tun
proto udp
remote $PUBLIC_IP 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA256
cipher AES-256-CBC
key-direction 1
verb 3

<ca>
$(cat "$EASYRSA_DIR/pki/ca.crt")
</ca>
<cert>
$(cat "$EASYRSA_DIR/pki/issued/$CLIENT_NAME.crt")
</cert>
<key>
$(cat "$EASYRSA_DIR/pki/private/$CLIENT_NAME.key")
</key>
<tls-auth>
$(cat "$EASYRSA_DIR/ta.key")
</tls-auth>
EOF

echo "✅ Client config created at: $OUTPUT_DIR/$CLIENT_NAME.ovpn"
