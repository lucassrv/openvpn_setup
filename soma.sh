#!/bin/bash
set -e

PUBLIC_IP="gpu.somadetect.com"
CLIENT_NAME="somadetect"
EASYRSA_DIR=/etc/easy-rsa
OUTPUT_DIR=~/client-configs


echo "🧹 Cleaning up existing OpenVPN/Easy-RSA setup..."
sudo systemctl stop openvpn@server || true
sudo systemctl stop openvpn || true
sudo systemctl disable openvpn@server || true
sudo systemctl disable openvpn || true
sudo pkill -u root openvpn || true
if pgrep openvpn >/dev/null; then
    echo "❌ OpenVPN processes still running."
    exit 1
fi
sudo apt purge -y openvpn easy-rsa
sudo rm -rf /etc/openvpn/ /var/log/openvpn/ /etc/easy-rsa/ /var/log/openvpn.log
sudo apt autoremove -y
sudo apt clean
sudo apt update

echo "📦 Installing OpenVPN and Easy-RSA..."
sudo DEBIAN_FRONTEND=noninteractive apt install -y openvpn easy-rsa iptables-persistent

echo "🔧 Setting up Easy-RSA..."
sudo mkdir -p "$EASYRSA_DIR"
sudo cp -r /usr/share/easy-rsa/* "$EASYRSA_DIR"
sudo chown -R root:root "$EASYRSA_DIR"
sudo chmod -R 700 "$EASYRSA_DIR"
cd "$EASYRSA_DIR"

cat > vars <<EOF
set_var EASYRSA_REQ_COUNTRY    "CA"
set_var EASYRSA_REQ_PROVINCE   "NS"
set_var EASYRSA_REQ_CITY       "Halifax"
set_var EASYRSA_REQ_ORG        "SomaDetect"
set_var EASYRSA_REQ_EMAIL      "lucas@somadetect.com"
set_var EASYRSA_REQ_OU         "AI"
EOF

./easyrsa init-pki || { echo "❌ Failed to initialize PKI"; exit 1; }
./easyrsa build-ca nopass <<EOF || { echo "❌ Failed to build CA"; exit 1; }
yes
EOF

./easyrsa build-server-full server nopass || { echo "❌ Failed to generate server cert"; exit 1; }
./easyrsa build-client-full "$CLIENT_NAME" nopass || { echo "❌ Failed to generate client cert"; exit 1; }

./easyrsa gen-dh || { echo "❌ Failed to generate DH params"; exit 1; }
./easyrsa gen-crl || { echo "❌ Failed to generate CRL"; exit 1; }
openvpn --genkey --secret ta.key || { echo "❌ Failed to generate ta.key"; exit 1; }

echo "💾 Backing up Easy-RSA directory..."
tar -czf ~/easy-rsa-backup-$(date +%F).tar.gz "$EASYRSA_DIR"
echo "✅ Backup saved to ~/easy-rsa-backup-$(date +%F).tar.gz"
echo "📌 To restore Easy-RSA, run: tar -xzf ~/easy-rsa-backup-$(date +%F).tar.gz -C /"

echo "📁 Copying files to /etc/openvpn/..."
sudo mkdir -p /etc/openvpn/
sudo cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key pki/crl.pem /etc/openvpn/
sudo chmod 600 /etc/openvpn/{ca.crt,server.key,server.crt,dh.pem,ta.key}
sudo chown root:root /etc/openvpn/{ca.crt,server.key,server.crt,dh.pem,ta.key}

if getent group nogroup >/dev/null; then
    GROUP=nogroup
else
    GROUP=nobody
fi
sudo chmod 640 /etc/openvpn/crl.pem
sudo chown root:$GROUP /etc/openvpn/crl.pem

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
group $GROUP
persist-key
persist-tun
status openvpn-status.log
log-append /var/log/openvpn.log
verb 4
crl-verify crl.pem
EOF

echo "📜 Setting up logging..."
sudo touch /var/log/openvpn.log
sudo chown nobody:$GROUP /var/log/openvpn.log
sudo chmod 640 /var/log/openvpn.log

echo "🌐 Enabling IP forwarding..."
sudo sed -i '/net.ipv4.ip_forward=1/ d' /etc/sysctl.conf
echo "net.ipv4.ip_forward=1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p

NIC=$(ip -o -4 route show default | awk '{print $5}')
if [[ -z "$NIC" ]]; then
    echo "❌ Error: Could not detect network interface."
    ip link show
    read -p "Enter the network interface (e.g., eth0): " NIC
    if [[ -z "$NIC" ]]; then
        echo "❌ No interface provided."
        exit 1
    fi
fi
echo "🛡 Configuring iptables (interface: $NIC)..."
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$NIC" -j MASQUERADE
sudo netfilter-persistent save || { echo "❌ Failed to save iptables rules"; exit 1; }

echo "🧱 Setting up UFW..."
if ! sudo ufw status | grep -q "active"; then
    echo "⚠ Ensure SSH is on port 22 or manually allowed in UFW to avoid lockout."
    echo "🧱 Enabling UFW..."
    sudo ufw --force enable
fi
sudo ufw allow 1194/udp
sudo ufw allow OpenSSH
sudo ufw reload
echo "⚠ If using a cloud provider, ensure port 1194/UDP is open in the security group/firewall."

echo "🚀 Starting and enabling OpenVPN service..."
lsmod | grep tun || { echo "❌ TUN module not loaded"; sudo modprobe tun || exit 1; }
if sudo netstat -tuln | grep -q ":1194"; then
    echo "❌ Port 1194 is already in use."
    exit 1
fi
for file in ca.crt server.crt server.key dh.pem ta.key crl.pem; do
    if [[ ! -f "/etc/openvpn/$file" ]]; then
        echo "❌ Missing file: /etc/openvpn/$file"
        exit 1
    fi
done
sudo systemctl start openvpn@server
# Check if the service is active
if systemctl is-active --quiet openvpn@server; then
    echo "✅ OpenVPN service started successfully."
    sudo systemctl enable openvpn@server
    sleep 2
    sudo journalctl -u openvpn@server --no-pager -n 30
else
    echo "❌ OpenVPN service failed to start. Check logs:"
    sudo journalctl -u openvpn@server --no-pager -n 30
    exit 1
fi

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
chmod 600 "$OUTPUT_DIR/$CLIENT_NAME.ovpn"
if [[ ! -s "$OUTPUT_DIR/$CLIENT_NAME.ovpn" ]]; then
    echo "❌ Client config file is empty or not created."
    exit 1
fi

echo "✅ Client config created at: $OUTPUT_DIR/$CLIENT_NAME.ovpn"
echo "📌 Ensure the client uses OpenVPN 2.4 or later for compatibility."