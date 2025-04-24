#!/bin/bash
set -e

if [[ -z "$1" || -z "$2" ]]; then
  echo "❌ Usage: $0 YOUR_PUBLIC_IP_OR_FQDN CLIENT_NAME"
  exit 1
fi

PUBLIC_IP="$1"
CLIENT_NAME="$2"
EASYRSA_DIR=/etc/easy-rsa
OUTPUT_DIR=~/client-configs

# Validate IP or FQDN
if [[ "$PUBLIC_IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "✅ Valid IPv4 address: $PUBLIC_IP"
elif [[ "$PUBLIC_IP" =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
    echo "✅ Valid FQDN: $PUBLIC_IP"
    # Optional: Verify FQDN resolves
    if ! host "$PUBLIC_IP" >/dev/null 2>&1; then
        echo "❌ Warning: FQDN $PUBLIC_IP does not resolve. Proceeding anyway."
    fi
else
    echo "❌ Invalid IP or FQDN: $PUBLIC_IP"
    exit 1
fi

# Validate CLIENT_NAME
if ! [[ "$CLIENT_NAME" =~ ^[a-zA-Z0-9_-]+$ ]]; then
    echo "❌ Invalid CLIENT_NAME: $CLIENT_NAME. Use alphanumeric characters, hyphens, or underscores only."
    exit 1
fi

# Check internet connectivity
ping -c 1 8.8.8.8 >/dev/null 2>&1 || { echo "❌ No internet connection"; exit 1; }

# Check disk space
df -h /var/log | grep -q "100%" && { echo "❌ /var/log filesystem full"; exit 1; }

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

./easyrsa gen-req server nopass || { echo "❌ Failed to generate server req"; exit 1; }
./easyrsa sign-req server server <<EOF || { echo "❌ Failed to sign server cert"; exit 1; }
yes
EOF

./easyrsa gen-dh || { echo "❌ Failed to generate DH params"; exit 1; }
./easyrsa gen-crl || { echo "❌ Failed to generate CRL"; exit 1; }
openvpn --genkey --secret ta.key || { echo "❌ Failed to generate ta.key"; exit 1; }

./easyrsa gen-req "$CLIENT_NAME" nopass || { echo "❌ Failed to generate client req"; exit 1; }
./easyrsa sign-req client "$CLIENT_NAME" <<EOF || { echo "❌ Failed to sign client cert"; exit 1; }
yes
EOF

echo "💾 Backing up Easy-RSA directory..."
tar -czf ~/easy-rsa-backup-$(date +%F).tar.gz "$EASYRSA_DIR"
echo "✅ Backup saved to ~/easy-rsa-backup-$(date +%F).tar.gz"

echo "📁 Copying files to /etc/openvpn/..."
sudo mkdir -p /etc/openvpn/
sudo cp pki/ca.crt pki/private/server.key pki/issued/server.crt pki/dh.pem ta.key pki/crl.pem /etc/openvpn/
sudo chmod 600 ſ/etc/openvpn/{ca.crt,server.key,server.crt,dh.pem,ta.key}
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
sudo netfilter-persistent save

echo "🧱 Setting up UFW..."
if ! sudo ufw status | grep -q "active"; then
    echo "🧱 Enabling UFW..."
    sudo ufw --force enable
fi
sudo ufw allow 1194/udp
sudo ufw allow OpenSSH
sudo ufw reload
echo "⚠ If using a cloud provider, ensure port 1194/UDP is open in the security group/firewall."

echo "🚀 Starting and enabling OpenVPN service..."
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
chmod 600 "$OUTPUT_DIR/$CLIENT_NAME.ovpn"
if [[ ! -s "$OUTPUT_DIR/$CLIENT_NAME.ovpn" ]]; then
    echo "❌ Client config file is empty or not created."
    exit 1
fi

echo "✅ Client config created at: $OUTPUT_DIR/$CLIENT_NAME.ovpn"
echo "📌 Ensure the client uses OpenVPN 2.4 or later for compatibility."