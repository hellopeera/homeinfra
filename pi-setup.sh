#!/bin/bash

# Update
apt-get update
apt-get upgrade -y
apt-get install -y vim rsync git iotop lsof dnsutils net-tools chrony man curl
apt-get remove -y dhcpcd5
apt-get clean -y
apt-get autoclean -y
apt-get autoremove -y

# DNS Options
test -e /etc/resolv.conf \
  && sed -i -r '/options / d' /etc/resolv.conf
echo 'options timeout:1' >> /etc/resolv.conf
echo 'options attempts:2' >> /etc/resolv.conf

# Disable ipv6
grep 'ipv6.disable=1' /boot/cmdline.txt &>/dev/null || sed -i -r 's/^(.*)$/\1 ipv6.disable=1/' /boot/cmdline.txt

# Disable wireless communication
rfkill block all
mv /etc/profile.d/wifi-check.sh /etc/profile.d/wifi-check.sh.disabled
cat > /etc/modprobe.d/raspi-blacklist.conf << EOF
# Wifi
blacklist brcmfmac
blacklist brcmutil

# Bluetooth
blacklist bluetooth
blacklist btrtl
blacklist btqca
blacklist btsdio
blacklist btintel
blacklist hci_uart
blacklist btbcm
blacklist hci_uart
EOF

# Disable dhcp
apt-get remove -y dhcpcd5
apt-get clean -y
apt-get autoclean -y
apt-get autoremove -y

# Disable unused services
systemctl disable --now wpa_supplicant.service
systemctl disable --now rsync
systemctl disable --now systemd-resolved

# Timezone
rm -f /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Bangkok /etc/localtime

# User defaults
sed -i -r 's/^PASS_MAX_DAYS.+$/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i -r 's/^PASS_MIN_DAYS.+$/PASS_MIN_DAYS   1/' /etc/login.defs
sed -i -r 's/^PASS_MIN_LEN.+$/PASS_MIN_LEN    8/' /etc/login.defs
sed -i -r 's/^PASS_WARN_AGE.+$/PASS_WARN_AGE   7/' /etc/login.defs
sed -i -r 's/^UMASK.+$/UMASK           027/' /etc/login.defs
cat /etc/shadow | awk -F: '{print $1}' | while read u; do chage -m -1 $u; done

# Delete unused users/groups
userdel news &>/dev/null
userdel games &>/dev/null
userdel gopher &>/dev/null
userdel apache &>/dev/null
userdel uucp &>/dev/null
groupdel news &>/dev/null
groupdel games &>/dev/null
groupdel gopher &>/dev/null
groupdel apache &>/dev/null
groupdel uucp &>/dev/null

# Disable logon banner
cat /dev/null > /etc/issue

# Set permissions
chmod 644 /etc/group /etc/passwd
chmod 640 ~/.bashrc
chmod 400 /etc/shadow /etc/crontab
chmod 755 /var/spool/cron
chown root:root /etc/group /etc/passwd /etc/shadow /etc/crontab

# Default umask
sed -i -r '/umask/ d' /etc/bash.bashrc
sed -i -r '/umask/ d' /etc/profile
echo 'umask 027' >> /etc/bash.bashrc
echo 'umask 027' >> /etc/profile

# Performance tuning
sed -i -r '/^vm.swappiness/ d' /etc/sysctl.conf
echo 'vm.swappiness = 1' >> /etc/sysctl.conf
sed -i '/net.ipv4.tcp_retries2/ d'  /etc/sysctl.conf
echo 'net.ipv4.tcp_retries2 = 5' >> /etc/sysctl.conf
# sed -i '/net.netfilter.nf_conntrack_max/ d' /etc/sysctl.conf
# echo 'net.netfilter.nf_conntrack_max = 262144' >> /etc/sysctl.conf
# echo 65536 > /sys/module/nf_conntrack/parameters/hashsize
# cat << EOF >/etc/modprobe.d/netfilter.conf
# options nf_conntrack hashsize=65536
# EOF

# Make system logs last longer
sed -i -r '/^rotate / c\rotate 12' /etc/logrotate.conf

# Clean motd
cat /dev/null > /etc/motd

# Create app user
userdel -r app &>/dev/null
useradd -u30000 --comment 'User for running applications' --create-home --shell /bin/bash app
chage --maxdays 99999 --mindays -1 app
chmod 700 /home/app

# Setup home path
for home in /root /home/app; do
  user=$(echo ${home}| awk -F/ '{print $NF}')

  # Correct permissions
  chmod 600 ${home}/.bash*

  # Setup SSH Keys
  mkdir -p ${home}/.ssh
  chmod 700 ${home}/.ssh
  touch ${home}/.ssh/authorized_keys
  chmod 600 ${home}/.ssh/authorized_keys
  chown -R ${user}:${user} ${home}/.ssh

  # Setup Bash Profile
  sed -i -r '/^PS1/ d' ${home}/.bashrc

  # Remove blank lines at the bottom
  while true; do
    tail -1 ${home}/.bashrc | egrep '^$' &>/dev/null && sed -i '$ d' ${home}/.bashrc || break
  done

  echo 'export PS1='"'"'[\t] \u@\h:$PWD # '"'"'' >> ${home}/.bashrc

  # Setup default alias
  sed -i -r '/^alias ls/ d' ${home}/.bashrc
  echo "alias ls='ls --color=auto'" >> ${home}/.bashrc
  sed -i -r '/^alias ll/ d' ${home}/.bashrc
  echo "alias ll='ls -l --color=auto'" >> ${home}/.bashrc
  sed -i -r '/^alias rm/ d' ${home}/.bashrc
  echo "alias rm='rm -i'" >> ${home}/.bashrc

  # Disable vim auto visual on mouse
  cat >${home}/.vimrc <<EOF
source /usr/share/vim/vim*/defaults.vim
set mouse-=a
EOF

done

# Configure /etc/hosts
IPADDRESS=$(ip address show $(ip route list | grep default | awk '{print $5}') | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)
NUMSPACE=$(( 15 - $(echo -n ${IPADDRESS} | wc -c) ))
if [[ "${NUMSPACE}" -gt "0" ]]; then
  SPACE="$(printf ' %.0s' {1..${NUMSPACE}})"
else
  SPACE=
fi
cat << EOF > /etc/hosts
127.0.0.1      localhost localhost.localdomain localhost4 localhost4.localdomain4
::1            localhost localhost.localdomain localhost6 localhost6.localdomain6

EOF
if [[ "$(hostname)" == "$(hostname -s)" ]]; then
  printf "%-14s %s %s\n" "${IPADDRESS}" "$(hostname)" >> /etc/hosts
else
  printf "%-14s %s %s\n" "${IPADDRESS}" "$(hostname) $(hostname -s)" >> /etc/hosts
fi

# Configure sshd
sed -i '/UseDNS/ c\UseDNS no' /etc/ssh/sshd_config
sed -i '/GSSAPIAuthentication/ c\GSSAPIAuthentication no' /etc/ssh/sshd_config
sed -i '/AllowAgentForwarding/ c\AllowAgentForwarding no' /etc/ssh/sshd_config
sed -i '/AllowTcpForwarding/ c\AllowTcpForwarding no' /etc/ssh/sshd_config
sed -i '/X11Forwarding/ c\X11Forwarding no' /etc/ssh/sshd_config
systemctl restart sshd

# Install docker
(umask 0022 && curl -fsSL https://get.docker.com | sh -)
sed -i '/net.ipv4.conf.all.forwarding/ d' /etc/sysctl.conf
echo 'net.ipv4.conf.all.forwarding = 1' >> /etc/sysctl.conf
sysctl -p
mkdir -p /etc/docker
cat << EOF >/etc/docker/daemon.json
{
  "bip": "192.168.64.1/24",
  "fixed-cidr": "192.168.64.0/24",
  "default-address-pools": [
    {
      "base": "192.168.64.0/18",
      "size": 24
    }
  ]
}
EOF
systemctl enable --now docker
systemctl restart docker

groupadd docker
usermod -aG docker app

# Upgrade libseccomp2 for newer docker reqs
# https://github.com/docker/for-linux/issues/1196
curl -O http://http.us.debian.org/debian/pool/main/libs/libseccomp/libseccomp2_2.5.1-1_armhf.deb
dpkg --install libseccomp2_2.5.1-1_armhf.deb


# Install docker-compose
docker pull linuxserver/docker-compose
container_id=$(docker run -d linuxserver/docker-compose)
docker cp ${container_id}:/usr/local/bin/docker-compose /usr/local/bin/docker-compose
docker stop ${container_id}
docker rm ${container_id}
docker image rm linuxserver/docker-compose
chmod 750 /usr/local/bin/docker-compose
chown root:docker /usr/local/bin/docker-compose

# Install k3s
node_ip=$(ip -br address | grep eth0 | egrep -o '[0-9\.]+/' | cut -d/ -f1)
cgroup_driver=$(docker info 2>/dev/null | sed -rn 's/^.*Cgroup Driver: (.*)$/\1/p')
curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION=v1.20.10+k3s1 sh -s - server \
  --node-name ${node_ip} \
  --node-external-ip ${node_ip} \
  --cluster-cidr 192.168.128.0/18 \
  --service-cidr 192.168.192.0/18 \
  --cluster-dns 192.168.192.10 \
  --cluster-domain k3s.home.arpa \
  --disable traefik \
  --docker \
  --kubelet-arg="cgroup-driver=${cgroup_driver}" \
  --write-kubeconfig-mode 640
  # --cluster-init

chmod 644 /etc/systemd/system/k3s.service

## Install bash-completion
apt-get install -y bash-completion
kubectl completion bash >/etc/bash_completion.d/kubectl

## Check
kubectl get all -A
kubectl get --raw='/readyz?verbose'

## Add routes to service cidr
cat > /etc/network/if-up.d/k3s-service-cidr << EOF
#!/bin/sh
if [ "\$IFACE" = "cni0" ]; then
    ip route add 192.168.192.0/18 dev cni0
fi
EOF
chmod 755 /etc/network/if-up.d/k3s-service-cidr

# Make k3s usable to app
groupadd k3s
chgrp k3s /etc/rancher/k3s/k3s.yaml
chgrp k3s /etc/bash_completion.d/kubectl
chmod 640 /etc/rancher/k3s/k3s.yaml
chmod 640 /etc/bash_completion.d/kubectl
usermod -aG k3s app
