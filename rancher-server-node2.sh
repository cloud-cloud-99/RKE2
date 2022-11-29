export RED='\x1b[0;31m'
export GREEN='\x1b[32m'
export BLUE='\x1b[34m'
export YELLOW='\x1b[33m'
export NO_COLOR='\x1b[0m'


server=140.82.57.201
token=K10a38a1061123b20e37619cb0a96b408a9e5d52a9b44eaee624ffad04f5f8fa704::server:f5cbd339066afabb22a84ae3ca0743b1

ip=$(dig +short myip.opendns.com @resolver1.opendns.com)
domain=$ip.nip.io
password=Testtest

#or deploy rke2
# https://docs.rke2.io/install/methods/#enterprise-linux-8

snap install kubectl --classic > /dev/null 2>&1
snap install helm --classic > /dev/null 2>&1
snap install jq > /dev/null 2>&1

#host modifications

echo -e -n " adding os packages"
mkdir -p /opt/kube; 
systemctl stop ufw; 
systemctl disable ufw; 
echo -e "PubkeyAcceptedKeyTypes=+ssh-rsa" >> /etc/ssh/sshd_config; 
systemctl restart sshd; 
export DEBIAN_FRONTEND=noninteractive; 
apt update; > /dev/null 2>&1
apt install nfs-common -y;  > /dev/null 2>&1
#apt upgrade -y; apt autoremove -y' > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"

iptables -F

#kernel tuning
echo -e -n " updating kernel settings"
cat << EOF >> /etc/sysctl.conf
# SWAP settings
vm.swappiness=0
vm.panic_on_oom=0
vm.overcommit_memory=1
kernel.panic=10
kernel.panic_on_oops=1
vm.max_map_count = 262144
# Have a larger connection range available
net.ipv4.ip_local_port_range=1024 65000
# Increase max connection
net.core.somaxconn=10000
# Reuse closed sockets faster
net.ipv4.tcp_tw_reuse=1
net.ipv4.tcp_fin_timeout=15
# The maximum number of "backlogged sockets".  Default is 128.
net.core.somaxconn=4096
net.core.netdev_max_backlog=4096
# 16MB per socket - which sounds like a lot,
net.core.rmem_max=16777216
net.core.wmem_max=16777216
# Various network tunables
net.ipv4.tcp_max_syn_backlog=20480
net.ipv4.tcp_max_tw_buckets=400000
net.ipv4.tcp_no_metrics_save=1
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_syn_retries=2
net.ipv4.tcp_synack_retries=2
net.ipv4.tcp_wmem=4096 65536 16777216
# ARP cache settings for a highly loaded docker swarm
net.ipv4.neigh.default.gc_thresh1=8096
net.ipv4.neigh.default.gc_thresh2=12288
net.ipv4.neigh.default.gc_thresh3=16384
# ip_forward and tcp keepalive for iptables
net.ipv4.tcp_keepalive_time=600
net.ipv4.ip_forward=1
# monitor file system events
fs.inotify.max_user_instances=8192
fs.inotify.max_user_watches=1048576
EOF
sysctl -p > /dev/null 2>&1
echo -e "$GREEN" "ok" "$NO_COLOR"

export NO_PROXY=.svc,.cluster.local


echo -e -n " deploying rke2 "

mkdir -p /etc/rancher/rke2/ /var/lib/rancher/rke2/server/manifests/; 
useradd -r -c "etcd user" -s /sbin/nologin -M etcd -U; 
echo -e "apiVersion: audit.k8s.io/v1\nkind: Policy\nrules:\n- level: RequestResponse" > /etc/rancher/rke2/audit-policy.yaml; 
#echo -e "\n#profile: cis-1.6\nselinux: true\nsecrets-encryption: true\nwrite-kubeconfig-mode: 0640\nstreaming-connection-idle-timeout: 5m\nkube-controller-manager-arg:\n- bind-address=127.0.0.1\n- use-service-account-credentials=true\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-scheduler-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\nkube-apiserver-arg:\n- tls-min-version=VersionTLS12\n- tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384\n- authorization-mode=RBAC,Node\n- anonymous-auth=false\n- audit-policy-file=/etc/rancher/rke2/audit-policy.yaml\n- audit-log-mode=blocking-strict\n- audit-log-maxage=30\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml; 
echo -e "---\napiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: rke2-ingress-nginx\n  namespace: kube-system\nspec:\n  valuesContent: |-\n    controller:\n      config:\n        use-forwarded-headers: true\n      extraArgs:\n        enable-ssl-passthrough: true" > /var/lib/rancher/rke2/server/manifests/rke2-ingress-nginx-config.yaml; 

echo -e "server: https://"$server":9345\ntoken: "$token"\nwrite-kubeconfig-mode: 0640\n#profile: cis-1.6\nkube-apiserver-arg:\n- authorization-mode=RBAC,Node\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml

curl -sfL https://get.rke2.io | sh - 
 sleep 10
 
systemctl enable rke2-server.service
systemctl start rke2-server.service


 sleep 30
 
  
 # simlink all the things - kubectl
 ln -s $(find /var/lib/rancher/rke2/data/ -name kubectl) /usr/local/bin/kubectl
 
 # add kubectl conf
 export KUBECONFIG=/etc/rancher/rke2/rke2.yaml PATH=$PATH:/var/lib/rancher/rke2/bin
 cp /etc/rancher/rke2/rke2.yaml ~/.kube/config > /dev/null 2>&1

 

# token=$(ssh root@$server 'cat /var/lib/rancher/rke2/server/node-token')
# pdsh -l root -w $worker_list 'curl -sfL https://get.rke2.io | INSTALL_RKE2_CHANNEL='$rke2_channel' INSTALL_RKE2_TYPE=agent sh - && systemctl enable rke2-agent.service && mkdir -p /etc/rancher/rke2/ && echo -e "server: https://"'$server'":9345\ntoken: "'$token'"\nwrite-kubeconfig-mode: 0640\n#profile: cis-1.6\nkube-apiserver-arg:\n- authorization-mode=RBAC,Node\nkubelet-arg:\n- protect-kernel-defaults=true\n- read-only-port=0\n- authorization-mode=Webhook" > /etc/rancher/rke2/config.yaml && systemctl start rke2-agent.service' > /dev/null 2>&1
# rsync -avP root@$server:/etc/rancher/rke2/rke2.yaml ~/.kube/config > /dev/null 2>&1
# sed -i'' -e "s/127.0.0.1/$server/g" ~/.kube/config 

echo -e "$GREEN" "ok" "$NO_COLOR"

 echo -e -n " - cluster active "
 sleep 5
 until [ $(kubectl get node|grep NotReady|wc -l) = 0 ]; do echo -e -n "."; sleep 2; done
 echo -e "$GREEN" "ok" "$NO_COLOR"

