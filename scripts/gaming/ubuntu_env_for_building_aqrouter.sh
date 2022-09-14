## https://free-proxy-list.net/
PROXY=http://91.146.251.138:8080
LIBUBOX_GIT=http://git.openwrt.org/project/libubox.git
UBUS_GIT=http://git.openwrt.org/project/ubus.git
USTREAM_SSL_GIT=http://git.openwrt.org/project/ustream-ssl.git
## same author as here: https://openwrt.org/packages/pkgdata/libuhttpd-openssl
LIBUHTTPD_GIT=http://github.com/zhaojh329/libuhttpd.git


rm -rf /tmp/sandbox
mkdir /tmp/sandbox
cd /tmp/sandbox
BASEPATH="$(pwd)"

apt-get update
apt-get install -y pkg-config uuid-dev libjson-c-dev libnl-genl-3-dev
ln -s /usr/lib/x86_64-linux-gnu/libnl-route-3.so.200 /usr/lib/x86_64-linux-gnu/libnl-route-3.so

export http_proxy=$PROXY

git clone $LIBUBOX_GIT
cd libubox
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_LUA=off
make
make install
cd $BASEPATH

git clone $UBUS_GIT
cd ubus
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_LUA=off
make
make install
cd $BASEPATH

git clone $USTREAM_SSL_GIT
cd ustream-ssl
mkdir build && cd build
cmake .. -DCMAKE_INSTALL_PREFIX=/usr
make
make install
cd $BASEPATH

git clone $LIBUHTTPD_GIT
cd libuhttpd
mkdir build && cd build
cmake .. -L -DCMAKE_INSTALL_PREFIX=/usr
cmake .. -LH
make
make install
cd $BASEPATH
