#!/proc/boot/sh

SCRIPT_STATUS_SUCCESS="[IF-CONFIG-SUCCESS]"
SCRIPT_STATUS_FAILED="[IF-CONFIG-FAILED]"

fail() {
    echo ${SCRIPT_STATUS_FAILED}
    exit 1
}

success() {
    echo ${SCRIPT_STATUS_SUCCESS}
    exit 0
}

set_ip_address() {
    # $1 - port (interface name)
    # $2 - address
    # $3 - netmask
    # $4 - gateway (not used)
    echo "Setting ip address $2 netmask $3 on port $1"
    if ! ifconfig $1 $2 netmask $3; then
        echo "ERROR! Failed to set ip address"
        fail
    fi
}

set_link_up() {
    # $1 - port (interface name)
    echo "Setting link up on port $1"
    if ! ifconfig $1 up; then
        echo "ERROR! Falied to link up"
        fail
    fi
}

set_link_down() {
    # $1 - port (interface name)
    echo "Setting link down on port $1"
    if ! ifconfig $1 down; then
        echo "ERROR! Failed to link down"
        fail
    fi
}

set_speed() {
    # $1 - port (interface name)
    # $2 - link speed
    echo "Setting link speed $2 on port $1"
    if [ $2 = "10G" ]; then
        res = `ifconfig $1 media 10Gbase-T`
    fi
    if [ $2 = "5G" ]; then
        # Yes, the next line is correct
        res = `ifconfig $1 media 10baseT`
    fi
    if [ $2 = "2.5G" ]; then
        res = `ifconfig $1 media 2500baseSX`
    fi
    if [ $2 = "1G" ]; then
        res = `ifconfig $1 media 1000baseT`
    fi
    if [ $2 = "100M" ]; then
        res = `ifconfig $1 media 100baseTX`
    fi

    if ! ${res}; then
        echo "ERROR! Failed to set link speed"
        fail
    fi
}

set_mtu() {
    # $1 - port (interface name)
    # $2 - mtu
    echo "Setting mtu $2 on port $1"
    if ! ifconfig $1 mtu $2; then
        echo "ERROR! Failed to set MTU"
        fail
    fi
}

get_speed() {
    # $1 - port (interface name)
    echo "Getting link speed on port $1"
    if ifconfig $1 | grep media | grep 10Gbase-T; then
        echo "LINK SPEED = 10G"
        success
    fi
    # Yes, the next line is correct
    if ifconfig $1 | grep media | grep 10baseT; then
        echo "LINK SPEED = 5G"
        success
    fi
    if ifconfig $1 | grep media | grep 2500baseSX; then
        echo "LINK SPEED = 2.5G"
        success
    fi
    if ifconfig $1 | grep media | grep 1000baseT; then
        echo "LINK SPEED = 1G"
        success
    fi
    if ifconfig $1 | grep media | grep 100baseTX; then
        echo "LINK SPEED = 100M"
        success
    fi

    echo "LINK SPEED = NO_LINK"
}

while [ $# -gt 0 ]
    do
    key="$1"

    case ${key} in
        -c|--command)
        COMMAND="$2"
        shift 2
        ;;
        -p|--port)
        PORT="$2"
        shift 2
        ;;
        -a|--address)
        ADDRESS="$2"
        shift 2
        ;;
        -n|--netmask)
        NETMASK="$2"
        shift 2
        ;;
        -g|--gateway)
        GATEWAY="$2"
        shift 2
        ;;
        -s|--speed)
        SPEED="$2"
        shift 2
        ;;
        --mtu)
        MTU="$2"
        shift 2
        ;;
        *)    # unknown option
        echo "Unknown option ${key}"
        fail
        ;;
    esac
done

case $COMMAND in
    setip)
    set_ip_address ${PORT} ${ADDRESS} ${NETMASK}
    ;;
    linkup)
    set_link_up ${PORT}
    ;;
    linkdown)
    set_link_down ${PORT}
    ;;
    setspeed)
    set_speed ${PORT} ${SPEED}
    ;;
    setmtu)
    set_mtu ${PORT} ${MTU}
    ;;
    getspeed)
    get_speed ${PORT}
    ;;
    *)
    echo "ERROR! Unknown command specified"
    fail
esac

success
