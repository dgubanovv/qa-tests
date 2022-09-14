#!/proc/boot/sh

SCRIPT_STATUS_SUCCESS="[OS-SUCCESS]"
SCRIPT_STATUS_FAILED="[OS-FAILED]"

fail() {
    echo ${SCRIPT_STATUS_FAILED}
    exit 1
}

success() {
    echo ${SCRIPT_STATUS_SUCCESS}
    exit 0
}

while [ $# -gt 0 ]
    do
    key="$1"

    case ${key} in
        -c|--command)
        COMMAND="$2"
        shift 2
        ;;
        *)    # unknown option
        echo "Unknown option ${key}"
        fail
        ;;
    esac
done

case $COMMAND in
    getname)
    echo "OS = QNX"
    ;;
    *)
    echo "ERROR! Unknown command specified"
    fail
esac

success