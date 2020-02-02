#!/bin/bash
set -u


DATADIR=./benchmark-datadir
SHA256CMD="$(command -v sha256sum || echo shasum)"
SHA256ARGS="$(command -v sha256sum >/dev/null || echo '-a 256')"

function arnak_rpc {
    ./src/arnak-cli -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 "$@"
}

function arnak_rpc_slow {
    # Timeout of 1 hour
    arnak_rpc -rpcclienttimeout=3600 "$@"
}

function arnak_rpc_veryslow {
    # Timeout of 2.5 hours
    arnak_rpc -rpcclienttimeout=9000 "$@"
}

function arnak_rpc_wait_for_start {
    arnak_rpc -rpcwait getinfo > /dev/null
}

function arnakd_generate {
    arnak_rpc generate 101 > /dev/null
}

function extract_benchmark_datadir {
    if [ -f "$1.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
$2  $1.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "$1.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        arnakd_stop
        echo
        echo "Please download it and place it in the base directory of the repository."
        exit 1
    fi
    xzcat "$1.tar.xz" | tar x
}

function use_200k_benchmark {
    rm -rf benchmark-200k-UTXOs
    extract_benchmark_datadir benchmark-200k-UTXOs dc8ab89eaa13730da57d9ac373c1f4e818a37181c1443f61fd11327e49fbcc5e
    DATADIR="./benchmark-200k-UTXOs/node$1"
}

function arnakd_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to arnakd_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/arnak.conf"
    esac
    ./src/arnakd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ARNAKD_PID=$!
    arnak_rpc_wait_for_start
}

function arnakd_stop {
    arnak_rpc stop > /dev/null
    wait $ARNAKD_PID
}

function arnakd_massif_start {
    case "$1" in
        sendtoaddress|loadwallet|listunspent)
            case "$2" in
                200k-recv)
                    use_200k_benchmark 0
                    ;;
                200k-send)
                    use_200k_benchmark 1
                    ;;
                *)
                    echo "Bad arguments to arnakd_massif_start."
                    exit 1
            esac
            ;;
        *)
            rm -rf "$DATADIR"
            mkdir -p "$DATADIR/regtest"
            touch "$DATADIR/arnak.conf"
    esac
    rm -f massif.out
    valgrind --tool=massif --time-unit=ms --massif-out-file=massif.out ./src/arnakd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ARNAKD_PID=$!
    arnak_rpc_wait_for_start
}

function arnakd_massif_stop {
    arnak_rpc stop > /dev/null
    wait $ARNAKD_PID
    ms_print massif.out
}

function arnakd_valgrind_start {
    rm -rf "$DATADIR"
    mkdir -p "$DATADIR/regtest"
    touch "$DATADIR/arnak.conf"
    rm -f valgrind.out
    valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/arnakd -regtest -datadir="$DATADIR" -rpcuser=user -rpcpassword=password -rpcport=5983 -showmetrics=0 &
    ARNAKD_PID=$!
    arnak_rpc_wait_for_start
}

function arnakd_valgrind_stop {
    arnak_rpc stop > /dev/null
    wait $ARNAKD_PID
    cat valgrind.out
}

function extract_benchmark_data {
    if [ -f "block-107134.tar.xz" ]; then
        # Check the hash of the archive:
        "$SHA256CMD" $SHA256ARGS -c <<EOF
4bd5ad1149714394e8895fa536725ed5d6c32c99812b962bfa73f03b5ffad4bb  block-107134.tar.xz
EOF
        ARCHIVE_RESULT=$?
    else
        echo "block-107134.tar.xz not found."
        ARCHIVE_RESULT=1
    fi
    if [ $ARCHIVE_RESULT -ne 0 ]; then
        arnakd_stop
        echo
        echo "Please generate it using qa/arnak/create_benchmark_archive.py"
        echo "and place it in the base directory of the repository."
        echo "Usage details are inside the Python script."
        exit 1
    fi
    xzcat block-107134.tar.xz | tar x -C "$DATADIR/regtest"
}


if [ $# -lt 2 ]
then
    echo "$0 : At least two arguments are required!"
    exit 1
fi

# Precomputation
case "$1" in
    *)
        case "$2" in
            verifyjoinsplit)
                arnakd_start "${@:2}"
                RAWJOINSPLIT=$(arnak_rpc zcsamplejoinsplit)
                arnakd_stop
        esac
esac

case "$1" in
    time)
        arnakd_start "${@:2}"
        case "$2" in
            sleep)
                arnak_rpc zcbenchmark sleep 10
                ;;
            parameterloading)
                arnak_rpc zcbenchmark parameterloading 10
                ;;
            createsaplingspend)
                arnak_rpc zcbenchmark createsaplingspend 10
                ;;
            verifysaplingspend)
                arnak_rpc zcbenchmark verifysaplingspend 1000
                ;;
            createsaplingoutput)
                arnak_rpc zcbenchmark createsaplingoutput 50
                ;;
            verifysaplingoutput)
                arnak_rpc zcbenchmark verifysaplingoutput 1000
                ;;
            createjoinsplit)
                arnak_rpc zcbenchmark createjoinsplit 10 "${@:3}"
                ;;
            verifyjoinsplit)
                arnak_rpc zcbenchmark verifyjoinsplit 1000 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                arnak_rpc_slow zcbenchmark solveequihash 50 "${@:3}"
                ;;
            verifyequihash)
                arnak_rpc zcbenchmark verifyequihash 1000
                ;;
            validatelargetx)
                arnak_rpc zcbenchmark validatelargetx 10 "${@:3}"
                ;;
            trydecryptnotes)
                arnak_rpc zcbenchmark trydecryptnotes 1000 "${@:3}"
                ;;
            incnotewitnesses)
                arnak_rpc zcbenchmark incnotewitnesses 100 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                arnak_rpc zcbenchmark connectblockslow 10
                ;;
            sendtoaddress)
                arnak_rpc zcbenchmark sendtoaddress 10 "${@:4}"
                ;;
            loadwallet)
                arnak_rpc zcbenchmark loadwallet 10 
                ;;
            listunspent)
                arnak_rpc zcbenchmark listunspent 10
                ;;
            *)
                arnakd_stop
                echo "Bad arguments to time."
                exit 1
        esac
        arnakd_stop
        ;;
    memory)
        arnakd_massif_start "${@:2}"
        case "$2" in
            sleep)
                arnak_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                arnak_rpc zcbenchmark parameterloading 1
                ;;
            createsaplingspend)
                arnak_rpc zcbenchmark createsaplingspend 1
                ;;
            verifysaplingspend)
                arnak_rpc zcbenchmark verifysaplingspend 1
                ;;
            createsaplingoutput)
                arnak_rpc zcbenchmark createsaplingoutput 1
                ;;
            verifysaplingoutput)
                arnak_rpc zcbenchmark verifysaplingoutput 1
                ;;
            createjoinsplit)
                arnak_rpc_slow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                arnak_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                arnak_rpc_slow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                arnak_rpc zcbenchmark verifyequihash 1
                ;;
            validatelargetx)
                arnak_rpc zcbenchmark validatelargetx 1
                ;;
            trydecryptnotes)
                arnak_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                arnak_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                arnak_rpc zcbenchmark connectblockslow 1
                ;;
            sendtoaddress)
                arnak_rpc zcbenchmark sendtoaddress 1 "${@:4}"
                ;;
            loadwallet)
                # The initial load is sufficient for measurement
                ;;
            listunspent)
                arnak_rpc zcbenchmark listunspent 1
                ;;
            *)
                arnakd_massif_stop
                echo "Bad arguments to memory."
                exit 1
        esac
        arnakd_massif_stop
        rm -f massif.out
        ;;
    valgrind)
        arnakd_valgrind_start
        case "$2" in
            sleep)
                arnak_rpc zcbenchmark sleep 1
                ;;
            parameterloading)
                arnak_rpc zcbenchmark parameterloading 1
                ;;
            createsaplingspend)
                arnak_rpc zcbenchmark createsaplingspend 1
                ;;
            verifysaplingspend)
                arnak_rpc zcbenchmark verifysaplingspend 1
                ;;
            createsaplingoutput)
                arnak_rpc zcbenchmark createsaplingoutput 1
                ;;
            verifysaplingoutput)
                arnak_rpc zcbenchmark verifysaplingoutput 1
                ;;
            createjoinsplit)
                arnak_rpc_veryslow zcbenchmark createjoinsplit 1 "${@:3}"
                ;;
            verifyjoinsplit)
                arnak_rpc zcbenchmark verifyjoinsplit 1 "\"$RAWJOINSPLIT\""
                ;;
            solveequihash)
                arnak_rpc_veryslow zcbenchmark solveequihash 1 "${@:3}"
                ;;
            verifyequihash)
                arnak_rpc zcbenchmark verifyequihash 1
                ;;
            trydecryptnotes)
                arnak_rpc zcbenchmark trydecryptnotes 1 "${@:3}"
                ;;
            incnotewitnesses)
                arnak_rpc zcbenchmark incnotewitnesses 1 "${@:3}"
                ;;
            connectblockslow)
                extract_benchmark_data
                arnak_rpc zcbenchmark connectblockslow 1
                ;;
            *)
                arnakd_valgrind_stop
                echo "Bad arguments to valgrind."
                exit 1
        esac
        arnakd_valgrind_stop
        rm -f valgrind.out
        ;;
    valgrind-tests)
        case "$2" in
            gtest)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/arnak-gtest
                cat valgrind.out
                rm -f valgrind.out
                ;;
            test_bitcoin)
                rm -f valgrind.out
                valgrind --leak-check=yes -v --error-limit=no --log-file="valgrind.out" ./src/test/test_bitcoin
                cat valgrind.out
                rm -f valgrind.out
                ;;
            *)
                echo "Bad arguments to valgrind-tests."
                exit 1
        esac
        ;;
    *)
        echo "Invalid benchmark type."
        exit 1
esac

# Cleanup
rm -rf "$DATADIR"
