#!/bin/sh
#
# Run external tests, requires a common lisp interpreter (sbcl by
# default) to be available.

SUDO=${SUDO:-doas}
USER=${USER?:user not set}
SBCL=${SBCL:-sbcl}

set -e

if ! which kamid 2>/dev/null >/dev/null; then
	echo "can't find kamid in PATH" >&2
	exit 1
fi

# gencerts name
gencerts() {
	echo "generating keypairs for $1..."
	openssl req -x509		\
		-newkey rsa:4096	\
		-out "$1.pem"		\
		-keyout "$1.key"	\
		-days 365		\
		-nodes			\
		-subj "/CN=$1"
}

# h cert
h() {
	printf "SHA256:"
	openssl x509 -in "$1" -noout -fingerprint -sha256 | \
		sed -e 's/^.*=//' -e 's/://g' | \
		tr A-Z a-z
}

if [ ! -f client.pem -o ! -f client.key ]; then
	gencerts client
fi

if [ ! -f kamid.pem -o ! -f kamid.key ]; then
	gencerts kamid
fi

kamid_hash="$(h client.pem)"
tmpdir="$(mktemp -d -t kamid-regress.XXXXXXXXXX)"
testroot="$tmpdir/root"

cp -R ../root/ "$tmpdir"

cat > regress.conf <<EOF
pki localhost cert "$PWD/kamid.pem"
pki localhost key  "$PWD/kamid.key"

table users { "$kamid_hash" => "flan" }
table virt  { "flan" => "$USER" }
table data  { "flan" => "$testroot" }

listen on localhost port 1337 tls pki localhost \
	auth <users> \
	virtual <virt> \
	userdata <data>
EOF

logfile="$tmpdir/$(date +%Y-%m-%d-%H-%M).log"

export REGRESS_CERT="$PWD/client.pem"
export REGRESS_KEY="$PWD/client.key"
export REGRESS_HOSTNAME=localhost
export REGRESS_PORT=1337
export REGRESS_ROOT="$testroot"

echo "REGRESS_CERT: $REGRESS_CERT"
echo "REGRESS_KEY: $REGRESS_KEY"
echo "REGRESS_HOSTNAME: $REGRESS_HOSTNAME"
echo "REGRESS_PORT: $REGRESS_PORT"
echo "REGRESS_ROOT: $REGRESS_ROOT"
echo

echo "logging on $logfile"
${SUDO} "$(which kamid)" -d -vvv -f regress.conf > "$logfile" 2>&1 &

ret=0

set +e
cd 9p-test/ && \
	${SBCL} --noinform \
		--disable-debugger \
		--eval "(require 'asdf)" \
		--eval "(push \"$(pwd)/\" asdf:*central-registry*)" \
		--eval "(asdf:make \"9p-test\")" \
		--eval "(all-tests:run-all-tests)"

ret=$?
if [ $ret -ne 0 ]; then
	echo
	echo "Test failed, leaving root at $testroot"
	sleep 1
else
	rm -rf "$testroot"
fi

${SUDO} pkill kamid

exit $ret
