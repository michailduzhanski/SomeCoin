#!/bin/sh

TOPDIR=${TOPDIR:-$(git rev-parse --show-toplevel)}
SRCDIR=${SRCDIR:-$TOPDIR/src}
MANDIR=${MANDIR:-$TOPDIR/doc/man}

ARNAKD=${ARNAKD:-$SRCDIR/arnakd}
ARNAKCLI=${ARNAKCLI:-$SRCDIR/arnak-cli}
ARNAKTX=${ARNAKTX:-$SRCDIR/arnak-tx}

[ ! -x $ARNAKD ] && echo "$ARNAKD not found or not executable." && exit 1

# The autodetected version git tag can screw up manpage output a little bit
ZECVERSTR=$($ARNAKCLI --version | head -n1 | awk '{ print $NF }')
ZECVER=$(echo $ZECVERSTR | awk -F- '{ OFS="-"; NF--; print $0; }')
ZECCOMMIT=$(echo $ZECVERSTR | awk -F- '{ print $NF }')

# Create a footer file with copyright content.
# This gets autodetected fine for arnakd if --version-string is not set,
# but has different outcomes for arnak-cli.
echo "[COPYRIGHT]" > footer.h2m
$ARNAKD --version | sed -n '1!p' >> footer.h2m

for cmd in $ARNAKD $ARNAKCLI $ARNAKTX; do
  cmdname="${cmd##*/}"
  help2man -N --version-string=$ZECVER --include=footer.h2m -o ${MANDIR}/${cmdname}.1 ${cmd}
  sed -i "s/\\\-$ZECCOMMIT//g" ${MANDIR}/${cmdname}.1
done

rm -f footer.h2m
