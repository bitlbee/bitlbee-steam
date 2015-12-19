#!/bin/bash
set -e

CFLAGS="-Werror" ./autogen.sh --disable-debug
make
make clean
scan-build -k --status-bugs make

git reset -q --hard
git clean -dfqx

CFLAGS="-Werror" ./autogen.sh --enable-debug
make
make clean
scan-build -k --status-bugs make

if [ "${TRAVIS_BRANCH}" != "master" ]; then
    exit
fi

FULLVERS="$(date +%Y%m%d)~$(git rev-parse --short=7 HEAD)~${TRAVIS_BUILD_NUMBER}"
FULLDATE=$(date -R)
REPONAME=$(basename "${TRAVIS_REPO_SLUG}")

git reset -q --hard
git clean -dfqx

sed -ri \
    -e "18 s/^(\s+).*(,)\$/\1\[${FULLVERS}\]\2/" \
    -e "s|^PKG_CHECK_MODULES\(\[BITLBEE\].*|plugindir=/usr/lib/bitlbee|" \
    configure.ac
sed -ri \
    -e "s/bitlbee-dev \([^\(\)]+\),?\s*//" \
    debian/control

cat <<EOF > debian/changelog
${REPONAME} (${FULLVERS}) UNRELEASED; urgency=medium

  * Updated to ${FULLVERS}.

 -- Travis CI <travis@travis-ci.org>  ${FULLDATE}
EOF

cat <<EOF > ~/.oscrc
[general]
apiurl = https://api.opensuse.org
[https://api.opensuse.org]
user = ${OBSUSER}
pass = ${OBSPASS}
EOF

mkdir -p m4
cp /usr/local/include/bitlbee/*.h steam
osc checkout "home:${OBSUSER}" "${REPONAME}" -o /tmp/obs

(
    cd /tmp/obs
    rm -f *.{dsc,tar.gz}
    dpkg-source -I -b "${TRAVIS_BUILD_DIR}"

    osc addremove -r
    osc commit -m "Updated to ${FULLVERS}"
)
