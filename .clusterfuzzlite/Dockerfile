FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:4d4bf15466807b053a811794c2ea980057e7b219010dcdcf7d6a1d4135a37d00

COPY . $SRC/cerberus
COPY ./.clusterfuzzlite/build.sh $SRC/build.sh
RUN chmod +x $SRC/build.sh
WORKDIR $SRC/cerberus
