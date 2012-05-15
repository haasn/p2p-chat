#!/bin/bash
FILES="
src/Math.hs
src/Crypto.hs
src/Util.hs
src/Types.hs
src/P2P.hs
src/Sending.hs
src/Serializing.hs
"

MAINFILE="Test"

GHC_WARNS="
-Wall
-fno-warn-name-shadowing
-fno-warn-orphans
-fno-warn-missing-signatures
-fno-warn-type-defaults
-fno-warn-unused-do-bind
"

GHC_OPTS="${GHC_WARNS} -hidir bin/obj -odir bin/obj"

mkdir -p bin/obj
rm -f -- bin/obj/Main.*
hlint ${FILES} src/${MAINFILE}.hs
ghc ${GHC_OPTS} ${FILES} src/${MAINFILE}.hs -o bin/${MAINFILE} && bin/${MAINFILE} $@
