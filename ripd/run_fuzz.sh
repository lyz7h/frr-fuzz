rm -r profraw
rm -r crashes_and_corpus

mkdir profraw
mkdir crashes_and_corpus

export LLVM_PROFILE_FILE="$PWD/profraw/frr-%p.profraw"

./ripd crashes_and_corpus/ ../corpus/rip -max_total_time=86400 -fork=1 \
-ignore_crashes=1 -ignore_timeouts=1 -ignore_ooms=1 -timeout=10 2>&1 | tee ./fuzz.log