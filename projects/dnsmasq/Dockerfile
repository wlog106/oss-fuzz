# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && apt-get install -y make autoconf automake libtool
RUN git clone --depth 1 git://thekelleys.org.uk/dnsmasq.git dnsmasq
WORKDIR dnsmasq
COPY build.sh $SRC/
COPY fuzz*.c $SRC/
COPY fuzz*.cc $SRC/
COPY fuzz*.h $SRC/

COPY fuzz_patch.patch $SRC/

# flat zip of DHCPv6 seeds (files at root, no folder). OSS-Fuzz associates a
# <target>_seed_corpus.zip with the target; build.sh copies it to $OUT so every
# run_fuzzer auto-loads it AFTER the corpus wipe. Must exist in the build
# context (projects/dnsmasq/) or this COPY fails the build.
COPY fuzz_dhcp6_seed_corpus.zip $SRC/
