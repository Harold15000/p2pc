#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# The fixed script of the `transcribe` template (H2 spec §7.6). The bundle ships it as an inline file, so it is
# read-only in the container. It converts /inputs/audio, runs the model and writes transcript.txt, transcript.srt and
# transcript.vtt to /outputs.
#
# LANGUAGE and MODEL are whole env values chosen from the template's enums. They are checked again here, and each is
# passed to a program as one quoted argument: nothing is evaluated.
#
# TRANSCRIBE_ROOT is a test hook: the tests point it at a fake root. The template never sets it and no parameter
# targets it, so in a job it is empty and every path below is absolute.
set -eu

root="${TRANSCRIBE_ROOT:-}"
audio="$root/inputs/audio"
out="$root/outputs"
models="$root/volumes/models"

# `-` without a default: an empty value is wrong, not "auto".
language="${LANGUAGE-auto}"
model="${MODEL-small}"

# "auto", or a code of two or three lowercase ASCII letters. The letters are spelled out because a range such as
# [a-z] can match other characters in some locales.
case "$language" in
  auto) ;;
  ?? | ???)
    case "$language" in
      *[!abcdefghijklmnopqrstuvwxyz]*)
        echo "transcribe: LANGUAGE is not a language code" >&2
        exit 64
        ;;
    esac
    ;;
  *)
    echo "transcribe: LANGUAGE is not a language code" >&2
    exit 64
    ;;
esac
case "$model" in
  base | small | medium) ;;
  *)
    echo "transcribe: MODEL must be base, small or medium" >&2
    exit 64
    ;;
esac

if [ ! -f "$audio" ]; then
  echo "transcribe: there is no input audio" >&2
  exit 66
fi

whisper="$(command -v whisper-cli || true)"
if [ -z "$whisper" ]; then
  whisper=/app/build/bin/whisper-cli
fi

mkdir -p "$out" "$models"

# What an earlier run may have left in the volume, which outlives the job: half-written downloads (a run killed by its
# timeout or by the loss of its node cannot clean up), and `.work.*` directories, which older versions of this script
# used for the converted audio (it now goes in /tmp, below). A volume has one job at a time (spec §11.3), so nothing
# here belongs to a run that is still going. Finished models stay.
rm -rf "$models"/.work.*
rm -f "$models"/ggml-*.bin.part

# The model first, so a bad or missing model stops the run before the user's audio is copied anywhere.
#
# The files come from one pinned commit of the Hugging Face repository, never from a moving branch, and each is
# checked against its SHA-256 (the LFS object id at that commit) on EVERY run, before it is used: the egress allowlist
# decides where the job may connect, not what it receives, and the model is parsed by native code. A file that fails
# the check is deleted and the run stops with an error; the next run downloads it again.
revision=5359861c739e955e79d9a303bcbc70fb988958b1
case "$model" in
  base) expected=60ed5bc3dd14eea856493d334349b405782ddcaf0028d4b5df4088345fba2efe ;;
  small) expected=1be3a9b2063867b937e64e2ec7483364a79917e157fa98c5d94b5c1fffea987b ;;
  medium) expected=6c14d5adee5f86394037b4e4e8b59f1673b6cee10e3cf0b11bbdbee79c156208 ;;
esac

if ! command -v sha256sum >/dev/null 2>&1; then
  echo "transcribe: sha256sum is missing, so no model can be checked" >&2
  exit 69
fi

# `check_model <file>`: whether the file has the pinned hash. `cut` takes the hash out of `sha256sum`'s
# "<hash>  <file>"; an empty answer matches nothing, so a failing sha256sum fails closed.
check_model() {
  actual="$(sha256sum "$1" | cut -d ' ' -f 1)"
  [ "$actual" = "$expected" ]
}

model_file="$models/ggml-$model.bin"
if [ ! -s "$model_file" ]; then
  # Downloaded under a temporary name, checked, and renamed to the final name only when the hash matches: a file under
  # the final name is always one that has passed the check, even if the job is killed in between. The shim's proxy
  # settings carry the traffic through the egress allowlist.
  #
  # Bounded, so that a connection that goes quiet cannot hold the job until its whole timeout_s (one hour):
  #  - --speed-limit/--speed-time: under 10 KiB/s for 60 s is a stall, and curl gives up on that try;
  #  - --max-time: no try lasts over 30 minutes, even a slow one that keeps moving;
  #  - --retry 2 with --retry-max-time: a try that fails early may be repeated, none started after 30 minutes since the
  #    first. The worst case can still use up the job's hour; the job then ends at its timeout and never hangs, and the
  #    next run starts clean (stale .part files are removed above).
  url="https://huggingface.co/ggerganov/whisper.cpp/resolve/$revision/ggml-$model.bin"
  curl --fail --location --silent --show-error \
    --connect-timeout 20 --speed-limit 10240 --speed-time 60 --max-time 1800 \
    --retry 2 --retry-max-time 1800 \
    --output "$model_file.part" "$url"
  if ! check_model "$model_file.part"; then
    rm -f "$model_file.part"
    echo "transcribe: the downloaded $model model failed its checksum and was deleted; run again to download it" >&2
    exit 65
  fi
  mv "$model_file.part" "$model_file"
elif ! check_model "$model_file"; then
  # A model that was already in the volume is checked too, on every run, before it is used.
  rm -f "$model_file"
  echo "transcribe: the $model model in the volume failed its checksum and was deleted; run again to download it" >&2
  exit 65
fi

# The converted audio is scratch: a full copy of the user's recording. It goes in the job's /tmp, a tmpfs that belongs
# to the container and disappears with it whatever ends the job (a SIGKILL included), never in the persistent models
# volume. The shim signals only this shell, and `sh` runs a trap only when its foreground command has returned, so the
# traps below cover a signal that arrives between commands and the normal exit; for a SIGKILL during ffmpeg or whisper,
# the tmpfs is what removes the copy. TERM, INT and HUP become an exit (143) so that the EXIT trap runs.
work="$(mktemp -d "$root${TMPDIR:-/tmp}/transcribe.XXXXXX")"
trap 'rm -rf "$work"' EXIT
trap 'exit 143' TERM INT HUP

# Whisper reads 16 kHz mono PCM. `-nostdin` keeps ffmpeg from reading the job's stdin.
ffmpeg -nostdin -loglevel error -y -i "$audio" -ar 16000 -ac 1 -c:a pcm_s16le -f wav "$work/audio.wav"

"$whisper" -m "$model_file" -f "$work/audio.wav" -l "$language" -otxt -osrt -ovtt -of "$out/transcript"
