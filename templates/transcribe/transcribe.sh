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

# A run killed by its timeout or by the loss of its node cannot run the `trap` below, and the volume outlives the job.
# So clear what an earlier run left behind: its scratch directories and its half-written downloads. A volume has one
# job at a time (spec §11.3), so nothing here belongs to a run that is still going. Finished models stay.
rm -rf "$models"/.work.*
rm -f "$models"/ggml-*.bin.part

# The converted audio is scratch: keep it out of the outputs and remove it on every exit.
work="$(mktemp -d "$models/.work.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Whisper reads 16 kHz mono PCM. `-nostdin` keeps ffmpeg from reading the job's stdin.
ffmpeg -nostdin -loglevel error -y -i "$audio" -ar 16000 -ac 1 -c:a pcm_s16le -f wav "$work/audio.wav"

model_file="$models/ggml-$model.bin"
if [ ! -s "$model_file" ]; then
  # Downloaded under a temporary name and renamed when complete, so an interrupted download is never mistaken for
  # the model. The shim's proxy settings carry the traffic through the egress allowlist.
  #
  # Bounded, so that a connection that goes quiet cannot hold the job until its whole timeout_s (one hour):
  #  - --speed-limit/--speed-time: below 1 KiB/s for 60 s is a stall, and curl gives up on that try;
  #  - --max-time: no try lasts over 25 minutes, even a slow one that keeps moving;
  #  - --retry 2 with --retry-max-time: at most two more tries, none started after 25 minutes since the first. The
  #    worst case is therefore about 50 minutes of download, which can still use up the job's hour; the job then ends at
  #    its timeout, never hangs, and the next run starts clean (stale .part files are removed above).
  url="https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-$model.bin"
  curl --fail --location --silent --show-error \
    --connect-timeout 20 --speed-limit 1024 --speed-time 60 --max-time 1500 \
    --retry 2 --retry-max-time 1500 \
    --output "$model_file.part" "$url"
  mv "$model_file.part" "$model_file"
fi

"$whisper" -m "$model_file" -f "$work/audio.wav" -l "$language" -otxt -osrt -ovtt -of "$out/transcript"
