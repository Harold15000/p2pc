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

# The converted audio is scratch: keep it out of the outputs and remove it on every exit.
work="$(mktemp -d "$models/.work.XXXXXX")"
trap 'rm -rf "$work"' EXIT

# Whisper reads 16 kHz mono PCM. `-nostdin` keeps ffmpeg from reading the job's stdin.
ffmpeg -nostdin -loglevel error -y -i "$audio" -ar 16000 -ac 1 -c:a pcm_s16le -f wav "$work/audio.wav"

model_file="$models/ggml-$model.bin"
if [ ! -s "$model_file" ]; then
  # Downloaded under a temporary name and renamed when complete, so an interrupted download is never mistaken for
  # the model. The shim's proxy settings carry the traffic through the egress allowlist.
  url="https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-$model.bin"
  curl --fail --location --silent --show-error --retry 3 --connect-timeout 20 --output "$model_file.part" "$url"
  mv "$model_file.part" "$model_file"
fi

"$whisper" -m "$model_file" -f "$work/audio.wav" -l "$language" -otxt -osrt -ovtt -of "$out/transcript"
