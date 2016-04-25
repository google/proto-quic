#!/bin/bash

rm -rf third_party/llvm-build/
git add third_party/*
git add base/*
git add net/*
git add crypto/*
git add url/*
git add chrome/*
git add sdch/*
git add testing/*
git add ../proto_quic_tools/*
