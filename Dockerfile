# syntax=docker/dockerfile:1
#
# LombokFuzzer — container image for GitHub Packages (ghcr.io).
#
# Two stages: `builder` compiles the dual CJS/ESM/types output, `runtime` ships
# only the built dist. The core is zero-dependency, so the runtime stage needs
# no `node_modules` at all — it just carries the compiled library plus docs.
#
# This image is primarily an ecosystem artifact: mount your own harness and
# import the library, or use it as a base image. (A first-class CLI lands in a
# later release.)

# ── Builder: install dev deps and build the library ──
FROM node:22-alpine AS builder
WORKDIR /build

COPY package.json package-lock.json ./
RUN npm ci

COPY tsconfig.json tsconfig.esm.json tsconfig.cjs.json tsconfig.types.json ./
COPY scripts ./scripts
COPY src ./src
RUN npm run build

# ── Runtime: ship the compiled dist only ──
FROM node:22-alpine AS runtime
WORKDIR /app

LABEL org.opencontainers.image.title="LombokFuzzer" \
      org.opencontainers.image.description="Universal fuzzing framework — coverage-guided, grammar-aware, protocol/API/web/SQL/crypto/hardware fuzzing. Part of the Lombok Ecosystem." \
      org.opencontainers.image.source="https://github.com/codinglombok/LombokFuzzer" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.vendor="codinglombok"

# README + LICENSE first so a failed layer here surfaces immediately
# (learned the hard way: a missing COPY README.md breaks the build stage).
COPY README.md LICENSE package.json ./
COPY --from=builder /build/dist ./dist

# No CLI yet — print version + pointer so `docker run` does something useful.
CMD ["node", "-e", "console.log('LombokFuzzer ' + require('./dist/cjs/index.js').VERSION + ' — import it in your harness. Docs: https://github.com/codinglombok/LombokFuzzer')"]
